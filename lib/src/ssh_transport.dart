import 'dart:async';
import 'dart:convert';
import 'dart:math' show max;
import 'dart:typed_data';

import 'package:dartssh2/src/hostkey/hostkey_ecdsa.dart';
import 'package:dartssh2/src/hostkey/hostkey_rsa.dart';
import 'package:dartssh2/src/kex/kex_dh.dart';
import 'package:dartssh2/src/kex/kex_nist.dart';
import 'package:dartssh2/src/kex/kex_x25519.dart';
import 'package:dartssh2/src/message/msg_debug.dart';
import 'package:dartssh2/src/message/msg_disconnect.dart';
import 'package:dartssh2/src/message/msg_userauth.dart';
import 'package:dartssh2/src/message/msg_ignore.dart';
import 'package:dartssh2/src/message/msg_unimplemented.dart';
import 'package:dartssh2/src/ssh_algorithm.dart';
import 'package:dartssh2/src/ssh_kex.dart';
import 'package:dartssh2/src/utils/bigint.dart';
import 'package:dartssh2/src/utils/cipher_ext.dart';
import 'package:dartssh2/src/utils/chunk_buffer.dart';
import 'package:dartssh2/src/utils/hostkey_fingerprint.dart';
import 'package:dartssh2/src/ssh_kex_utils.dart';
import 'package:dartssh2/src/ssh_packet.dart';
import 'package:dartssh2/src/utils/int.dart';
import 'package:dartssh2/src/hostkey/hostkey_ed25519.dart';
import 'package:dartssh2/src/utils/list.dart';
import 'package:dartssh2/src/utils/openssh_chacha20_poly1305.dart';
import 'package:dartssh2/src/message/msg_ext_info.dart';
import 'package:dartssh2/src/message/msg_kex.dart';
import 'package:dartssh2/src/message/msg_kex_dh.dart';
import 'package:dartssh2/src/message/msg_kex_ecdh.dart';
import 'package:dartssh2/src/ssh_message.dart';
import 'package:meta/meta.dart';
import 'package:pointycastle/export.dart';

import '../dartssh2.dart';

typedef SSHPrintHandler = void Function(String?);

/// Function called when host key is received.
/// [type] is the type of the host key, For example 'ssh-rsa',
/// [fingerprint] OpenSSH-style SHA256 fingerprint of the host key,
/// UTF-8 encoded as `SHA256:<base64>`.
typedef SSHHostkeyVerifyHandler = FutureOr<bool> Function(
  String type,
  Uint8List fingerprint,
);

typedef SSHTransportReadyHandler = void Function();

typedef SSHPacketHandler = void Function(Uint8List payload);

/// Handles a packet and returns whether its message type is recognized.
typedef SSHMessageHandler = bool Function(Uint8List payload);

/// Pseudo algorithm names that are advertised inside the key exchange
/// name-list without being key exchange algorithms themselves.
abstract class SSHKexPseudoAlgorithm {
  /// Sent by a client to signal support for strict key exchange.
  static const strictKexClient = 'kex-strict-c-v00@openssh.com';

  /// Sent by a server to signal support for strict key exchange.
  static const strictKexServer = 'kex-strict-s-v00@openssh.com';

  /// Sent by a client to ask for SSH_MSG_EXT_INFO (RFC 8308 §2.2).
  static const extInfoClient = 'ext-info-c';

  /// Sent by a server to ask for SSH_MSG_EXT_INFO (RFC 8308 §2.2).
  static const extInfoServer = 'ext-info-s';
}

class SSHTransport {
  /// Version of the SSH software. By default "DartSSH_2.0"
  final String version;

  /// The socket to read and write data to.
  final SSHSocket socket;

  /// Whether the transport acts as a server.
  final bool isServer;

  /// Whether the transport acts as a client. This is equal to `!isServer`.
  bool get isClient => !isServer;

  /// Function invoked with debug logging.
  final SSHPrintHandler? printDebug;

  /// Function invoked with trace logging.
  final SSHPrintHandler? printTrace;

  /// The collection of cryptographic and transport algorithms to negotiate and use.
  final SSHAlgorithms algorithms;

  /// Function called when the hostkey has been received. Returns true if the
  /// hostkey is valid, false to reject key and disconnect.
  final SSHHostkeyVerifyHandler? onVerifyHostKey;

  /// Function called when the transport is ready to send data.
  final SSHTransportReadyHandler? onReady;

  /// Function called when a packet is received.
  ///
  /// Every packet handed to this callback is assumed to be handled, so the
  /// transport can never tell that a message was unrecognized and never
  /// replies with SSH_MSG_UNIMPLEMENTED on its behalf.
  @Deprecated(
    'Use onMessage instead, which reports whether the message was recognized '
    'so the transport can answer unknown ones as RFC 4253 requires. '
    'Will be removed in a future major release.',
  )
  final SSHPacketHandler? onPacket;

  /// Function called for messages not handled by the transport layer.
  ///
  /// Returning `false` causes the transport to reply with
  /// SSH_MSG_UNIMPLEMENTED for the current packet. [onPacket] is retained for
  /// backwards compatibility and assumes every packet it receives is handled.
  final SSHMessageHandler? onMessage;

  /// Whether to bypass server host key verification.
  ///
  /// If set to `true`, the connection will proceed without checking the server's
  /// host key signature or identity, which is useful for testing but insecure.
  final bool disableHostkeyVerification;

  /// A [Future] that completes when the transport is closed, or when an error
  /// occurs. After this [Future] completes, [isClosed] will be true and no
  /// more data can be sent or received.
  Future<void> get done => _doneCompleter.future;

  /// `true` if the connection is closed normally or due to an error.
  bool get isClosed => _doneCompleter.isCompleted;

  /// Identification string sent by the other side. For example, "SSH-2.0-OpenSSH_7.4p1".
  /// May be `null` if the handshake has not yet completed.
  String? get remoteVersion => _remoteVersion;

  SSHTransport(
    this.socket, {
    this.isServer = false,
    this.version = 'DartSSH_2.0',
    this.printDebug,
    this.printTrace,
    this.algorithms = const SSHAlgorithms(),
    this.onVerifyHostKey,
    this.onReady,
    this.onPacket,
    this.onMessage,
    this.disableHostkeyVerification = false,
  }) : assert(onPacket == null || onMessage == null) {
    _initSocket();
    _startHandshake();
  }

  /// A completer that completes when the transport is closed or terminated,
  /// either normally or due to an error.
  final _doneCompleter = Completer<void>();

  /// Contains unprocessed data from the socket.
  final _buffer = ChunkBuffer();

  /// Contains decrypted packet data. May be partial.
  final _decryptBuffer = ChunkBuffer();

  /// Subscription to the socket's [Stream]. It should be closed when the
  /// transport is closed.
  StreamSubscription? _socketSubscription;

  /// Guards asynchronous packet processing to preserve message order.
  var _isProcessingData = false;

  /// Tracks whether new socket data was received since packet processing started.
  var _hasNewData = false;

  /// Identification string sent by us without trailing \r\n. For example,
  /// "SSH-2.0-DartSSH_2.0".
  String get _localVersion => 'SSH-2.0-$version';

  /// Identification string sent by the other side. For example, "SSH-2.0-OpenSSH_7.4p1".
  /// May be `null` if the handshake has not yet completed.
  /// This is kept to compute [_exchangeHash]
  String? _remoteVersion;

  /// Payload of the [SSH_Message_KexInit] sent by us. Kept to compute the
  /// exchange hash.
  late Uint8List _localKexInit;

  /// Payload of the [SSH_Message_KexInit] sent by the other side. Kept to
  /// compute the exchange hash.
  late Uint8List _remoteKexInit;

  /// The selected key exchange algorithm type negotiated between the parties.
  SSHKexType? _kexType;

  /// The selected server host key algorithm type negotiated between the parties.
  SSHHostkeyType? _hostkeyType;

  /// The encryption cipher algorithm type selected for client-to-server communication.
  SSHCipherType? _clientCipherType;

  /// The decryption cipher algorithm type selected for server-to-client communication.
  SSHCipherType? _serverCipherType;

  /// Cipher currently active for packets sent to the other side.
  SSHCipherType? _localCipherType;

  /// Cipher currently active for packets received from the other side.
  SSHCipherType? _remoteCipherType;

  /// The MAC algorithm type selected for client-to-server integrity verification.
  SSHMacType? _clientMacType;

  /// The MAC algorithm type selected for server-to-client integrity verification.
  SSHMacType? _serverMacType;

  /// MAC currently active for packets sent to the other side.
  SSHMacType? _localMacType;

  /// MAC currently active for packets received from the other side.
  SSHMacType? _remoteMacType;

  /// The active key exchange algorithm implementation instance.
  SSHKex? _kex;

  /// [_exchangeHash] of the first key exchange is used as session identifier.
  /// Used to derive the cipher IV, cipher key and MAC key.
  Uint8List? _sessionId;

  // ignore: unnecessary_getters_setters
  Uint8List? get sessionId => _sessionId;
  set sessionId(Uint8List? value) => _sessionId = value;

  /// A hash value of various parameters (defined in rfc4253). Kept to derive the
  /// cipher IV, cipher key and MAC key.
  Uint8List? _exchangeHash;

  /// Whether the hostkey of the server has been verified. This is always false
  /// when the transport is acting as a server.
  var _hostkeyVerified = false;

  /// Fingerprint of the host key verified during the first key exchange.
  ///
  /// Kept so that a later rekey can detect the host key silently changing to
  /// a different one, which OpenSSH treats as an error: [_hostkeyVerified]
  /// only latches whether verification ever succeeded, not which key it
  /// succeeded for.
  Uint8List? _verifiedHostkeyFingerprint;

  /// Host key type verified during the first key exchange, checked alongside
  /// [_verifiedHostkeyFingerprint] on rekey.
  SSHHostkeyType? _verifiedHostkeyType;

  /// Shared secret derived from the key exchange process. Kept to derive the
  /// cipher IV, cipher key and MAC key.
  BigInt? _sharedSecret;

  /// A [BlockCipher] to encrypt data sent to the other side.
  BlockCipher? _encryptCipher;

  /// A [BlockCipher] to decrypt data sent from the other side.
  BlockCipher? _decryptCipher;

  /// OpenSSH ChaCha20-Poly1305 context for packets sent to the other side.
  OpenSSHChaCha20Poly1305? _localChaChaCipher;

  /// OpenSSH ChaCha20-Poly1305 context for packets received from the other side.
  OpenSSHChaCha20Poly1305? _remoteChaChaCipher;

  /// The cipher key derived for encrypting outgoing data.
  Uint8List? _localCipherKey;

  /// The cipher key derived for decrypting incoming data.
  Uint8List? _remoteCipherKey;

  /// The initialization vector (IV) or nonce prefix derived for encrypting outgoing data.
  Uint8List? _localIV;

  /// The initialization vector (IV) or nonce prefix derived for decrypting incoming data.
  Uint8List? _remoteIV;

  /// A [Mac] used to authenticate data sent to the other side.
  Mac? _localMac;

  /// A [Mac] used to authenticate data sent from the other side.
  Mac? _remoteMac;

  /// The monotonic sequence number of local packets sent over this transport.
  /// Used for MAC computation and standard packet flow tracing.
  final _localPacketSN = SSHPacketSN.fromZero();

  /// The monotonic sequence number of remote packets received over this transport.
  /// Used for MAC verification and standard packet flow tracing.
  final _remotePacketSN = SSHPacketSN.fromZero();

  /// The invocation counter for local AEAD (e.g. AES-GCM) packets.
  ///
  /// According to RFC 5647 Section 7.1, the invocation counter (used to derive
  /// the AEAD nonce) must reset to zero when new keys are established (NEWKEYS).
  /// This counter is used instead of [_localPacketSN], which is monotonic
  /// across the entire SSH session and does not reset on rekey.
  int _localAeadPacketCount = 0;

  /// The invocation counter for remote AEAD (e.g. AES-GCM) packets.
  ///
  /// According to RFC 5647 Section 7.1, the invocation counter (used to derive
  /// the AEAD nonce) must reset to zero when new keys are established (NEWKEYS).
  /// This counter is used instead of [_remotePacketSN], which is monotonic
  /// across the entire SSH session and does not reset on rekey.
  int _remoteAeadPacketCount = 0;

  /// Whether a key exchange is currently in progress (initial or re-key).
  bool _kexInProgress = false;

  /// Whether we have already sent our SSH_MSG_KEXINIT for the ongoing key
  /// exchange round. This is reset when the exchange finishes.
  bool _sentKexInit = false;

  /// Whether the initial key exchange is still running. The strict key exchange
  /// and EXT_INFO indicators are only valid in the first SSH_MSG_KEXINIT, so
  /// they are advertised and read while this is `true`.
  bool _isFirstKex = true;

  /// Whether both peers advertised strict key exchange and it is therefore in
  /// effect for this connection.
  ///
  /// Strict key exchange is the countermeasure against the Terrapin attack
  /// (CVE-2023-48795). It removes the attacker's ability to delete packets
  /// from the start of the connection undetected, by resetting the packet
  /// sequence numbers after every SSH_MSG_NEWKEYS and by forbidding the
  /// optional messages that made the injection possible.
  bool get strictKex => _strictKex;
  var _strictKex = false;

  /// Set when a received SSH_MSG_NEWKEYS asks for a sequence number reset, so
  /// that the reset happens after [_processPackets] is done with the packet
  /// rather than being undone by the trailing increment.
  var _resetRemotePacketSN = false;

  /// Extensions sent by the server in SSH_MSG_EXT_INFO (RFC 8308), or `null`
  /// if the server sent none.
  Map<String, Uint8List>? get extInfo => _extInfo;
  Map<String, Uint8List>? _extInfo;

  /// The signature algorithms the server accepts for `publickey`
  /// authentication, as advertised through the `server-sig-algs` extension.
  /// `null` when the server did not send it.
  List<String>? get serverSigAlgs => _serverSigAlgs;
  List<String>? _serverSigAlgs;

  /// Packets queued during key exchange that will be sent after NEW_KEYS
  final List<Uint8List> _rekeyPendingPackets = [];

  /// Completes when the key exchange a [rekey] call is waiting on reaches
  /// SSH_MSG_NEWKEYS, or with an error if the connection ends first.
  ///
  /// `null` when no caller is waiting: the initial handshake and exchanges
  /// nobody asked about do not allocate one.
  Completer<void>? _rekeyCompleter;

  /// Sends an SSH packet payload over the transport.
  ///
  /// This method packs the [data], calculates padding and MAC, encrypts the payload
  /// (if encryption has been negotiated), and writes the bytes to the underlying socket.
  /// If a key exchange is currently in progress, packets are queued and sent after
  /// the key exchange completes (except for key exchange control messages which bypass the queue).
  void sendPacket(Uint8List data) {
    if (isClosed) {
      throw SSHStateError('Transport is closed');
    }

    if (_kexInProgress && !_shouldBypassRekeyBuffer(data)) {
      _rekeyPendingPackets.add(Uint8List.fromList(data));
      return;
    }

    // Check if encryption is enabled and if we have MAC types initialized
    final macType = _localMacType;
    final localCipherType = _localCipherType;

    final localChaChaCipher = _localChaChaCipher;
    if (localCipherType == SSHCipherType.chacha20poly1305 &&
        localChaChaCipher != null) {
      _sendChaChaPacket(data, localChaChaCipher);
      _localPacketSN.increase();
      return;
    }

    if (localCipherType != null &&
        localCipherType.isAead &&
        _localCipherKey != null &&
        _localIV != null) {
      _sendAeadPacket(data, localCipherType);
      _localPacketSN.increase();
      return;
    }

    final isEtm = _encryptCipher != null && macType != null && macType.isEtm;

    // For ETM, we need to handle the packet differently
    if (isEtm) {
      // For ETM (Encrypt-Then-MAC):
      // 1. Keep the packet length in plaintext
      // 2. Encrypt only the payload (padding length, payload, padding)

      // Calculate the block size for alignment
      final blockSize = _encryptCipher!.blockSize;

      // Create a custom packet structure for ETM mode
      // We need to ensure that the payload we're encrypting is a multiple of the block size

      // Calculate the padding length to ensure the total length is a
      // multiple of the block size (accounting for the 1 byte padding
      // length field), enforcing the SSH-mandated 4 byte minimum.
      final adjustedPaddingLength = _alignedPaddingLength(
        data.length,
        blockSize,
      );

      // Calculate the total packet length (excluding the length field itself)
      final packetLength = 1 + data.length + adjustedPaddingLength;

      // Create the packet length field (4 bytes)
      final packetLengthBytes = Uint8List(4);
      packetLengthBytes.buffer.asByteData().setUint32(0, packetLength);

      // Create the payload to be encrypted (padding length + payload + padding)
      final payloadToEncrypt = Uint8List(packetLength);
      payloadToEncrypt[0] = adjustedPaddingLength; // Set padding length
      payloadToEncrypt.setRange(1, 1 + data.length, data); // Copy data

      // Add random padding (RFC 4253 §6 requires it).
      payloadToEncrypt.setRange(
        1 + data.length,
        packetLength,
        randomBytes(adjustedPaddingLength),
      );

      // Verify that the payload length is a multiple of the block size
      if (payloadToEncrypt.length % blockSize != 0) {
        throw StateError(
            'Payload length ${payloadToEncrypt.length} is not a multiple of block size $blockSize');
      }

      // Encrypt the payload
      final encryptedPayload = _encryptCipher!.processAll(payloadToEncrypt);

      // Calculate MAC on the packet length and encrypted payload
      final mac = _localMac!;
      mac.updateAll(_localPacketSN.value.toUint32());
      mac.updateAll(packetLengthBytes);
      mac.updateAll(encryptedPayload);
      final macBytes = mac.finish();

      // Build the final packet: length + encrypted payload + MAC
      final buffer = BytesBuilder(copy: false);
      buffer.add(packetLengthBytes);
      buffer.add(encryptedPayload);
      buffer.add(macBytes);

      socket.sink.add(buffer.takeBytes());
    } else {
      // For standard encryption or no encryption:
      // Use the original packet packing logic
      final packetAlign = _encryptCipher == null
          ? SSHPacket.minAlign
          : max(SSHPacket.minAlign, _encryptCipher!.blockSize);

      final packet = SSHPacket.pack(data, align: packetAlign);

      if (_encryptCipher == null) {
        socket.sink.add(packet);
      } else {
        final mac = _localMac!;
        final encryptedPacket = _encryptCipher!.processAll(packet);

        final buffer = BytesBuilder(copy: false);
        buffer.add(encryptedPacket);

        // Calculate MAC on the unencrypted packet
        mac.updateAll(_localPacketSN.value.toUint32());
        mac.updateAll(packet);
        buffer.add(mac.finish());

        socket.sink.add(buffer.takeBytes());
      }
    }

    _localPacketSN.increase();
  }

  /// Sends a packet using the OpenSSH ChaCha20-Poly1305 construction.
  void _sendChaChaPacket(
    Uint8List data,
    OpenSSHChaCha20Poly1305 cipher,
  ) {
    final paddingLength = _alignedPaddingLength(
      data.length,
      OpenSSHChaCha20Poly1305.blockSize,
    );
    final packetLength = 1 + data.length + paddingLength;
    final packet = Uint8List(4 + packetLength);
    ByteData.sublistView(packet, 0, 4).setUint32(0, packetLength);
    packet[4] = paddingLength;
    packet.setRange(5, 5 + data.length, data);
    packet.setRange(
      5 + data.length,
      packet.length,
      randomBytes(paddingLength),
    );

    socket.sink.add(cipher.encryptPacket(packet, _localPacketSN.value));
  }

  /// Sends a packet encrypted using AEAD (e.g. AES-GCM).
  ///
  /// Constructs the packet length and padding, generates random padding bytes,
  /// encrypts the payload with GCM, and writes the packet to the socket.
  void _sendAeadPacket(Uint8List data, SSHCipherType cipherType) {
    final paddingLength =
        _alignedPaddingLength(data.length, cipherType.blockSize);
    final packetLength = 1 + data.length + paddingLength;

    final aad = Uint8List(4)..buffer.asByteData().setUint32(0, packetLength);

    final plaintext = Uint8List(packetLength)
      ..[0] = paddingLength
      ..setRange(1, 1 + data.length, data)
      // RFC 4253 §6 requires the padding to consist of random bytes.
      ..setRange(1 + data.length, packetLength, randomBytes(paddingLength));

    final encrypted = _processAead(
      key: _localCipherKey!,
      iv: _localIV!,
      sequence: _localAeadPacketCount++,
      aad: aad,
      input: plaintext,
      forEncryption: true,
    );

    final buffer = BytesBuilder(copy: false)
      ..add(aad)
      ..add(encrypted);

    socket.sink.add(buffer.takeBytes());
  }

  /// Computes the correct padding length required to align the total packet size to [align] blocks.
  int _alignedPaddingLength(int payloadLength, int align) {
    final paddingLength = align - ((payloadLength + 1) % align);
    return paddingLength < 4 ? paddingLength + align : paddingLength;
  }

  /// Encrypts or decrypts [input] using the AES-GCM AEAD block cipher.
  Uint8List _processAead({
    required Uint8List key,
    required Uint8List iv,
    required int sequence,
    required Uint8List aad,
    required Uint8List input,
    required bool forEncryption,
  }) {
    final cipher = GCMBlockCipher(AESEngine());
    final nonce = _nonceForSequence(iv, sequence);
    cipher.init(
      forEncryption,
      AEADParameters(KeyParameter(key), 128, nonce, aad),
    );
    return cipher.process(input);
  }

  /// Generates the AEAD nonce for a given [iv] and packet [sequence] number.
  ///
  /// XORs or appends the sequence number to the IV as specified by the cipher.
  Uint8List _nonceForSequence(Uint8List iv, int sequence) {
    if (iv.length != 12) {
      throw ArgumentError.value(iv, 'iv', 'AEAD IV must be 12 bytes long');
    }

    final nonce = Uint8List.fromList(iv);
    final view = ByteData.sublistView(nonce);
    // Two 32-bit words with carry rather than getUint64/setUint64 (which
    // throw when compiled to JavaScript): see utils/int.dart. This also
    // sidesteps combining the counter into a single int, which matters
    // here because the counter is derived from key material and routinely
    // has its top bit set.
    view.addToUint64Split(4, sequence);
    return nonce;
  }

  /// Closes the SSH transport, cancels the socket subscription, and terminates the connection.
  Future<void> close() async {
    printDebug?.call('SSHTransport.close');
    if (isClosed) return;
    _socketSubscription?.cancel();
    _socketSubscription = null;
    _doneCompleter.complete();
    _failPendingRekey(
      SSHStateError('Transport closed before the key exchange completed'),
      StackTrace.current,
    );
    await socket.close();
  }

  /// Closes the SSH transport and completes the [done] future with an [error].
  void closeWithError(SSHError error, [StackTrace? stackTrace]) {
    printDebug?.call('SSHTransport.closeWithError $error');
    if (isClosed) return;
    _socketSubscription?.cancel();
    _socketSubscription = null;
    _doneCompleter.completeError(error, stackTrace ?? StackTrace.current);
    _failPendingRekey(error, stackTrace ?? StackTrace.current);
    socket.destroy();
  }

  /// Force flush any buffered outgoing data to the socket.
  Future<void> flush() async {
    await socket.flush();
  }

  /// Subscribes to the underlying socket stream to handle incoming data and status events.
  void _initSocket() {
    _socketSubscription = socket.stream.listen(
      _onSocketData,
      onError: _onSocketError,
      onDone: _onSocketDone,
    );

    socket.done.catchError(_onSocketError);
  }

  /// Callback triggered when new raw bytes are received from the socket.
  void _onSocketData(Uint8List data) {
    _buffer.add(data);
    _hasNewData = true;
    _scheduleProcessData();
  }

  /// Callback triggered when an error occurs on the socket stream.
  void _onSocketError(Object error, StackTrace stackTrace) {
    printDebug?.call('SSHTransport._onSocketError($error)');
    closeWithError(SSHSocketError(error), stackTrace);
  }

  /// Callback triggered when the socket stream is closed by the remote peer.
  void _onSocketDone() {
    printDebug?.call('SSHTransport._onSocketDone');
    close();
  }

  void _scheduleProcessData() {
    if (_isProcessingData || isClosed) {
      return;
    }

    _isProcessingData = true;
    final lengthBefore = _buffer.length;
    _hasNewData = false;

    _processDataAsync().catchError((error, stackTrace) {
      if (error is SSHError) {
        closeWithError(error, stackTrace);
      } else {
        closeWithError(SSHInternalError(error), stackTrace);
      }
    }).whenComplete(() {
      _isProcessingData = false;
      if (_buffer.isNotEmpty && !isClosed) {
        if (_hasNewData || _buffer.length < lengthBefore) {
          _scheduleProcessData();
        }
      }
    });
  }

  Future<void> _processDataAsync() async {
    if (_remoteVersion == null) {
      _processVersionExchange();
    }
    if (_remoteVersion != null) {
      await _processPackets();
    }
  }

  /// Maximum number of pre-banner lines accepted before the identification
  /// line. RFC 4253 §4.2 puts no limit on them; OpenSSH stops after 1024 and
  /// so do we, so that a server streaming lines forever cannot keep a client
  /// busy indefinitely. This library has no handshake timeout to fall back on.
  static const _maxPreBannerLines = 1024;

  /// Pre-banner lines skipped so far. Persists across calls to
  /// [_processVersionExchange] because the cap has to bound the whole
  /// exchange, not a single pass over the buffer.
  var _preBannerLines = 0;

  /// Parses the SSH protocol banner/version string sent by the remote host.
  ///
  /// This may be called multiple times as the socket delivers more data: if
  /// the buffer does not yet contain a full line, it simply waits for the
  /// next call instead of failing, since a banner routinely arrives split
  /// across multiple TCP segments or WebSocket frames.
  void _processVersionExchange() {
    printDebug?.call('SSHTransport._processVersionExchange');

    // RFC 4253 §4.2 allows the server to send arbitrary lines of text before
    // its identification line. Skip any such lines until the real
    // "SSH-" identification line arrives (or the buffer runs out).
    while (true) {
      if (_buffer.length > 10240) {
        throw SSHHandshakeError('Version exchange too long');
      }

      final bufferString = latin1.decode(_buffer.data);

      // SSH version exchange is terminated by \r\n.
      var index = bufferString.indexOf('\r\n');
      int lineEnd;
      if (index == -1) {
        // In the (rare) case SSH-2 version string is terminated by \n only (observed on Synology DS120j 2021)
        index = bufferString.indexOf('\n');
        if (index == -1) {
          // The line is not complete yet. Wait for more data to arrive from
          // the socket instead of failing; _onSocketData will call us again.
          return;
        }
        lineEnd = index + 1;
      } else {
        lineEnd = index + 2;
      }

      final versionString = bufferString.substring(0, index);

      if (!versionString.startsWith('SSH-')) {
        // A pre-banner line: discard it and keep looking for the
        // identification line.
        _preBannerLines++;
        if (_preBannerLines > _maxPreBannerLines) {
          throw SSHHandshakeError(
            'Too many lines before the version string '
            '(more than $_maxPreBannerLines)',
          );
        }
        _buffer.skip(lineEnd);
        continue;
      }

      _buffer.skip(lineEnd);

      // RFC compatibility: SSH-1.99 banners indicate SSH-2 support with SSH-1 fallback.
      if (!(versionString.startsWith('SSH-2.0-') ||
          versionString.startsWith('SSH-1.99-'))) {
        socket.sink.add(latin1.encode('Protocol mismatch\r\n'));
        throw SSHHandshakeError('Invalid version: $versionString');
      }

      printTrace?.call('<- $socket: $versionString');
      printDebug?.call('SSHTransport._remoteVersion = "$versionString"');
      _remoteVersion = versionString;

      if (isServer) {
        _sendKexInit();
      }

      // There maybe more data in the buffer, so it will be consumed by the
      // asynchronous packet processing queue.
      return;
    }
  }

  /// Process one or more SSH packets queued in [_buffer].
  Future<void> _processPackets() async {
    printDebug?.call('SSHTransport._processPackets');

    while (_buffer.isNotEmpty && !isClosed) {
      final payload = _consumePacket();
      if (payload == null) {
        break;
      }

      // Note: no payload-specific length check here. RFC 4253 §6.1's 32768
      // byte figure is the payload size every implementation must *accept*,
      // not a cap: a peer honouring our advertised 32768 byte channel packet
      // size still sends SSH_MSG_CHANNEL_DATA payloads of 32768 + 9 bytes of
      // message header. [SSHPacket.maxLength] (35000), enforced in
      // [_verifyPacketLength], is the bound that actually applies.

      await _handleMessage(payload);

      if (_resetRemotePacketSN) {
        _resetRemotePacketSN = false;
        _remotePacketSN.reset();
      } else {
        _remotePacketSN.increase();
      }
    }
  }

  /// Reads a single SSH packet from the buffer. Returns payload of the packet
  /// WITHOUT `packet length`, `padding length`, `padding` and `MAC`. Returns
  /// `null` if there is not enough data in the buffer to read the packet.
  Uint8List? _consumePacket() {
    if (_remoteCipherType == SSHCipherType.chacha20poly1305 &&
        _remoteChaChaCipher != null) {
      return _consumeChaChaPacket();
    }
    return (_decryptCipher == null && _remoteCipherKey == null)
        ? _consumeClearTextPacket()
        : _consumeEncryptedPacket();
  }

  /// Consumes and decrypts one OpenSSH ChaCha20-Poly1305 packet.
  Uint8List? _consumeChaChaPacket() {
    if (_buffer.length < OpenSSHChaCha20Poly1305.encryptedLengthSize) {
      return null;
    }

    final cipher = _remoteChaChaCipher!;
    final packetLength = cipher.decryptPacketLength(
      _buffer.view(0, OpenSSHChaCha20Poly1305.encryptedLengthSize),
      _remotePacketSN.value,
    );
    _verifyPacketLength(packetLength);
    if (packetLength % OpenSSHChaCha20Poly1305.blockSize != 0) {
      throw SSHPacketError(
        'Invalid packet alignment: $packetLength is not a multiple of '
        '${OpenSSHChaCha20Poly1305.blockSize}',
      );
    }

    final encryptedPacketLength = OpenSSHChaCha20Poly1305.encryptedLengthSize +
        packetLength +
        OpenSSHChaCha20Poly1305.tagSize;
    if (_buffer.length < encryptedPacketLength) {
      return null;
    }

    late Uint8List packet;
    try {
      packet = cipher.decryptPacket(
        _buffer.view(0, encryptedPacketLength),
        _remotePacketSN.value,
      );
    } on InvalidCipherTextException {
      throw SSHPacketError('AEAD authentication failed');
    }
    _buffer.skip(encryptedPacketLength);

    if (SSHPacket.readPacketLength(packet) != packetLength) {
      throw SSHPacketError('Decrypted packet length changed unexpectedly');
    }
    final paddingLength = SSHPacket.readPaddingLength(packet);
    final payloadLength = packetLength - paddingLength - 1;
    if (payloadLength < 0) {
      throw SSHPacketError(
        'Invalid padding length: $paddingLength for packet length $packetLength',
      );
    }

    final minimumPaddingLength = _alignedPaddingLength(
      payloadLength,
      OpenSSHChaCha20Poly1305.blockSize,
    );
    if (paddingLength < minimumPaddingLength) {
      throw SSHPacketError(
        'Invalid padding length: $paddingLength, expected: $minimumPaddingLength',
      );
    }

    return Uint8List.sublistView(packet, 5, 5 + payloadLength);
  }

  /// Consumes and returns a single unencrypted packet payload from the buffer.
  Uint8List? _consumeClearTextPacket() {
    printDebug?.call('SSHTransport._consumeClearTextPacket');

    if (_buffer.length < 4) {
      return null;
    }

    final packetLength = SSHPacket.readPacketLength(_buffer.data);
    _verifyPacketLength(packetLength);

    if (_buffer.length < packetLength + 4) {
      return null;
    }

    // A copy (the default consume()), not a view: this path only runs
    // before a cipher is negotiated, i.e. for the handful of small packets
    // exchanged during the initial handshake, so the extra allocation is
    // negligible. The returned payload is handed to an async handler that
    // may hold onto it indefinitely, so it's not worth reasoning about
    // whether aliasing the receive buffer would be safe here.
    final packet = _buffer.consume(packetLength + 4);
    final paddingLength = SSHPacket.readPaddingLength(packet);
    final payloadLength = packetLength - paddingLength - 1;
    _verifyPacketPadding(payloadLength, paddingLength);

    return Uint8List.sublistView(packet, 5, packet.length - paddingLength);
  }

  /// Consumes, decrypts, and returns a single encrypted packet payload from the buffer.
  Uint8List? _consumeEncryptedPacket() {
    printDebug?.call('SSHTransport._consumeEncryptedPacket');

    final remoteCipherType = _remoteCipherType;
    if (remoteCipherType != null &&
        remoteCipherType.isAead &&
        _remoteCipherKey != null &&
        _remoteIV != null) {
      return _consumeAeadPacket(remoteCipherType);
    }

    final blockSize = _decryptCipher!.blockSize;
    if (_buffer.length < blockSize) {
      return null;
    }

    final macType = _remoteMacType!;
    final isEtm = macType.isEtm;
    final macLength = _remoteMac!.macSize;

    if (isEtm) {
      // For ETM (Encrypt-Then-MAC) algorithms, the packet length is in plaintext
      // followed by the encrypted payload and then the MAC

      // We need at least 4 bytes to read the packet length
      if (_buffer.length < 4) {
        return null;
      }

      // Read the packet length from the plaintext data
      final packetLength = SSHPacket.readPacketLength(_buffer.data);
      _verifyPacketLength(packetLength);

      // Make sure we have enough data for the entire packet and MAC
      if (_buffer.length < 4 + packetLength + macLength) {
        return null;
      }

      // Get the packet length bytes
      final packetLengthBytes = _buffer.view(0, 4);

      // Get the encrypted payload and MAC
      final encryptedPayload = _buffer.view(4, packetLength);
      final mac = _buffer.view(4 + packetLength, macLength);

      // Verify the MAC on the packet length and encrypted payload
      final packetForMac = Uint8List(4 + packetLength);
      packetForMac.setRange(0, 4, packetLengthBytes);
      packetForMac.setRange(4, 4 + packetLength, encryptedPayload);
      _verifyPacketMac(packetForMac, mac, isEncrypted: true);

      // Consume the packet and MAC from the buffer. The bytes we actually
      // need (packetLengthBytes/encryptedPayload/mac) were already taken as
      // views above and are fully used by this point, so there is nothing
      // left to allocate here.
      _buffer.skip(4 + packetLength + macLength);

      // Ensure the encrypted payload length is a multiple of the block size
      if (encryptedPayload.length % blockSize != 0) {
        throw SSHPacketError(
          'Encrypted payload length ${encryptedPayload.length} is not a multiple of block size $blockSize',
        );
      }

      // Decrypt the payload
      final decryptedPayload = _decryptCipher!.processAll(encryptedPayload);

      // Process the decrypted payload
      final paddingLength = decryptedPayload[0];

      // Verify that the padding length is valid
      if (paddingLength < 4) {
        throw SSHPacketError(
          'Padding length too small: $paddingLength (minimum is 4)',
        );
      }

      if (paddingLength >= packetLength) {
        throw SSHPacketError(
          'Padding length too large: $paddingLength (packet length is $packetLength)',
        );
      }

      final payloadLength = packetLength - paddingLength - 1;
      if (payloadLength < 0) {
        throw SSHPacketError(
          'Invalid payload length: $payloadLength (packet length: $packetLength, padding length: $paddingLength)',
        );
      }

      // Skip the padding length byte and extract the payload
      return Uint8List.sublistView(decryptedPayload, 1, 1 + payloadLength);
    } else {
      // For standard MAC algorithms, decrypt the packet first, then verify the MAC

      if (_decryptBuffer.isEmpty) {
        // A view is safe here: firstBlock is only read synchronously by
        // process() below and never stored.
        final firstBlock = _buffer.consumeView(blockSize);
        _decryptBuffer.add(_decryptCipher!.process(firstBlock));
      }

      final packetLength = SSHPacket.readPacketLength(_decryptBuffer.data);
      _verifyPacketLength(packetLength);

      if (_buffer.length + _decryptBuffer.length <
          4 + packetLength + macLength) {
        return null;
      }

      final encryptedPacketLength = 4 + packetLength;
      if (encryptedPacketLength % blockSize != 0) {
        throw SSHPacketError(
          'Encrypted packet length $encryptedPacketLength is not a multiple '
          'of block size $blockSize',
        );
      }

      final remaining = encryptedPacketLength - _decryptBuffer.length;
      if (remaining > 0) {
        // Same as firstBlock above: processAll reads this synchronously into
        // a fresh array and never stores it, so a view is safe and saves
        // copying the rest of the packet.
        _decryptBuffer.add(
          _decryptCipher!.processAll(_buffer.consumeView(remaining)),
        );
      }

      // A view is safe here: _decryptBuffer only ever holds the decrypted
      // blocks for the packet currently being assembled (at most one
      // packet's worth), so aliasing it does not pin an unbounded amount
      // of memory the way aliasing the raw receive buffer could.
      final packet = _decryptBuffer.consumeView(packetLength + 4);

      // Authenticate before interpreting any attacker-controlled field of
      // the decrypted packet. Checking the padding length first would make
      // a padding error distinguishable from a MAC error, i.e. a padding
      // oracle.
      final mac = _buffer.consumeView(macLength);
      _verifyPacketMac(packet, mac, isEncrypted: false);

      final paddingLength = SSHPacket.readPaddingLength(packet);
      final payloadLength = packetLength - paddingLength - 1;
      _verifyPacketPadding(payloadLength, paddingLength);

      return Uint8List.sublistView(packet, 5, packet.length - paddingLength);
    }
  }

  /// Consumes and decrypts an AEAD-encrypted packet.
  Uint8List? _consumeAeadPacket(SSHCipherType cipherType) {
    if (_buffer.length < 4) {
      return null;
    }

    final packetLength = SSHPacket.readPacketLength(_buffer.data);
    _verifyPacketLength(packetLength);

    final tagLength = cipherType.aeadTagSize;
    if (_buffer.length < 4 + packetLength + tagLength) {
      return null;
    }

    // Views are safe here: aad is only read synchronously by _processAead
    // below, and ciphertext/tag are copied into encryptedInput immediately.
    final aad = _buffer.consumeView(4);
    final ciphertext = _buffer.consumeView(packetLength);
    final tag = _buffer.consumeView(tagLength);

    final encryptedInput = Uint8List(packetLength + tagLength)
      ..setRange(0, packetLength, ciphertext)
      ..setRange(packetLength, packetLength + tagLength, tag);

    late Uint8List plaintext;
    try {
      plaintext = _processAead(
        key: _remoteCipherKey!,
        iv: _remoteIV!,
        sequence: _remoteAeadPacketCount++,
        aad: aad,
        input: encryptedInput,
        forEncryption: false,
      );
    } on InvalidCipherTextException {
      throw SSHPacketError('AEAD authentication failed');
    }

    final paddingLength = plaintext[0];
    final payloadLength = packetLength - paddingLength - 1;
    if (payloadLength < 0) {
      throw SSHPacketError(
        'Invalid padding length: $paddingLength for packet length $packetLength',
      );
    }

    final minPaddingLength =
        _alignedPaddingLength(payloadLength, cipherType.blockSize);
    if (paddingLength < minPaddingLength) {
      throw SSHPacketError(
        'Invalid padding length: $paddingLength, expected: $minPaddingLength',
      );
    }

    return Uint8List.sublistView(plaintext, 1, 1 + payloadLength);
  }

  /// Validates that the parsed packet length is within acceptable bounds.
  ///
  /// The lower bound (5) is the minimum a well-formed packet can be: the 1
  /// byte padding length field plus the mandatory 4 byte minimum padding.
  /// Without it, a packetLength of 0-4 makes [SSHPacket.readPaddingLength]
  /// read past the data actually received for the packet.
  void _verifyPacketLength(int packetLength) {
    if (packetLength < 5) {
      throw SSHPacketError('Packet too short: $packetLength');
    }
    if (packetLength > SSHPacket.maxLength) {
      throw SSHPacketError('Packet too long: $packetLength');
    }
  }

  /// Verifies that the padding of the packet is correct. Throws [SSHPacketError]
  /// if the padding is incorrect.
  void _verifyPacketPadding(int payloadLength, int paddingLength) {
    final expectedPacketAlign = _decryptCipher == null
        ? SSHPacket.minAlign
        : max(SSHPacket.minAlign, _decryptCipher!.blockSize);

    final minPaddingLength = SSHPacket.paddingLength(
      payloadLength,
      align: expectedPacketAlign,
    );

    if (paddingLength < minPaddingLength) {
      throw SSHPacketError(
        'Invalid padding length: $paddingLength, expected: $minPaddingLength',
      );
    }
  }

  /// Verifies that the MAC of the packet is correct. Throws [SSHPacketError]
  /// if the MAC is incorrect.
  ///
  /// For ETM (Encrypt-Then-MAC) algorithms, the MAC is calculated on the packet length and encrypted payload.
  /// For standard MAC algorithms, the MAC is calculated on the unencrypted packet.
  void _verifyPacketMac(Uint8List payload, Uint8List actualMac,
      {bool isEncrypted = false}) {
    final macSize = _remoteMac!.macSize;
    if (actualMac.length != macSize) {
      throw ArgumentError.value(actualMac, 'mac', 'Invalid MAC size');
    }

    final macType = isClient ? _serverMacType! : _clientMacType!;
    final isEtm = macType.isEtm;

    _remoteMac!.updateAll(_remotePacketSN.value.toUint32());

    // For ETM algorithms, the MAC is calculated on the packet length and encrypted payload
    // For standard MAC algorithms, the MAC is calculated on the unencrypted packet
    if (isEtm && isEncrypted) {
      _remoteMac!.updateAll(payload);
    } else if (!isEtm && !isEncrypted) {
      _remoteMac!.updateAll(payload);
    } else {
      throw SSHPacketError(
        'MAC algorithm mismatch: isEtm=$isEtm, isEncrypted=$isEncrypted',
      );
    }

    final expectedMac = _remoteMac!.finish();

    if (!constantTimeEquals(expectedMac, actualMac)) {
      // Deliberately does not include the expected or actual MAC bytes: for
      // an attacker choosing the ciphertext, an expected-MAC value leaked
      // through a log would be a forgery oracle.
      throw SSHPacketError('MAC mismatch');
    }
  }

  /// Initiates the SSH version exchange handshake.
  void _startHandshake() {
    socket.sink.add(latin1.encode('$_localVersion\r\n'));

    if (isClient) {
      _sendKexInit();
    }
  }

  /// Derives and applies the encryption and MAC keys for local-to-remote communication.
  void _applyLocalKeys() {
    final cipherType = isClient ? _clientCipherType : _serverCipherType;
    if (cipherType == null) throw StateError('No cipher type selected');

    if (cipherType == SSHCipherType.chacha20poly1305) {
      final key = _deriveKey(
        isClient ? SSHDeriveKeyType.clientKey : SSHDeriveKeyType.serverKey,
        OpenSSHChaCha20Poly1305.keySize,
      );
      final chachaCipher = OpenSSHChaCha20Poly1305(key);

      _localCipherType = cipherType;
      _localMacType = null;
      _localChaChaCipher = chachaCipher;
      _localCipherKey = null;
      _localIV = null;
      _encryptCipher = null;
      _localMac = null;
      _localAeadPacketCount = 0;
      return;
    }

    final cipherKey = _deriveKey(
      isClient ? SSHDeriveKeyType.clientKey : SSHDeriveKeyType.serverKey,
      cipherType.keySize,
    );
    final iv = _deriveKey(
      isClient ? SSHDeriveKeyType.clientIV : SSHDeriveKeyType.serverIV,
      cipherType.ivSize,
    );

    if (cipherType.isAead) {
      _localCipherType = cipherType;
      _localMacType = null;
      _localChaChaCipher = null;
      _localCipherKey = cipherKey;
      _localIV = iv;
      _encryptCipher = null;
      _localMac = null;
      _localAeadPacketCount = 0;
      return;
    }

    final encryptCipher = cipherType.createCipher(
      cipherKey,
      iv,
      forEncryption: true,
    );

    final macType = isClient ? _clientMacType : _serverMacType;
    if (macType == null) throw StateError('No MAC type selected');

    final macKey = _deriveKey(
      isClient ? SSHDeriveKeyType.clientMacKey : SSHDeriveKeyType.serverMacKey,
      macType.keySize,
    );
    final mac = macType.createMac(macKey);

    _localCipherType = cipherType;
    _localMacType = macType;
    _localChaChaCipher = null;
    _localCipherKey = cipherKey;
    _localIV = iv;
    _encryptCipher = encryptCipher;
    _localMac = mac;
    _localAeadPacketCount = 0;
  }

  /// Derives and applies the decryption and MAC keys for remote-to-local communication.
  void _applyRemoteKeys() {
    final cipherType = isClient ? _serverCipherType : _clientCipherType;
    if (cipherType == null) throw StateError('No cipher type selected');

    if (cipherType == SSHCipherType.chacha20poly1305) {
      final key = _deriveKey(
        isClient ? SSHDeriveKeyType.serverKey : SSHDeriveKeyType.clientKey,
        OpenSSHChaCha20Poly1305.keySize,
      );
      final chachaCipher = OpenSSHChaCha20Poly1305(key);

      _remoteCipherType = cipherType;
      _remoteMacType = null;
      _remoteChaChaCipher = chachaCipher;
      _remoteCipherKey = null;
      _remoteIV = null;
      _decryptCipher = null;
      _remoteMac = null;
      _remoteAeadPacketCount = 0;
      return;
    }

    final cipherKey = _deriveKey(
      isClient ? SSHDeriveKeyType.serverKey : SSHDeriveKeyType.clientKey,
      cipherType.keySize,
    );
    final iv = _deriveKey(
      isClient ? SSHDeriveKeyType.serverIV : SSHDeriveKeyType.clientIV,
      cipherType.ivSize,
    );

    if (cipherType.isAead) {
      _remoteCipherType = cipherType;
      _remoteMacType = null;
      _remoteChaChaCipher = null;
      _remoteCipherKey = cipherKey;
      _remoteIV = iv;
      _decryptCipher = null;
      _remoteMac = null;
      _remoteAeadPacketCount = 0;
      return;
    }

    final decryptCipher = cipherType.createCipher(
      cipherKey,
      iv,
      forEncryption: false,
    );

    final macType = isClient ? _serverMacType : _clientMacType;
    if (macType == null) throw StateError('No MAC type selected');

    final macKey = _deriveKey(
      isClient ? SSHDeriveKeyType.serverMacKey : SSHDeriveKeyType.clientMacKey,
      macType.keySize,
    );
    final mac = macType.createMac(macKey);

    _remoteCipherType = cipherType;
    _remoteMacType = macType;
    _remoteChaChaCipher = null;
    _remoteCipherKey = cipherKey;
    _remoteIV = iv;
    _decryptCipher = decryptCipher;
    _remoteMac = mac;
    _remoteAeadPacketCount = 0;
  }

  /// Derives a cryptographic key/IV of [keySize] bytes using KDF rules for the given [keyType].
  Uint8List _deriveKey(SSHDeriveKeyType keyType, int keySize) {
    return SSHKexUtils.deriveKey(
      digest: _kexType!.createDigest(),
      sharedSecret: _sharedSecret!,
      exchangeHash: _exchangeHash!,
      keyType: keyType,
      sessionId: sessionId!,
      keySize: keySize,
    );
  }

  /// Composes the data blob to be signed by the client with its public key.
  Uint8List composeChallenge({
    required String username,
    required String service,
    required String publicKeyAlgorithm,
    required Uint8List publicKey,
  }) {
    final writer = SSHMessageWriter();
    writer.writeString(sessionId!);
    writer.writeUint8(SSH_Message_Userauth_Request.messageId);
    writer.writeUtf8(username);
    writer.writeUtf8(service);
    writer.writeUtf8('publickey');
    writer.writeBool(true);
    writer.writeUtf8(publicKeyAlgorithm);
    writer.writeString(publicKey);
    return writer.takeBytes();
  }

  /// Composes the RFC 4252 hostbased authentication data to be signed.
  Uint8List composeHostbasedChallenge({
    required String username,
    required String service,
    required String hostKeyAlgorithm,
    required Uint8List hostKey,
    required String clientHostName,
    required String clientUsername,
  }) {
    final writer = SSHMessageWriter();
    writer.writeString(sessionId!);
    writer.writeUint8(SSH_Message_Userauth_Request.messageId);
    writer.writeUtf8(username);
    writer.writeUtf8(service);
    writer.writeUtf8('hostbased');
    writer.writeUtf8(hostKeyAlgorithm);
    writer.writeString(hostKey);
    writer.writeUtf8(clientHostName);
    writer.writeUtf8(clientUsername);
    return writer.takeBytes();
  }

  /// Verifies the server's public host key signature against the computed exchange hash.
  bool _verifyHostkey({
    required Uint8List keyBytes,
    required Uint8List signatureBytes,
    required Uint8List exchangeHash,
  }) {
    switch (_hostkeyType) {
      case SSHHostkeyType.ed25519:
        final publicKey = SSHEd25519PublicKey.decode(keyBytes);
        final signature = SSHEd25519Signature.decode(signatureBytes);
        return publicKey.verify(exchangeHash, signature);
      case SSHHostkeyType.rsaSha1:
      case SSHHostkeyType.rsaSha256:
      case SSHHostkeyType.rsaSha512:
        final publicKey = SSHRsaPublicKey.decode(keyBytes);
        final signature = SSHRsaSignature.decode(signatureBytes);
        return publicKey.verify(exchangeHash, signature);
      case SSHHostkeyType.ecdsa256:
      case SSHHostkeyType.ecdsa384:
      case SSHHostkeyType.ecdsa521:
        final publicKey = SSHEcdsaPublicKey.decode(keyBytes);
        final signature = SSHEcdsaSignature.decode(signatureBytes);
        return publicKey.verify(exchangeHash, signature);
      case null:
        throw StateError('No hostkey type negotiated');
      default:
        throw UnimplementedError('Unsupported hostkey type: $_hostkeyType');
    }
  }

  /// Sends the KEXINIT message to negotiate algorithms with the remote peer.
  void _sendKexInit() {
    printDebug?.call('SSHTransport._sendKexInit');

    // Don't start a new key exchange when one is already in progress
    if (_kexInProgress && _sentKexInit) {
      printDebug?.call('Key exchange already in progress, ignoring');
      return;
    }

    // Mark that a new key-exchange round has started from our side.
    _kexInProgress = true;
    _sentKexInit = true;

    final message = SSH_Message_KexInit(
      kexAlgorithms: _localKexAlgorithmNames(),
      serverHostKeyAlgorithms: algorithms.hostkey.toNameList(),
      encryptionClientToServer: algorithms.cipher.toNameList(),
      encryptionServerToClient: algorithms.cipher.toNameList(),
      macClientToServer: algorithms.mac.toNameList(),
      macServerToClient: algorithms.mac.toNameList(),
      compressionClientToServer: ['none'],
      compressionServerToClient: ['none'],
      firstKexPacketFollows: false,
    );

    final payload = message.encode();
    _localKexInit = payload;

    sendPacket(payload);
    printTrace?.call('-> $socket: $message');
  }

  /// The key exchange name-list we advertise, including the pseudo algorithms
  /// that signal strict key exchange and EXT_INFO support.
  ///
  /// Both indicators are only meaningful in the first SSH_MSG_KEXINIT, so they
  /// are dropped once the initial key exchange is done. Sending them on a
  /// re-key would be ignored at best and confusing at worst.
  List<String> _localKexAlgorithmNames() {
    final names = algorithms.kex.toNameList();
    if (!_isFirstKex) return names;
    names.add(
      isServer
          ? SSHKexPseudoAlgorithm.strictKexServer
          : SSHKexPseudoAlgorithm.strictKexClient,
    );
    names.add(
      isServer
          ? SSHKexPseudoAlgorithm.extInfoServer
          : SSHKexPseudoAlgorithm.extInfoClient,
    );
    return names;
  }

  /// Send diffie-hellman key exchange message. The exact message format depends
  /// on the negotiated key exchange algorithm.
  void _sendKexDHInit() {
    printDebug?.call('SSHTransport._sendKexDHInit');

    final kex = _kex;
    late final SSHMessage message;

    if (kex is SSHKexDH) {
      message = SSH_Message_KexDH_Init(e: kex.e);
    } else if (kex is SSHKexECDH) {
      message = SSH_Message_KexECDH_Init(kex.publicKey);
    } else {
      throw StateError('No key exchange algorithm negotiated');
    }

    sendPacket(message.encode());
    printTrace?.call('-> $socket: $message');
  }

  /// Sends the Diffie-Hellman Group Exchange Request message.
  void _sendKexDHGexRequest() {
    printDebug?.call('SSHTransport._sendKexDHGexRequest');

    final message = SSH_Message_KexDH_GexRequest(
      minN: SSHKexDH.gexMin,
      preferredN: SSHKexDH.gexPref,
      maxN: SSHKexDH.gexMax,
    );

    sendPacket(message.encode());
    printTrace?.call('-> $socket: $message');
  }

  /// Sends the Diffie-Hellman Group Exchange Init message.
  void _sendKexDHGexInit() {
    printDebug?.call('SSHTransport._sendKexDHGexInit');

    final kex = _kex;
    if (kex is! SSHKexDH) {
      throw StateError('kex is not SSHKexDH');
    }

    final message = SSH_Message_KexDH_GexInit(e: kex.e);
    sendPacket(message.encode());
    printTrace?.call('-> $socket: $message');
  }

  /// Sends [SSH_Message_NewKeys] message. After this message, all data sent
  /// to the server should be encrypted with the keys negotiated in key exchange.
  void _sendNewKeys() {
    printDebug?.call('SSHTransport._sendNewKeys');
    final message = SSH_Message_NewKeys();
    printTrace?.call('-> $socket: $message');
    sendPacket(message.encode());

    // [sendPacket] already advanced the sequence number past NEWKEYS, so under
    // strict key exchange the reset belongs right here: the next packet we
    // send is the first one of the new keys and must be number zero.
    if (_strictKex) {
      _localPacketSN.reset();
    }
  }

  /// Dispatches the incoming decrypted packet payload to the appropriate message handler.
  Future<void> _handleMessage(Uint8List message) async {
    final messageId = SSHMessage.readMessageId(message);

    // Under strict key exchange the optional transport messages are not
    // allowed to appear between KEXINIT and NEWKEYS. Receiving one there means
    // someone is padding the transcript, so the connection is torn down.
    if (_strictKex &&
        _isFirstKex &&
        _kexInProgress &&
        _isForbiddenDuringStrictKex(messageId)) {
      throw SSHHandshakeError(
        'Strict key exchange violation: message $messageId received during '
        'key exchange',
      );
    }

    switch (messageId) {
      case SSH_Message_Disconnect.messageId:
        final disconnect = SSH_Message_Disconnect.decode(message);
        printTrace?.call('<- $socket: $disconnect');
        // The peer said why it is going away. Surface that instead of letting
        // the caller see an unexplained disconnection.
        return closeWithError(
          SSHDisconnectError(
            disconnect.reasonCode,
            disconnect.description,
          ),
        );
      case SSH_Message_Ignore.messageId:
        final ignore = SSH_Message_Ignore.decode(message);
        printTrace?.call('<- $socket: $ignore');
        return;
      case SSH_Message_Unimplemented.messageId:
        final unimplemented = SSH_Message_Unimplemented.decode(message);
        printTrace?.call('<- $socket: $unimplemented');
        printDebug?.call(
          'Received SSH_MSG_UNIMPLEMENTED for packet '
          '${unimplemented.sequenceNumber}',
        );
        return;
      case SSH_Message_Debug.messageId:
        final debug = SSH_Message_Debug.decode(message);
        printTrace?.call('<- $socket: $debug');
        printDebug?.call(
          'Remote: ${utf8.decode(debug.message, allowMalformed: true)}',
        );
        return;
      case SSH_Message_KexInit.messageId:
        return _handleMessageKexInit(message);
      case SSH_Message_KexDH_Reply.messageId:
      case SSH_Message_KexDH_GexReply.messageId:
        return _handleMessageKexReply(message);
      case SSH_Message_NewKeys.messageId:
        return _handleMessageNewKeys(message);
      case SSH_Message_ExtInfo.messageId:
        if (_kexInProgress) {
          return _handleUnexpectedKexMessage(messageId);
        }
        return _handleMessageExtInfo(message);
      default:
        if (_kexInProgress) {
          return _handleUnexpectedKexMessage(messageId);
        }

        final messageHandler = onMessage;
        if (messageHandler != null) {
          if (messageHandler(message)) return;
        } else {
          // Deprecated path, kept so existing callers keep working. It
          // cannot report whether the message was recognized, so nothing is
          // ever answered with SSH_MSG_UNIMPLEMENTED on its behalf.
          final packetHandler = onPacket;
          if (packetHandler != null) {
            packetHandler(message);
            return;
          }
        }

        _sendUnimplemented(messageId);
    }
  }

  /// Handles a message that is not valid during the current key exchange.
  ///
  /// OpenSSH disconnects for unexpected messages during the initial strict
  /// key exchange. For non-strict exchanges and rekeys, it reports the
  /// message as unimplemented.
  void _handleUnexpectedKexMessage(int messageId) {
    if (_strictKex && _isFirstKex) {
      throw SSHHandshakeError(
        'Strict key exchange violation: unexpected message $messageId '
        'received during key exchange',
      );
    }
    _sendUnimplemented(messageId);
  }

  /// Reports an unrecognized message using the rejected packet's sequence
  /// number, before [_processPackets] advances it.
  void _sendUnimplemented(int messageId) {
    final message = SSH_Message_Unimplemented(_remotePacketSN.value);
    printDebug?.call(
      'Unsupported SSH message $messageId at packet '
      '${_remotePacketSN.value}',
    );
    printTrace?.call('-> $socket: $message');
    sendPacket(message.encode());
  }

  /// Records the extensions advertised by the peer in SSH_MSG_EXT_INFO.
  void _handleMessageExtInfo(Uint8List payload) {
    final message = SSH_Message_ExtInfo.decode(payload);
    printDebug?.call('SSHTransport._handleMessageExtInfo');
    printTrace?.call('<- $socket: $message');

    _extInfo = message.extensions;
    _serverSigAlgs = message.serverSigAlgs;
  }

  /// Enables strict key exchange when the peer advertised it in its first
  /// SSH_MSG_KEXINIT, and validates the preconditions the mode requires.
  ///
  /// Strict key exchange is the Terrapin (CVE-2023-48795) countermeasure. Once
  /// both sides have advertised it, the first SSH_MSG_KEXINIT must be the very
  /// first packet of the connection: if it is not, packets were inserted or
  /// removed before it and the exchange hash no longer covers the real
  /// transcript.
  void _negotiateStrictKex(SSH_Message_KexInit message) {
    final peerIndicator = isServer
        ? SSHKexPseudoAlgorithm.strictKexClient
        : SSHKexPseudoAlgorithm.strictKexServer;

    _strictKex = message.kexAlgorithms.contains(peerIndicator);
    printDebug?.call('SSHTransport._strictKex = $_strictKex');

    if (!_strictKex) return;

    if (_remotePacketSN.value != 0) {
      throw SSHHandshakeError(
        'Strict key exchange violation: KEXINIT was not the first packet '
        '(sequence number ${_remotePacketSN.value})',
      );
    }
  }

  /// Whether [messageId] is one of the optional transport messages that strict
  /// key exchange forbids while a key exchange is running.
  ///
  /// SSH_MSG_IGNORE (2), SSH_MSG_UNIMPLEMENTED (3) and SSH_MSG_DEBUG (4) carry
  /// no meaning for the exchange but do advance the sequence numbers, which is
  /// exactly what the Terrapin attack abuses.
  static bool _isForbiddenDuringStrictKex(int messageId) {
    return messageId >= 2 && messageId <= 4;
  }

  /// Processes the KEXINIT message received from the remote peer and negotiates algorithms.
  Future<void> _handleMessageKexInit(Uint8List payload) async {
    printDebug?.call('SSHTransport._handleMessageKexInit');

    // If this message initiates a new key-exchange round from the remote
    // side, we MUST respond with our own KEXINIT (RFC 4253 §7.1).
    if (!_kexInProgress) {
      // Start a new exchange initiated by the peer.
      _kexInProgress = true;
    }

    if (!_sentKexInit) {
      // We have not sent our KEXINIT for this round yet, do it now.
      _sendKexInit();
    }

    final message = SSH_Message_KexInit.decode(payload);
    printTrace?.call('<- $socket: $message');
    _remoteKexInit = payload;

    if (_isFirstKex) {
      _negotiateStrictKex(message);
    }

    _kexType = SSHKexUtils.selectAlgorithm(
      localAlgorithms: algorithms.kex,
      remoteAlgorithms: message.kexAlgorithms,
      isServer: isServer,
    );
    _hostkeyType = SSHKexUtils.selectAlgorithm(
      localAlgorithms: algorithms.hostkey,
      remoteAlgorithms: message.serverHostKeyAlgorithms,
      isServer: isServer,
    );
    _clientCipherType = SSHKexUtils.selectAlgorithm(
      localAlgorithms: algorithms.cipher,
      remoteAlgorithms: message.encryptionClientToServer,
      isServer: isServer,
    );
    _serverCipherType = SSHKexUtils.selectAlgorithm(
      localAlgorithms: algorithms.cipher,
      remoteAlgorithms: message.encryptionServerToClient,
      isServer: isServer,
    );
    _clientMacType = SSHKexUtils.selectAlgorithm(
      localAlgorithms: algorithms.mac,
      remoteAlgorithms: message.macClientToServer,
      isServer: isServer,
    );
    _serverMacType = SSHKexUtils.selectAlgorithm(
      localAlgorithms: algorithms.mac,
      remoteAlgorithms: message.macServerToClient,
      isServer: isServer,
    );

    if (_kexType == null) {
      throw StateError('No matching key exchange algorithm');
    }
    if (_hostkeyType == null) {
      throw StateError('No matching host key algorithm');
    }
    if (_clientCipherType == null) {
      throw StateError('No matching client cipher algorithm');
    }
    if (_serverCipherType == null) {
      throw StateError('No matching server cipher algorithm');
    }
    if (_clientMacType == null && !_clientCipherType!.isAead) {
      throw StateError('No matching client MAC algorithm');
    }
    if (_serverMacType == null && !_serverCipherType!.isAead) {
      throw StateError('No matching server MAC algorithm');
    }

    printDebug?.call('SSHTransport._kexType: $_kexType');
    printDebug?.call('SSHTransport._hostkeyType: $_hostkeyType');
    printDebug?.call('SSHTransport._clientCipherType: $_clientCipherType');
    printDebug?.call('SSHTransport._serverCipherType: $_serverCipherType');
    printDebug?.call('SSHTransport._clientMacType: $_clientMacType');
    printDebug?.call('SSHTransport._serverMacType: $_serverMacType');

    switch (_kexType) {
      // Elliptic curve key generation is a single fixed-size scalar multiply,
      // well under a millisecond. Spawning an isolate for it costs several
      // times more than the work it offloads, and the server is timing our
      // handshake while we pay it, so it stays on this isolate.
      case SSHKexType.x25519:
      case SSHKexType.x25519Rfc:
        _kex = SSHKexX25519();
        break;
      case SSHKexType.nistp256:
        _kex = SSHKexNist.p256();
        break;
      case SSHKexType.nistp384:
        _kex = SSHKexNist.p384();
        break;
      case SSHKexType.nistp521:
        _kex = SSHKexNist.p521();
        break;
      // Finite field Diffie-Hellman is the one exchange whose cost the server
      // controls: group exchange lets it name a modulus up to 8192 bits, and
      // modular exponentiation grows steeply with that size. These stay
      // offloaded so a large group cannot block the calling isolate.
      case SSHKexType.dh14Sha1:
      case SSHKexType.dh14Sha256:
        _kex = await SSHKexDH.group14Async();
        break;
      case SSHKexType.dh1Sha1:
        _kex = await SSHKexDH.group1Async();
        break;
      case SSHKexType.dhGexSha1:
      case SSHKexType.dhGexSha256:
        if (isClient) _sendKexDHGexRequest();
        return;
      default:
        throw UnimplementedError('$_kexType');
    }

    if (isClient) {
      _sendKexDHInit();
    }
  }

  /// When client receives [SSH_Message_KexECDH_Reply], it should verify the
  /// server's signature with the server's public key. Then send NEW_KEYS
  /// message back to the server.
  Future<void> _handleMessageKexReply(Uint8List payload) async {
    printDebug?.call('SSHTransport._handleMessageKexReply');
    if (isServer) throw SSHStateError('Unexpected KEX_REPLY');

    final kex = _kex;
    final kexType = _kexType;

    if (kexType == null) {
      throw SSHStateError('kexType has not been negotiated');
    }

    if (kex == null) {
      if (kexType.isGroupExchange == true) {
        return _handleMessageKexGexReply(payload);
      } else {
        throw SSHStateError('No key exchange algorithm');
      }
    }

    late Uint8List hostkey;
    late Uint8List hostSignature;
    late Uint8List serverKexKey;
    late Uint8List clientKexKey;
    late BigInt sharedSecret;

    if (kex is SSHKexDH) {
      final message = kexType.isGroupExchange
          ? SSH_Message_KexDH_GexReply.decode(payload)
          : SSH_Message_KexDH_Reply.decode(payload);
      printTrace?.call('<- $socket: $message');
      hostkey = message.hostPublicKey;
      hostSignature = message.signature;
      serverKexKey = encodeBigInt(message.f);
      clientKexKey = encodeBigInt(kex.e);
      sharedSecret = await kex.computeSecretAsync(message.f);
    } else if (kex is SSHKexECDH) {
      final message = SSH_Message_KexECDH_Reply.decode(payload);
      printTrace?.call('<- $socket: $message');
      hostkey = message.hostPublicKey;
      hostSignature = message.signature;
      serverKexKey = message.ecdhPublicKey;
      clientKexKey = kex.publicKey;
      sharedSecret = kex.computeSecret(message.ecdhPublicKey);
    } else {
      throw UnimplementedError('$kex');
    }

    final exchangeHash = SSHKexUtils.computeExchangeHash(
      digest: _kexType!.createDigest(),
      groupExchange: kexType.isGroupExchange ? kex as SSHKexDH : null,
      clientVersion: _localVersion,
      serverVersion: _remoteVersion!,
      clientKexInit: _localKexInit,
      serverKexInit: _remoteKexInit,
      hostKey: hostkey,
      clientPublicKey: clientKexKey,
      serverPublicKey: serverKexKey,
      sharedSecret: sharedSecret,
    );

    if (!disableHostkeyVerification) {
      printDebug?.call('SSHTransport._verifyHostkey');
      final verified = _verifyHostkey(
        keyBytes: hostkey,
        signatureBytes: hostSignature,
        exchangeHash: exchangeHash,
      );
      if (!verified) throw SSHHostkeyError('Signature verification failed');
    }

    _exchangeHash = exchangeHash;
    _sessionId ??= exchangeHash;
    _sharedSecret = sharedSecret;

    final fingerprint = hostkeyFingerprint(hostkey);

    if (_hostkeyVerified) {
      // The signature above is re-checked on every rekey, but that only
      // proves the *current* host key is self-consistent, not that it is
      // the same key the user (or [onVerifyHostKey]) already approved.
      // OpenSSH rejects a host key change during rekey; do the same.
      final verifiedFingerprint = _verifiedHostkeyFingerprint;
      if (verifiedFingerprint == null ||
          _verifiedHostkeyType != _hostkeyType ||
          !constantTimeEquals(verifiedFingerprint, fingerprint)) {
        closeWithError(
          SSHHostkeyError(
            'Host key changed during rekey: was $_verifiedHostkeyType '
            '${utf8.decode(verifiedFingerprint ?? Uint8List(0), allowMalformed: true)}, '
            'now $_hostkeyType '
            '${utf8.decode(fingerprint, allowMalformed: true)}',
          ),
        );
        return;
      }
      _sendNewKeys();
      _applyLocalKeys();
      return;
    }

    // The server is waiting for our NEWKEYS while this runs, and a slow
    // callback here has already been mistaken for a hung key exchange, so
    // bracket it in the debug log rather than leaving a silent gap.
    printDebug?.call('SSHTransport.onVerifyHostKey');
    final userVerified = onVerifyHostKey != null
        ? await Future.value(onVerifyHostKey!(_hostkeyType!.name, fingerprint))
        : true;
    printDebug?.call('SSHTransport.onVerifyHostKey = $userVerified');

    if (!userVerified) {
      closeWithError(SSHHostkeyError('Hostkey verification failed'));
      return;
    }

    _hostkeyVerified = true;
    _verifiedHostkeyFingerprint = fingerprint;
    _verifiedHostkeyType = _hostkeyType;
    _sendNewKeys();
    _applyLocalKeys();
    onReady?.call();
  }

  /// Processes the Group Exchange Reply (GEX Group) message containing Diffie-Hellman params.
  Future<void> _handleMessageKexGexReply(Uint8List payload) async {
    printDebug?.call('SSHTransport._handleMessageKexGexReply');
    if (isServer) throw SSHStateError('Unexpected KEX_GEX_REPLY');

    final message = SSH_Message_KexDH_GexGroup.decode(payload);
    printTrace?.call('<- $socket: $message');

    _kex =
        await SSHKexDH.createAsync(p: message.p, g: message.g, secretBits: 256);
    _sendKexDHGexInit();
  }

  /// Handles the NEWKEYS message, activating the remote decryption keys and flushing queued packets.
  Future<void> _handleMessageNewKeys(Uint8List message) async {
    printDebug?.call('SSHTransport._handleMessageNewKeys');
    printTrace?.call('<- $socket: SSH_Message_NewKeys');

    _applyRemoteKeys();

    // Key exchange round finished.
    _kexInProgress = false;
    _sentKexInit = false;
    _isFirstKex = false;
    _kex = null;

    // The reset is deferred to [_processPackets]: this handler runs before the
    // trailing increment for the NEWKEYS packet, so resetting here would be
    // undone immediately.
    if (_strictKex) {
      _resetRemotePacketSN = true;
    }

    // Flush any pending packets
    final pending = List<Uint8List>.from(_rekeyPendingPackets);
    _rekeyPendingPackets.clear();
    for (final packet in pending) {
      sendPacket(packet);
    }

    final rekeyCompleter = _rekeyCompleter;
    _rekeyCompleter = null;
    rekeyCompleter?.complete();
  }

  /// Initiates a client-side re-key operation. This can be called
  /// by client code to refresh session keys when needed.
  ///
  /// The returned future completes when the exchange reaches
  /// SSH_MSG_NEWKEYS. If an exchange is already running, whether this side
  /// or the peer started it, no second one is sent and the future tracks the
  /// exchange in flight. If the connection ends before new keys are in place
  /// the future completes with the error that ended it, or with an
  /// [SSHStateError] on an orderly close.
  Future<void> rekey() {
    printDebug?.call('SSHTransport.rekey');

    if (isClosed) {
      final failed = Future<void>.error(
        SSHStateError('Transport is closed'),
        StackTrace.current,
      );

      // Same guard as [_waitForNewKeys]: a caller that drops this future the
      // way the old `void` signature forced must not leak the error to their
      // zone. Marking it handled here does not take it from a caller who does
      // await, a future can carry more than one listener.
      failed.catchError((_) {});

      return failed;
    }

    final future = _waitForNewKeys();

    if (_kexInProgress) {
      printDebug?.call(
        'Key exchange already in progress, waiting for it instead of '
        'starting another',
      );
      return future;
    }

    _sendKexInit();
    return future;
  }

  /// The future of the [_rekeyCompleter], creating it if no caller is waiting
  /// on the current exchange yet.
  Future<void> _waitForNewKeys() {
    final completer = _rekeyCompleter ??= Completer<void>();

    // A caller is free to drop the future, and the connection dying is not an
    // unhandled error just because nobody looked. This listener marks the
    // error handled without taking it away from the caller: the completer's
    // future can carry more than one.
    completer.future.catchError((_) {});

    return completer.future;
  }

  /// Fails a [rekey] future that will never see its NEW_KEYS because the
  /// connection ended first.
  void _failPendingRekey(Object error, StackTrace stackTrace) {
    final rekeyCompleter = _rekeyCompleter;
    _rekeyCompleter = null;
    rekeyCompleter?.completeError(error, stackTrace);
  }

  /// Determines if a packet should bypass the rekey buffer.
  ///
  /// During key exchange, most packets should be buffered until the exchange
  /// is complete. However, key exchange packets themselves and transport layer
  /// control messages (like disconnect) need to be sent immediately.
  ///
  /// Per RFC 4253, the following message types bypass the buffer:
  ///
  ///  /// Critical transport messages (1-4):
  /// - 1: [SSH_Message_Disconnect]
  /// - 2: [SSH_Message_Ignore]
  /// - 3: [SSH_Message_Unimplemented]
  /// - 4: [SSH_Message_Debug]
  ///
  /// Key exchange messages (20-49):
  /// - 20: [SSH_Message_KexInit]
  /// - 21: [SSH_Message_NewKeys]
  /// - 30: [SSH_Message_KexDH_Init]/[SSH_Message_KexECDH_Init]
  /// - 31: [SSH_Message_KexDH_Reply]/[SSH_Message_KexECDH_Reply]/[SSH_Message_KexDH_GexGroup]
  /// - 32: [SSH_Message_KexDH_GexInit]
  /// - 33: [SSH_Message_KexDH_GexReply]
  /// - 34: [SSH_Message_KexDH_GexRequest]
  ///
  ///
  bool _shouldBypassRekeyBuffer(Uint8List data) {
    if (data.isEmpty) return false;

    final messageId = data[0];
    return (messageId >= 20 && messageId <= 49) || messageId <= 4;
  }
}

/// Internal state of [transport], for this package's own tests.
///
/// The transport implements only the client side of the key exchange, so its
/// tests cannot run a real handshake in memory. They set up the state one
/// would leave behind (negotiated algorithms, keys, sequence numbers) and
/// drive the steps that follow it. This is not part of the public API: like
/// [SSHTransportTestHooks], it is hidden from `package:dartssh2/dartssh2.dart`,
/// so [SSHTransport] itself gains no member, and it may change in any release.
@visibleForTesting
SSHTransportTestHooks transportTestHooks(SSHTransport transport) =>
    SSHTransportTestHooks._(transport);

/// See [transportTestHooks].
@visibleForTesting
class SSHTransportTestHooks {
  SSHTransportTestHooks._(this._transport);

  final SSHTransport _transport;

  set remoteVersion(String? value) => _transport._remoteVersion = value;

  set localKexInit(Uint8List value) => _transport._localKexInit = value;

  set remoteKexInit(Uint8List value) => _transport._remoteKexInit = value;

  set kexType(SSHKexType? value) => _transport._kexType = value;

  set hostkeyType(SSHHostkeyType? value) => _transport._hostkeyType = value;

  set clientCipherType(SSHCipherType? value) =>
      _transport._clientCipherType = value;

  set serverCipherType(SSHCipherType? value) =>
      _transport._serverCipherType = value;

  SSHCipherType? get localCipherType => _transport._localCipherType;
  set localCipherType(SSHCipherType? value) =>
      _transport._localCipherType = value;

  SSHCipherType? get remoteCipherType => _transport._remoteCipherType;
  set remoteCipherType(SSHCipherType? value) =>
      _transport._remoteCipherType = value;

  set clientMacType(SSHMacType? value) => _transport._clientMacType = value;

  set serverMacType(SSHMacType? value) => _transport._serverMacType = value;

  SSHMacType? get localMacType => _transport._localMacType;
  set localMacType(SSHMacType? value) => _transport._localMacType = value;

  SSHMacType? get remoteMacType => _transport._remoteMacType;
  set remoteMacType(SSHMacType? value) => _transport._remoteMacType = value;

  set kex(SSHKex? value) => _transport._kex = value;

  set sessionId(Uint8List? value) => _transport._sessionId = value;

  set exchangeHash(Uint8List? value) => _transport._exchangeHash = value;

  bool get hostkeyVerified => _transport._hostkeyVerified;

  Uint8List? get verifiedHostkeyFingerprint =>
      _transport._verifiedHostkeyFingerprint;

  set sharedSecret(BigInt? value) => _transport._sharedSecret = value;

  BlockCipher? get encryptCipher => _transport._encryptCipher;
  set encryptCipher(BlockCipher? value) => _transport._encryptCipher = value;

  BlockCipher? get decryptCipher => _transport._decryptCipher;
  set decryptCipher(BlockCipher? value) => _transport._decryptCipher = value;

  OpenSSHChaCha20Poly1305? get localChaChaCipher =>
      _transport._localChaChaCipher;
  set localChaChaCipher(OpenSSHChaCha20Poly1305? value) =>
      _transport._localChaChaCipher = value;

  OpenSSHChaCha20Poly1305? get remoteChaChaCipher =>
      _transport._remoteChaChaCipher;
  set remoteChaChaCipher(OpenSSHChaCha20Poly1305? value) =>
      _transport._remoteChaChaCipher = value;

  Uint8List? get localCipherKey => _transport._localCipherKey;
  set localCipherKey(Uint8List? value) => _transport._localCipherKey = value;

  Uint8List? get remoteCipherKey => _transport._remoteCipherKey;
  set remoteCipherKey(Uint8List? value) => _transport._remoteCipherKey = value;

  Uint8List? get localIV => _transport._localIV;
  set localIV(Uint8List? value) => _transport._localIV = value;

  Uint8List? get remoteIV => _transport._remoteIV;
  set remoteIV(Uint8List? value) => _transport._remoteIV = value;

  Mac? get localMac => _transport._localMac;
  set localMac(Mac? value) => _transport._localMac = value;

  Mac? get remoteMac => _transport._remoteMac;
  set remoteMac(Mac? value) => _transport._remoteMac = value;

  bool get kexInProgress => _transport._kexInProgress;
  set kexInProgress(bool value) => _transport._kexInProgress = value;

  set sentKexInit(bool value) => _transport._sentKexInit = value;

  set isFirstKex(bool value) => _transport._isFirstKex = value;

  set strictKex(bool value) => _transport._strictKex = value;

  ChunkBuffer get buffer => _transport._buffer;

  SSHPacketSN get localPacketSN => _transport._localPacketSN;

  SSHPacketSN get remotePacketSN => _transport._remotePacketSN;

  List<Uint8List> get rekeyPendingPackets => _transport._rekeyPendingPackets;

  Future<void> processPackets() => _transport._processPackets();

  Future<void> handleMessage(Uint8List message) =>
      _transport._handleMessage(message);

  Future<void> handleMessageKexInit(Uint8List payload) =>
      _transport._handleMessageKexInit(payload);

  Future<void> handleMessageKexReply(Uint8List payload) =>
      _transport._handleMessageKexReply(payload);

  Future<void> handleMessageNewKeys(Uint8List message) =>
      _transport._handleMessageNewKeys(message);

  void handleMessageExtInfo(Uint8List payload) =>
      _transport._handleMessageExtInfo(payload);

  void sendKexInit() => _transport._sendKexInit();

  void sendNewKeys() => _transport._sendNewKeys();

  void applyLocalKeys() => _transport._applyLocalKeys();

  void applyRemoteKeys() => _transport._applyRemoteKeys();

  Uint8List? consumePacket() => _transport._consumePacket();

  Uint8List? consumeChaChaPacket() => _transport._consumeChaChaPacket();

  Uint8List? consumeAeadPacket(SSHCipherType cipherType) =>
      _transport._consumeAeadPacket(cipherType);

  void verifyPacketLength(int packetLength) =>
      _transport._verifyPacketLength(packetLength);

  Uint8List nonceForSequence(Uint8List iv, int sequence) =>
      _transport._nonceForSequence(iv, sequence);
}
