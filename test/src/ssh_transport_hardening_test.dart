// Uses dart:mirrors, which is VM-only.
@TestOn('vm')
library;

import 'dart:async';
// Deprecated in Dart 3.14, still needed here to reach private state.
// ignore: deprecated_member_use
import 'dart:mirrors';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/kex/kex_x25519.dart';
import 'package:dartssh2/src/message/msg_kex_ecdh.dart';
import 'package:dartssh2/src/message/msg_kex.dart';
import 'package:dartssh2/src/ssh_message.dart';
import 'package:dartssh2/src/ssh_packet.dart';
import 'package:dartssh2/src/utils/cipher_ext.dart';
import 'package:pointycastle/export.dart';
import 'package:test/test.dart';

/// Builds the wire payload of an `SSH_MSG_KEXDH_REPLY` (host key, ephemeral
/// public key, signature — RFC 4253 §8), in the field order
/// [SSH_Message_KexECDH_Reply.decode] expects.
///
/// Deliberately does not use [SSH_Message_KexECDH_Reply.encode]: that method
/// writes the ephemeral public key before the host key, the opposite of what
/// its own `decode` (and the wire format) expects. That mismatch is a
/// pre-existing bug in lib/src/message/msg_kex_ecdh.dart, outside the scope
/// of this change (message/** is owned by another workstream), so this
/// helper reproduces the correct RFC 4253 wire order directly instead of
/// exercising the broken round trip.
Uint8List _encodeKexEcdhReply({
  required Uint8List hostPublicKey,
  required Uint8List ecdhPublicKey,
  required Uint8List signature,
}) {
  final writer = SSHMessageWriter();
  writer.writeUint8(SSH_Message_KexECDH_Reply.messageId);
  writer.writeString(hostPublicKey);
  writer.writeString(ecdhPublicKey);
  writer.writeString(signature);
  return writer.takeBytes();
}

/// Regression tests for the transport-layer security audit findings T-05
/// (random padding), T-07 (host key pinning across rekey), T-09/T-11
/// (malformed length handling) and T-12 (MAC-before-padding ordering).
///
/// These exercise the transport's private send/receive paths directly via
/// `dart:mirrors`, following the same pattern already used by
/// ssh_transport_aead_test.dart and ssh_transport_strict_kex_test.dart.
void main() {
  final transportLibrary = reflectClass(SSHTransport).owner as LibraryMirror;
  final packetLibrary = reflectClass(SSHPacketSN).owner as LibraryMirror;

  Symbol privateSymbol(String name) =>
      MirrorSystem.getSymbol(name, transportLibrary);
  Symbol packetPrivateSymbol(String name) =>
      MirrorSystem.getSymbol(name, packetLibrary);

  void setPrivate(SSHTransport transport, String field, Object? value) {
    reflect(transport).setField(privateSymbol(field), value);
  }

  T getPrivate<T>(SSHTransport transport, String field) {
    return reflect(transport).getField(privateSymbol(field)).reflectee as T;
  }

  void setSequenceValue(SSHTransport transport, String field, int value) {
    final sequence =
        reflect(transport).getField(privateSymbol(field)).reflectee;
    reflect(sequence).setField(packetPrivateSymbol('_value'), value);
  }

  Future<Object?> invokePrivate(
    SSHTransport transport,
    String method,
    List<Object?> args,
  ) async {
    final result = reflect(transport).invoke(privateSymbol(method), args);
    final value = result.reflectee;
    if (value is Future) return await value;
    return value;
  }

  group('T-05: padding is random', () {
    test(
        'ETM send path uses padding that is not all zero and differs '
        'between packets with identical payloads', () {
      final cipherType = SSHCipherType.aes128ctr;
      final macType = SSHMacType.hmacSha256Etm;
      final key = Uint8List.fromList(
        List<int>.generate(cipherType.keySize, (i) => i),
      );
      final iv = Uint8List.fromList(
        List<int>.generate(cipherType.ivSize, (i) => i + 1),
      );
      final macKey = Uint8List.fromList(
        List<int>.generate(macType.keySize, (i) => i + 2),
      );

      Uint8List paddingOf(Uint8List payload) {
        final socket = _CaptureSSHSocket();
        final transport = SSHTransport(socket);
        setPrivate(transport, '_clientMacType', macType);
        setPrivate(transport, '_localMacType', macType);
        setPrivate(
          transport,
          '_encryptCipher',
          cipherType.createCipher(key, iv, forEncryption: true),
        );
        setPrivate(transport, '_localMac', macType.createMac(macKey));
        setPrivate(transport, '_kexInProgress', false);
        setSequenceValue(transport, '_localPacketSN', 0);

        transport.sendPacket(payload);
        final packet = socket.packets.last;
        transport.close();

        final packetLength = SSHPacket.readPacketLength(packet);
        final encryptedPayload =
            Uint8List.sublistView(packet, 4, 4 + packetLength);

        final decryptCipher =
            cipherType.createCipher(key, iv, forEncryption: false);
        final decrypted = decryptCipher.processAll(encryptedPayload);
        final paddingLength = decrypted[0];
        expect(paddingLength, greaterThanOrEqualTo(4));

        return Uint8List.sublistView(
          decrypted,
          decrypted.length - paddingLength,
        );
      }

      final payload = Uint8List.fromList(List<int>.generate(10, (i) => i));
      final firstPadding = paddingOf(payload);
      final secondPadding = paddingOf(payload);

      expect(firstPadding, isNot(everyElement(0)));
      expect(firstPadding, isNot(equals(secondPadding)));
    });

    test(
        'AEAD send path uses padding that is not all zero and differs '
        'between packets with identical payloads', () {
      for (final cipherType in [
        SSHCipherType.aes128gcm,
        SSHCipherType.aes256gcm,
      ]) {
        final key = Uint8List.fromList(
          List<int>.generate(cipherType.keySize, (i) => i),
        );
        final iv = Uint8List.fromList(
          List<int>.generate(cipherType.ivSize, (i) => i + 5),
        );

        Uint8List paddingOf(Uint8List payload) {
          final socket = _CaptureSSHSocket();
          final transport = SSHTransport(socket);
          setPrivate(transport, '_clientCipherType', cipherType);
          setPrivate(transport, '_localCipherType', cipherType);
          setPrivate(transport, '_localCipherKey', key);
          setPrivate(transport, '_localIV', iv);
          setPrivate(transport, '_kexInProgress', false);
          setSequenceValue(transport, '_localPacketSN', 0);

          transport.sendPacket(payload);
          final packet = socket.packets.last;
          transport.close();

          final aad = Uint8List.sublistView(packet, 0, 4);
          final rest = Uint8List.sublistView(packet, 4);

          final cipher = GCMBlockCipher(AESEngine());
          cipher.init(
            false,
            AEADParameters(KeyParameter(key), 128, iv, aad),
          );
          final plaintext = cipher.process(rest);
          final paddingLength = plaintext[0];
          expect(paddingLength, greaterThanOrEqualTo(4));

          return Uint8List.sublistView(
            plaintext,
            plaintext.length - paddingLength,
          );
        }

        final payload = Uint8List.fromList(List<int>.generate(10, (i) => i));
        final firstPadding = paddingOf(payload);
        final secondPadding = paddingOf(payload);

        expect(firstPadding, isNot(everyElement(0)));
        expect(firstPadding, isNot(equals(secondPadding)));
      }
    });
  });

  group('T-05/T-12: non-ETM and ETM round trips still deliver the payload', () {
    Future<void> roundTrip({
      required bool useEtm,
      int payloadLength = 37,
    }) async {
      final cipherType = SSHCipherType.aes128ctr;
      final macType = useEtm ? SSHMacType.hmacSha256Etm : SSHMacType.hmacSha256;
      final key = Uint8List.fromList(
        List<int>.generate(cipherType.keySize, (i) => i),
      );
      final iv = Uint8List.fromList(
        List<int>.generate(cipherType.ivSize, (i) => i + 9),
      );
      final macKey = Uint8List.fromList(
        List<int>.generate(macType.keySize, (i) => i + 3),
      );
      // First byte (message id) is 200, unused by the transport's own
      // dispatch table, so it always falls through to onMessage.
      final payload = Uint8List.fromList(
        [
          200,
          ...List<int>.generate(
            payloadLength - 1,
            (i) => (i * 5 + 1) & 0xff,
          ),
        ],
      );

      final senderSocket = _CaptureSSHSocket();
      final sender = SSHTransport(senderSocket);
      setPrivate(sender, '_clientMacType', macType);
      setPrivate(sender, '_localMacType', macType);
      setPrivate(
        sender,
        '_encryptCipher',
        cipherType.createCipher(key, iv, forEncryption: true),
      );
      setPrivate(sender, '_localMac', macType.createMac(macKey));
      setPrivate(sender, '_kexInProgress', false);
      setSequenceValue(sender, '_localPacketSN', 0);

      sender.sendPacket(payload);
      final encrypted = senderSocket.packets.last;

      final receiverSocket = _CaptureSSHSocket();
      final receivedPacket = Completer<Uint8List>();
      final receiver = SSHTransport(
        receiverSocket,
        onMessage: (packet) {
          if (!receivedPacket.isCompleted) receivedPacket.complete(packet);
          return true;
        },
      );
      setPrivate(receiver, '_remoteVersion', 'SSH-2.0-test');
      setPrivate(receiver, '_serverMacType', macType);
      setPrivate(receiver, '_remoteMacType', macType);
      setPrivate(
        receiver,
        '_decryptCipher',
        cipherType.createCipher(key, iv, forEncryption: false),
      );
      setPrivate(receiver, '_remoteMac', macType.createMac(macKey));
      setPrivate(receiver, '_kexInProgress', false);
      setSequenceValue(receiver, '_remotePacketSN', 0);

      receiverSocket.addIncomingBytes(encrypted);

      final received =
          await receivedPacket.future.timeout(const Duration(seconds: 2));
      expect(received, payload);

      sender.close();
      receiver.close();
    }

    test('non-ETM (encrypt-and-mac)', () async {
      await roundTrip(useEtm: false);
    });

    test('ETM (encrypt-then-mac)', () async {
      await roundTrip(useEtm: true);
    });

    test('a large non-ETM packet', () async {
      await roundTrip(useEtm: false, payloadLength: 32 * 1024);
    });
  });

  group(
      'T-09/T-11: malformed lengths raise SSHPacketError, not '
      'RangeError/SSHInternalError', () {
    test('_verifyPacketLength rejects lengths below the 5 byte minimum', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      for (final packetLength in [0, 1, 4]) {
        expect(
          () => reflect(transport)
              .invoke(privateSymbol('_verifyPacketLength'), [packetLength]),
          throwsA(isA<SSHPacketError>()),
          reason: 'packetLength=$packetLength should be rejected',
        );
      }

      transport.close();
    });

    test('_verifyPacketLength still accepts an in-range length', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      expect(
        () => reflect(transport)
            .invoke(privateSymbol('_verifyPacketLength'), [16]),
        returnsNormally,
      );

      transport.close();
    });

    test(
        'plaintext receive path raises SSHPacketError instead of a '
        'RangeError for a too-short packetLength', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      final dynamic buffer = getPrivate<dynamic>(transport, '_buffer');
      // packetLength = 1 leaves no room for the mandatory padding, which
      // used to let readPaddingLength/sublistView read past the packet.
      final packet = Uint8List(4 + 1);
      ByteData.sublistView(packet, 0, 4).setUint32(0, 1);
      packet[4] = 4;
      buffer.add(packet);

      expect(
        () => reflect(transport)
            .invoke(privateSymbol('_consumePacket'), const []),
        throwsA(isA<SSHPacketError>()),
      );

      transport.close();
    });

    test(
        'non-ETM receive rejects an unaligned encrypted packet before '
        'consuming its remaining ciphertext or MAC', () {
      final cipherType = SSHCipherType.aes128ctr;
      final macType = SSHMacType.hmacSha256;
      final key = Uint8List.fromList(
        List<int>.generate(cipherType.keySize, (i) => i),
      );
      final iv = Uint8List.fromList(
        List<int>.generate(cipherType.ivSize, (i) => i + 1),
      );
      final macKey = Uint8List.fromList(
        List<int>.generate(macType.keySize, (i) => i + 2),
      );

      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);
      setPrivate(transport, '_remoteCipherType', cipherType);
      setPrivate(transport, '_remoteMacType', macType);
      setPrivate(
        transport,
        '_decryptCipher',
        cipherType.createCipher(key, iv, forEncryption: false),
      );
      final remoteMac = macType.createMac(macKey);
      setPrivate(transport, '_remoteMac', remoteMac);

      // The first decrypted block claims packetLength=20. Including the
      // four-byte length field gives 24 encrypted bytes, which is not aligned
      // to AES's 16-byte block size.
      const packetLength = 20;
      final firstPlaintextBlock = Uint8List(cipherType.blockSize)
        ..buffer.asByteData().setUint32(0, packetLength);
      final firstCiphertextBlock = cipherType
          .createCipher(key, iv, forEncryption: true)
          .processAll(firstPlaintextBlock);
      final bytesAfterFirstBlock =
          4 + packetLength + remoteMac.macSize - cipherType.blockSize;
      final input = Uint8List.fromList([
        ...firstCiphertextBlock,
        ...Uint8List(bytesAfterFirstBlock),
      ]);

      final dynamic buffer = getPrivate<dynamic>(transport, '_buffer');
      buffer.add(input);

      expect(
        () => reflect(transport)
            .invoke(privateSymbol('_consumePacket'), const []),
        throwsA(
          isA<SSHPacketError>().having(
            (error) => error.toString(),
            'message',
            contains('not a multiple of block size'),
          ),
        ),
      );
      expect(
        buffer.length,
        bytesAfterFirstBlock,
        reason: 'only the first block needed to read packetLength is consumed',
      );

      transport.close();
    });

    test(
        'AEAD receive path rejects a padding length that would make the '
        'payload length negative (T-11)', () {
      for (final cipherType in [
        SSHCipherType.aes128gcm,
        SSHCipherType.aes256gcm,
      ]) {
        final key = Uint8List(cipherType.keySize);
        final iv = Uint8List(cipherType.ivSize);

        final socket = _CaptureSSHSocket();
        final transport = SSHTransport(socket);
        setPrivate(transport, '_remoteVersion', 'SSH-2.0-test');
        setPrivate(transport, '_serverCipherType', cipherType);
        setPrivate(transport, '_remoteCipherType', cipherType);
        setPrivate(transport, '_remoteCipherKey', key);
        setPrivate(transport, '_remoteIV', iv);
        setSequenceValue(transport, '_remotePacketSN', 0);

        // packetLength = 16, but the (encrypted) padding-length byte we put
        // in the plaintext is 255: payloadLength = 16 - 255 - 1 < 0.
        const packetLength = 16;
        final aad = Uint8List(4)
          ..buffer.asByteData().setUint32(0, packetLength);
        final plaintext = Uint8List(packetLength)..[0] = 255;

        final cipher = GCMBlockCipher(AESEngine());
        cipher.init(true, AEADParameters(KeyParameter(key), 128, iv, aad));
        final encrypted = cipher.process(plaintext);

        final dynamic buffer = getPrivate<dynamic>(transport, '_buffer');
        buffer.add(Uint8List.fromList([...aad, ...encrypted]));

        expect(
          () => reflect(transport)
              .invoke(privateSymbol('_consumeAeadPacket'), [cipherType]),
          throwsA(isA<SSHPacketError>()),
        );

        transport.close();
      }
    });
  });

  group('T-12: MAC is checked before padding on the non-ETM path', () {
    test(
        'a packet with both an invalid padding length and a wrong MAC '
        'fails with a MAC error, not a padding error', () {
      final cipherType = SSHCipherType.aes128ctr;
      final macType = SSHMacType.hmacSha256;
      final key = Uint8List.fromList(
        List<int>.generate(cipherType.keySize, (i) => i),
      );
      final iv = Uint8List.fromList(
        List<int>.generate(cipherType.ivSize, (i) => i + 1),
      );
      final macKey = Uint8List.fromList(
        List<int>.generate(macType.keySize, (i) => i + 2),
      );

      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);
      setPrivate(transport, '_remoteVersion', 'SSH-2.0-test');
      setPrivate(transport, '_serverCipherType', cipherType);
      setPrivate(transport, '_remoteCipherType', cipherType);
      setPrivate(transport, '_serverMacType', macType);
      setPrivate(transport, '_remoteMacType', macType);
      setPrivate(
        transport,
        '_decryptCipher',
        cipherType.createCipher(key, iv, forEncryption: false),
      );
      setPrivate(transport, '_remoteMac', macType.createMac(macKey));
      setSequenceValue(transport, '_remotePacketSN', 0);

      // One AES block (16 bytes): packetLength=12, padding length byte=1
      // (invalid: SSH requires padding length >= 4).
      final rawPacket = Uint8List(16);
      ByteData.sublistView(rawPacket, 0, 4).setUint32(0, 12);
      rawPacket[4] = 1;

      final encryptCipher =
          cipherType.createCipher(key, iv, forEncryption: true);
      final ciphertext = encryptCipher.processAll(rawPacket);

      // A MAC that does not match what would actually be computed.
      final wrongMac = Uint8List(macType.createMac(macKey).macSize)
        ..fillRange(0, macType.createMac(macKey).macSize, 0xFF);

      final dynamic buffer = getPrivate<dynamic>(transport, '_buffer');
      buffer.add(Uint8List.fromList([...ciphertext, ...wrongMac]));

      expect(
        () => reflect(transport)
            .invoke(privateSymbol('_consumePacket'), const []),
        throwsA(
          isA<SSHPacketError>().having(
            (error) => error.toString(),
            'message',
            allOf(contains('MAC mismatch'), isNot(contains('Padding'))),
          ),
        ),
      );

      transport.close();
    });
  });

  group('T-07: host key is re-verified on rekey', () {
    test('a rekey presenting a different host key fingerprint is rejected',
        () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(
        socket,
        disableHostkeyVerification: true,
      );

      setPrivate(transport, '_remoteVersion', 'SSH-2.0-test');
      setPrivate(
        transport,
        '_localKexInit',
        Uint8List.fromList([20, 1, 2, 3]),
      );
      setPrivate(
        transport,
        '_remoteKexInit',
        Uint8List.fromList([20, 4, 5, 6]),
      );
      setPrivate(transport, '_kexType', SSHKexType.x25519);
      setPrivate(transport, '_hostkeyType', SSHHostkeyType.ed25519);
      setPrivate(
        transport,
        '_clientCipherType',
        SSHCipherType.chacha20poly1305,
      );
      setPrivate(transport, '_kexInProgress', false);

      Uint8List buildReply(Uint8List hostKeyBytes) {
        // Simulates the fresh ephemeral key exchange a real rekey would
        // create.
        setPrivate(transport, '_kex', SSHKexX25519());
        return _encodeKexEcdhReply(
          hostPublicKey: hostKeyBytes,
          ecdhPublicKey: SSHKexX25519().publicKey,
          // Never checked: disableHostkeyVerification is true.
          signature: Uint8List(4),
        );
      }

      final firstHostKey = Uint8List.fromList(List<int>.filled(32, 1));
      await invokePrivate(
        transport,
        '_handleMessageKexReply',
        [buildReply(firstHostKey)],
      );

      expect(getPrivate<bool>(transport, '_hostkeyVerified'), isTrue);
      expect(
        getPrivate<Uint8List?>(transport, '_verifiedHostkeyFingerprint'),
        isNotNull,
      );
      expect(transport.isClosed, isFalse);

      // A rekey now arrives presenting a *different* host key. The ECDH kex
      // path never awaits before reaching closeWithError, so it completes
      // `transport.done` with an error synchronously within the
      // reflect().invoke() call below. The assertion on `done` therefore has
      // to be wired up first, or the error is reported as unhandled before
      // expectLater gets a chance to attach its listener.
      final secondHostKey = Uint8List.fromList(List<int>.filled(32, 2));
      final doneAssertion = expectLater(
        transport.done,
        throwsA(isA<SSHHostkeyError>()),
      );
      await invokePrivate(
        transport,
        '_handleMessageKexReply',
        [buildReply(secondHostKey)],
      );

      expect(transport.isClosed, isTrue);
      await doneAssertion;
    });

    test('a rekey presenting the same host key is accepted', () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(
        socket,
        disableHostkeyVerification: true,
      );

      setPrivate(transport, '_remoteVersion', 'SSH-2.0-test');
      setPrivate(
        transport,
        '_localKexInit',
        Uint8List.fromList([20, 1, 2, 3]),
      );
      setPrivate(
        transport,
        '_remoteKexInit',
        Uint8List.fromList([20, 4, 5, 6]),
      );
      setPrivate(transport, '_kexType', SSHKexType.x25519);
      setPrivate(transport, '_hostkeyType', SSHHostkeyType.ed25519);
      setPrivate(
        transport,
        '_clientCipherType',
        SSHCipherType.chacha20poly1305,
      );
      setPrivate(transport, '_kexInProgress', false);

      final hostKey = Uint8List.fromList(List<int>.filled(32, 7));

      Uint8List buildReply() {
        setPrivate(transport, '_kex', SSHKexX25519());
        return _encodeKexEcdhReply(
          hostPublicKey: hostKey,
          ecdhPublicKey: SSHKexX25519().publicKey,
          signature: Uint8List(4),
        );
      }

      await invokePrivate(
        transport,
        '_handleMessageKexReply',
        [buildReply()],
      );
      expect(transport.isClosed, isFalse);

      // Same host key presented again on rekey: must not be rejected.
      await invokePrivate(
        transport,
        '_handleMessageKexReply',
        [buildReply()],
      );

      expect(transport.isClosed, isFalse);

      transport.close();
    });
  });

  group('rekey() reports when the new keys are in effect', () {
    /// Puts [transport] in the state a rekey starts from: version strings
    /// exchanged, algorithms negotiated, first exchange already done.
    void primeForRekey(SSHTransport transport, _CaptureSSHSocket socket) {
      // The constructor already ran the opening handshake, KEXINIT included.
      // Drop what it wrote so the counts below only see the rekey.
      socket.packets.clear();

      setPrivate(transport, '_remoteVersion', 'SSH-2.0-test');
      setPrivate(
        transport,
        '_localKexInit',
        Uint8List.fromList([20, 1, 2, 3]),
      );
      setPrivate(
        transport,
        '_remoteKexInit',
        Uint8List.fromList([20, 4, 5, 6]),
      );
      setPrivate(transport, '_kexType', SSHKexType.x25519);
      setPrivate(transport, '_hostkeyType', SSHHostkeyType.ed25519);
      setPrivate(
        transport,
        '_clientCipherType',
        SSHCipherType.chacha20poly1305,
      );
      setPrivate(
        transport,
        '_serverCipherType',
        SSHCipherType.chacha20poly1305,
      );
      setPrivate(transport, '_kexInProgress', false);
      setPrivate(transport, '_sentKexInit', false);
    }

    /// Drives [transport] through the rest of an exchange the way the server
    /// would: a KEXDH reply carrying [hostKey], then NEWKEYS.
    Future<void> completeExchange(
      SSHTransport transport,
      Uint8List hostKey,
    ) async {
      setPrivate(transport, '_kex', SSHKexX25519());
      await invokePrivate(
        transport,
        '_handleMessageKexReply',
        [
          _encodeKexEcdhReply(
            hostPublicKey: hostKey,
            ecdhPublicKey: SSHKexX25519().publicKey,
            // Never checked: disableHostkeyVerification is true.
            signature: Uint8List(4),
          )
        ],
      );
      await invokePrivate(
        transport,
        '_handleMessageNewKeys',
        [
          Uint8List.fromList([SSH_Message_NewKeys.messageId])
        ],
      );
    }

    int countKexInits(_CaptureSSHSocket socket) {
      // Nothing is encrypted on this transport, so a written packet's first
      // payload byte is its message id: 5 bytes of length/padding header.
      return socket.packets
          .where((packet) =>
              packet.length > 5 && packet[5] == SSH_Message_KexInit.messageId)
          .length;
    }

    test('the future completes once NEWKEYS arrives, not before', () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket, disableHostkeyVerification: true);
      primeForRekey(transport, socket);

      var completed = false;
      final rekeyDone = transport.rekey().then((_) => completed = true);

      expect(countKexInits(socket), 1);

      // The exchange is in flight: nothing to report yet.
      await pumpEventQueue();
      expect(completed, isFalse);

      await completeExchange(
        transport,
        Uint8List.fromList(List<int>.filled(32, 7)),
      );

      await rekeyDone;
      expect(completed, isTrue);
      expect(getPrivate<bool>(transport, '_kexInProgress'), isFalse);

      await transport.close();
    });

    test('a second call joins the exchange in flight instead of starting one',
        () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket, disableHostkeyVerification: true);
      primeForRekey(transport, socket);

      final first = transport.rekey();
      final second = transport.rekey();

      // One exchange, two callers waiting on it.
      expect(countKexInits(socket), 1);

      await completeExchange(
        transport,
        Uint8List.fromList(List<int>.filled(32, 7)),
      );

      await Future.wait([first, second]);

      await transport.close();
    });

    test('the future fails with the error that ended the connection', () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket, disableHostkeyVerification: true);
      primeForRekey(transport, socket);

      final rekeyDone = transport.rekey();
      final doneAssertion = expectLater(
        transport.done,
        throwsA(isA<SSHSocketError>()),
      );

      transport.closeWithError(SSHSocketError('connection reset'));

      await expectLater(rekeyDone, throwsA(isA<SSHSocketError>()));
      await doneAssertion;
    });

    test('an orderly close fails a rekey that never saw its NEWKEYS', () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket, disableHostkeyVerification: true);
      primeForRekey(transport, socket);

      final rekeyDone = transport.rekey();
      await transport.close();

      await expectLater(rekeyDone, throwsA(isA<SSHStateError>()));
    });

    test('rekey() on a closed transport fails instead of hanging', () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket, disableHostkeyVerification: true);
      primeForRekey(transport, socket);

      await transport.close();

      await expectLater(transport.rekey(), throwsA(isA<SSHStateError>()));
    });

    test(
        'dropping the future of a live rekey does not raise an unhandled error',
        () async {
      final uncaught = <Object>[];
      final settled = Completer<void>();

      await runZonedGuarded(
        () async {
          final socket = _CaptureSSHSocket();
          final transport = SSHTransport(
            socket,
            disableHostkeyVerification: true,
          );
          primeForRekey(transport, socket);

          // A caller that fires a rekey and carries on. Only `done` is
          // watched, which is what callers did before rekey() returned a
          // future.
          transport.rekey();
          transport.done.catchError((_) {});

          transport.closeWithError(SSHSocketError('connection reset'));
          settled.complete();
        },
        (error, stackTrace) => uncaught.add(error),
      );

      await settled.future;
      // Give the zone a chance to report a dropped error before asserting.
      await pumpEventQueue();

      expect(uncaught, isEmpty);
    });

    test('dropping the future of a rekey on a closed transport stays silent',
        () async {
      // The other door into the same case: the early return for a closed
      // transport hands back its error future without going through the
      // completer, so it needs its own guard and its own test. The live-rekey
      // case above does not reach it, and the closed-transport case awaits,
      // so neither one would catch a regression here.
      final uncaught = <Object>[];
      final settled = Completer<void>();

      await runZonedGuarded(
        () async {
          final socket = _CaptureSSHSocket();
          final transport = SSHTransport(
            socket,
            disableHostkeyVerification: true,
          );
          primeForRekey(transport, socket);

          transport.done.catchError((_) {});
          await transport.close();

          // Dropped, the way the old `void` signature forced.
          transport.rekey();
          settled.complete();
        },
        (error, stackTrace) => uncaught.add(error),
      );

      await settled.future;
      await pumpEventQueue();

      expect(uncaught, isEmpty);
    });
  });
}

class _CaptureSSHSocket implements SSHSocket {
  final _inputController = StreamController<Uint8List>();
  final _doneCompleter = Completer<void>();
  final packets = <Uint8List>[];

  @override
  Stream<Uint8List> get stream => _inputController.stream;

  @override
  StreamSink<List<int>> get sink => _CaptureSink(packets);

  @override
  Future<void> get done => _doneCompleter.future;

  void addIncomingBytes(Uint8List data) {
    _inputController.add(Uint8List.fromList(data));
  }

  @override
  Future<void> close() async {
    if (!_doneCompleter.isCompleted) {
      _doneCompleter.complete();
    }
    await _inputController.close();
  }

  @override
  void destroy() {
    if (!_doneCompleter.isCompleted) {
      _doneCompleter.complete();
    }
    unawaited(_inputController.close());
  }

  @override
  Future<void> flush() async {}
}

class _CaptureSink implements StreamSink<List<int>> {
  _CaptureSink(this._packets);

  final List<Uint8List> _packets;

  @override
  void add(List<int> data) {
    _packets.add(Uint8List.fromList(data));
  }

  @override
  Future<void> addStream(Stream<List<int>> stream) async {
    await for (final chunk in stream) {
      add(chunk);
    }
  }

  @override
  void addError(Object error, [StackTrace? stackTrace]) {}

  @override
  Future<void> close() async {}

  @override
  Future<void> get done async {}
}
