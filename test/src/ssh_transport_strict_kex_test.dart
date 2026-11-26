// Uses dart:mirrors, which is VM-only.
@TestOn('vm')
library;

import 'dart:async';
// Deprecated in Dart 3.14, still needed here to reach private state.
// ignore: deprecated_member_use
import 'dart:mirrors';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/message/msg_debug.dart';
import 'package:dartssh2/src/message/msg_ext_info.dart';
import 'package:dartssh2/src/message/msg_ignore.dart';
import 'package:dartssh2/src/message/msg_kex.dart';
import 'package:dartssh2/src/message/msg_unimplemented.dart';
import 'package:dartssh2/src/ssh_packet.dart';
import 'package:test/test.dart';

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

  int sequenceValue(SSHTransport transport, String field) {
    final sequence =
        reflect(transport).getField(privateSymbol(field)).reflectee;
    return reflect(sequence).getField(packetPrivateSymbol('_value')).reflectee
        as int;
  }

  void setSequenceValue(SSHTransport transport, String field, int value) {
    final sequence =
        reflect(transport).getField(privateSymbol(field)).reflectee;
    reflect(sequence).setField(packetPrivateSymbol('_value'), value);
  }

  Future<void> invokePrivate(
    SSHTransport transport,
    String method,
    List<Object?> args,
  ) async {
    final result = reflect(transport).invoke(privateSymbol(method), args);
    final value = result.reflectee;
    if (value is Future) await value;
  }

  /// Decodes the KEXINIT that the transport wrote to [socket] during the
  /// handshake, stripping the RFC 4253 packet framing.
  SSH_Message_KexInit sentKexInit(_CaptureSSHSocket socket) {
    // The first write is the version banner, the second one is the KEXINIT.
    final packet = socket.packets[1];
    final paddingLength = SSHPacket.readPaddingLength(packet);
    final payload = Uint8List.sublistView(
      packet,
      SSHPacket.headerLength,
      packet.length - paddingLength,
    );
    return SSH_Message_KexInit.decode(payload);
  }

  /// Builds an unencrypted packet carrying [payload], as it would arrive on
  /// the wire before NEWKEYS.
  Uint8List clearTextPacket(Uint8List payload) {
    return SSHPacket.pack(payload, align: SSHPacket.minAlign);
  }

  SSH_Message_KexInit serverKexInit(
      {List<String> extraKexAlgorithms = const []}) {
    return SSH_Message_KexInit(
      kexAlgorithms: [SSHKexType.x25519.name, ...extraKexAlgorithms],
      serverHostKeyAlgorithms: [SSHHostkeyType.ed25519.name],
      encryptionClientToServer: [SSHCipherType.aes128ctr.name],
      encryptionServerToClient: [SSHCipherType.aes128ctr.name],
      macClientToServer: [SSHMacType.hmacSha256.name],
      macServerToClient: [SSHMacType.hmacSha256.name],
      compressionClientToServer: const ['none'],
      compressionServerToClient: const ['none'],
      firstKexPacketFollows: false,
    );
  }

  group('Strict key exchange advertisement', () {
    test('client advertises strict kex and ext-info in the first KEXINIT', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      final message = sentKexInit(socket);
      expect(message.kexAlgorithms, contains('kex-strict-c-v00@openssh.com'));
      expect(message.kexAlgorithms, contains('ext-info-c'));

      // The indicators must not displace the real algorithms.
      expect(message.kexAlgorithms.first, SSHKexType.x25519Rfc.name);

      transport.close();
    });

    test('server advertises the server-side indicators', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket, isServer: true);

      // A server only sends its KEXINIT after seeing the peer version, so
      // trigger it explicitly.
      reflect(transport).invoke(privateSymbol('_sendKexInit'), const []);

      final packet = socket.packets[1];
      final paddingLength = SSHPacket.readPaddingLength(packet);
      final message = SSH_Message_KexInit.decode(
        Uint8List.sublistView(
          packet,
          SSHPacket.headerLength,
          packet.length - paddingLength,
        ),
      );

      expect(message.kexAlgorithms, contains('kex-strict-s-v00@openssh.com'));
      expect(message.kexAlgorithms, contains('ext-info-s'));

      transport.close();
    });

    test('indicators are not repeated on a re-key', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      // Simulate the initial exchange having finished, so the next
      // _sendKexInit is a re-key rather than a no-op.
      setPrivate(transport, '_isFirstKex', false);
      setPrivate(transport, '_kexInProgress', false);
      setPrivate(transport, '_sentKexInit', false);
      socket.packets.clear();

      reflect(transport).invoke(privateSymbol('_sendKexInit'), const []);

      final packet = socket.packets.last;
      final paddingLength = SSHPacket.readPaddingLength(packet);
      final message = SSH_Message_KexInit.decode(
        Uint8List.sublistView(
          packet,
          SSHPacket.headerLength,
          packet.length - paddingLength,
        ),
      );

      expect(
        message.kexAlgorithms,
        isNot(contains('kex-strict-c-v00@openssh.com')),
      );
      expect(message.kexAlgorithms, isNot(contains('ext-info-c')));

      transport.close();
    });
  });

  group('Strict key exchange negotiation', () {
    test('enabled when the server advertises it', () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      setPrivate(transport, '_kexInProgress', true);
      setPrivate(transport, '_sentKexInit', true);

      await invokePrivate(transport, '_handleMessageKexInit', [
        serverKexInit(
          extraKexAlgorithms: const ['kex-strict-s-v00@openssh.com'],
        ).encode(),
      ]);

      expect(transport.strictKex, isTrue);

      transport.close();
    });

    test('stays disabled when the server does not advertise it', () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      setPrivate(transport, '_kexInProgress', true);
      setPrivate(transport, '_sentKexInit', true);

      await invokePrivate(
        transport,
        '_handleMessageKexInit',
        [serverKexInit().encode()],
      );

      expect(transport.strictKex, isFalse);

      transport.close();
    });

    test('the client-side indicator does not enable it on a client', () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      setPrivate(transport, '_kexInProgress', true);
      setPrivate(transport, '_sentKexInit', true);

      // A client must only accept the server indicator. Echoing back the
      // client one must not turn the mode on.
      await invokePrivate(transport, '_handleMessageKexInit', [
        serverKexInit(
          extraKexAlgorithms: const ['kex-strict-c-v00@openssh.com'],
        ).encode(),
      ]);

      expect(transport.strictKex, isFalse);

      transport.close();
    });

    test('rejects a first KEXINIT that is not the first packet', () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      setPrivate(transport, '_kexInProgress', true);
      setPrivate(transport, '_sentKexInit', true);
      // Something was received before the KEXINIT, which is exactly the
      // packet-insertion Terrapin relies on.
      setSequenceValue(transport, '_remotePacketSN', 1);

      await expectLater(
        invokePrivate(transport, '_handleMessageKexInit', [
          serverKexInit(
            extraKexAlgorithms: const ['kex-strict-s-v00@openssh.com'],
          ).encode(),
        ]),
        throwsA(isA<SSHHandshakeError>()),
      );

      transport.close();
    });
  });

  group('Strict key exchange message filtering', () {
    for (final entry in <String, Uint8List>{
      'SSH_MSG_IGNORE': SSH_Message_Ignore.empty().encode(),
      'SSH_MSG_UNIMPLEMENTED': SSH_Message_Unimplemented(0).encode(),
      'SSH_MSG_DEBUG': SSH_Message_Debug(
        alwaysDisplay: false,
        message: Uint8List(0),
        language: Uint8List(0),
      ).encode(),
    }.entries) {
      test('rejects ${entry.key} during key exchange', () async {
        final socket = _CaptureSSHSocket();
        final transport = SSHTransport(socket);

        setPrivate(transport, '_strictKex', true);
        setPrivate(transport, '_kexInProgress', true);

        await expectLater(
          invokePrivate(transport, '_handleMessage', [
            entry.value,
          ]),
          throwsA(isA<SSHHandshakeError>()),
        );

        transport.close();
      });

      test('allows ${entry.key} outside of key exchange', () async {
        final socket = _CaptureSSHSocket();
        final transport = SSHTransport(socket);

        setPrivate(transport, '_strictKex', true);
        setPrivate(transport, '_kexInProgress', false);

        await invokePrivate(transport, '_handleMessage', [
          entry.value,
        ]);

        transport.close();
      });

      test('allows ${entry.key} when strict kex is off', () async {
        final socket = _CaptureSSHSocket();
        final transport = SSHTransport(socket);

        setPrivate(transport, '_strictKex', false);
        setPrivate(transport, '_kexInProgress', true);

        await invokePrivate(transport, '_handleMessage', [
          entry.value,
        ]);

        transport.close();
      });
    }
  });

  group('Strict key exchange sequence numbers', () {
    /// Prepares the state [_applyRemoteKeys] needs so a NEWKEYS can be handled.
    void prepareKeys(SSHTransport transport) {
      setPrivate(transport, '_kexType', SSHKexType.x25519);
      setPrivate(transport, '_sharedSecret', BigInt.from(42));
      setPrivate(transport, '_exchangeHash',
          Uint8List.fromList(List<int>.filled(32, 1)));
      setPrivate(
          transport, '_sessionId', Uint8List.fromList(List<int>.filled(32, 2)));
      setPrivate(transport, '_clientCipherType', SSHCipherType.aes128ctr);
      setPrivate(transport, '_serverCipherType', SSHCipherType.aes128ctr);
      setPrivate(transport, '_clientMacType', SSHMacType.hmacSha256);
      setPrivate(transport, '_serverMacType', SSHMacType.hmacSha256);
    }

    test('local sequence number resets after sending NEWKEYS', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      setPrivate(transport, '_strictKex', true);
      setSequenceValue(transport, '_localPacketSN', 7);

      reflect(transport).invoke(privateSymbol('_sendNewKeys'), const []);

      expect(sequenceValue(transport, '_localPacketSN'), 0);

      transport.close();
    });

    test('local sequence number keeps counting without strict kex', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      setPrivate(transport, '_strictKex', false);
      setSequenceValue(transport, '_localPacketSN', 7);

      reflect(transport).invoke(privateSymbol('_sendNewKeys'), const []);

      expect(sequenceValue(transport, '_localPacketSN'), 8);

      transport.close();
    });

    test('remote sequence number resets after receiving NEWKEYS', () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      prepareKeys(transport);
      setPrivate(transport, '_strictKex', true);
      setPrivate(transport, '_remoteVersion', 'SSH-2.0-test');
      setSequenceValue(transport, '_remotePacketSN', 9);

      final dynamic buffer = getPrivate<dynamic>(transport, '_buffer');
      buffer.add(clearTextPacket(SSH_Message_NewKeys().encode()));

      await invokePrivate(transport, '_processPackets', const []);

      expect(sequenceValue(transport, '_remotePacketSN'), 0);

      transport.close();
    });

    test('remote sequence number keeps counting without strict kex', () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      prepareKeys(transport);
      setPrivate(transport, '_strictKex', false);
      setPrivate(transport, '_remoteVersion', 'SSH-2.0-test');
      setSequenceValue(transport, '_remotePacketSN', 9);

      final dynamic buffer = getPrivate<dynamic>(transport, '_buffer');
      buffer.add(clearTextPacket(SSH_Message_NewKeys().encode()));

      await invokePrivate(transport, '_processPackets', const []);

      expect(sequenceValue(transport, '_remotePacketSN'), 10);

      transport.close();
    });

    test('the reset applies once, not to every later packet', () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      prepareKeys(transport);
      setPrivate(transport, '_strictKex', true);
      setPrivate(transport, '_remoteVersion', 'SSH-2.0-test');
      setSequenceValue(transport, '_remotePacketSN', 9);

      // NEWKEYS resets to 0, then two ordinary packets take it to 2. They are
      // read as clear text because the remote keys are only applied to the
      // cipher once a non-null key is set, which this fixture does not do.
      final dynamic buffer = getPrivate<dynamic>(transport, '_buffer');
      buffer.add(clearTextPacket(SSH_Message_NewKeys().encode()));

      await invokePrivate(transport, '_processPackets', const []);
      expect(sequenceValue(transport, '_remotePacketSN'), 0);

      setPrivate(transport, '_remoteCipherKey', null);
      setPrivate(transport, '_decryptCipher', null);

      buffer.add(clearTextPacket(Uint8List.fromList([94, 1, 2])));
      buffer.add(clearTextPacket(Uint8List.fromList([94, 3, 4])));

      await invokePrivate(transport, '_processPackets', const []);
      expect(sequenceValue(transport, '_remotePacketSN'), 2);

      transport.close();
    });
  });

  group('EXT_INFO', () {
    test('records server-sig-algs sent by the server', () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      final message = SSH_Message_ExtInfo({
        'server-sig-algs': Uint8List.fromList(
          'rsa-sha2-512,rsa-sha2-256,ssh-ed25519'.codeUnits,
        ),
      });

      await invokePrivate(
        transport,
        '_handleMessageExtInfo',
        [message.encode()],
      );

      expect(
        transport.serverSigAlgs,
        ['rsa-sha2-512', 'rsa-sha2-256', 'ssh-ed25519'],
      );
      expect(transport.extInfo, isNotNull);
      expect(transport.extInfo!.keys, contains('server-sig-algs'));

      transport.close();
    });

    test('serverSigAlgs is null when the extension is absent', () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      final message = SSH_Message_ExtInfo({
        'delay-compression': Uint8List.fromList([1, 2, 3]),
      });

      await invokePrivate(
        transport,
        '_handleMessageExtInfo',
        [message.encode()],
      );

      expect(transport.serverSigAlgs, isNull);
      expect(transport.extInfo!.keys, contains('delay-compression'));

      transport.close();
    });

    test('round-trips through encode and decode', () {
      final original = SSH_Message_ExtInfo({
        'server-sig-algs': Uint8List.fromList('rsa-sha2-256'.codeUnits),
        'delay-compression': Uint8List.fromList([9, 9]),
      });

      final decoded = SSH_Message_ExtInfo.decode(original.encode());

      expect(decoded.extensions, hasLength(2));
      expect(decoded.serverSigAlgs, ['rsa-sha2-256']);
      expect(decoded.extensions['delay-compression'], [9, 9]);
      expect(decoded.toString(), contains('server-sig-algs'));
    });

    test('ignores a truncated extension list instead of throwing', () {
      // A count of 5 with a single extension present must not blow up.
      final writer = _extInfoWithCount(5, {
        'server-sig-algs': 'ssh-ed25519',
      });

      final decoded = SSH_Message_ExtInfo.decode(writer);

      expect(decoded.serverSigAlgs, ['ssh-ed25519']);
    });

    test('an empty server-sig-algs value decodes to an empty list', () {
      final message = SSH_Message_ExtInfo({
        'server-sig-algs': Uint8List(0),
      });

      final decoded = SSH_Message_ExtInfo.decode(message.encode());

      expect(decoded.serverSigAlgs, isEmpty);
    });
  });
}

/// Builds an SSH_MSG_EXT_INFO body whose declared extension count does not
/// match the number of extensions actually written.
Uint8List _extInfoWithCount(int count, Map<String, String> extensions) {
  final builder = BytesBuilder();
  builder.addByte(SSH_Message_ExtInfo.messageId);
  builder.add(_uint32(count));
  for (final entry in extensions.entries) {
    builder.add(_uint32(entry.key.length));
    builder.add(entry.key.codeUnits);
    builder.add(_uint32(entry.value.length));
    builder.add(entry.value.codeUnits);
  }
  return builder.takeBytes();
}

List<int> _uint32(int value) {
  final data = ByteData(4);
  data.setUint32(0, value);
  return data.buffer.asUint8List();
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
