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
import 'package:dartssh2/src/message/msg_disconnect.dart';
import 'package:dartssh2/src/message/msg_ignore.dart';
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

  void setSequenceValue(SSHTransport transport, int value) {
    final sequence =
        reflect(transport).getField(privateSymbol('_remotePacketSN')).reflectee;
    reflect(sequence).setField(packetPrivateSymbol('_value'), value);
  }

  Future<void> invokeHandleMessage(
    SSHTransport transport,
    Uint8List message,
  ) async {
    final result = reflect(transport).invoke(
      privateSymbol('_handleMessage'),
      [message],
    );
    final value = result.reflectee;
    if (value is Future) await value;
  }

  Future<void> invokeProcessPackets(SSHTransport transport) async {
    final result = reflect(transport).invoke(
      privateSymbol('_processPackets'),
      const [],
    );
    final value = result.reflectee;
    if (value is Future) await value;
  }

  dynamic packetBuffer(SSHTransport transport) {
    return reflect(transport).getField(privateSymbol('_buffer')).reflectee;
  }

  Uint8List clearTextPacket(Uint8List payload) {
    return SSHPacket.pack(payload, align: SSHPacket.minAlign);
  }

  Uint8List packetPayload(Uint8List packet) {
    final paddingLength = SSHPacket.readPaddingLength(packet);
    return Uint8List.sublistView(
      packet,
      SSHPacket.headerLength,
      packet.length - paddingLength,
    );
  }

  SSH_Message_Unimplemented sentUnimplemented(Uint8List packet) {
    return SSH_Message_Unimplemented.decode(packetPayload(packet));
  }

  group('SSH_MSG_UNIMPLEMENTED encoding', () {
    test('round-trips the rejected packet sequence number', () {
      final message = SSH_Message_Unimplemented(0xffffffff);

      final decoded = SSH_Message_Unimplemented.decode(message.encode());

      expect(decoded.sequenceNumber, 0xffffffff);
      expect(decoded.toString(), contains('4294967295'));
    });
  });

  group('SSH_MSG_UNIMPLEMENTED dispatch', () {
    test('replies to an unrecognized message with its receive sequence',
        () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(
        socket,
        onMessage: (_) => false,
      );
      socket.packets.clear();
      setPrivate(transport, '_kexInProgress', false);
      setSequenceValue(transport, 37);

      await invokeHandleMessage(transport, Uint8List.fromList([255]));

      expect(socket.packets, hasLength(1));
      expect(sentUnimplemented(socket.packets.single).sequenceNumber, 37);

      await transport.close();
    });

    test('surfaces the reason the peer gave for disconnecting', () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);
      setPrivate(transport, '_kexInProgress', false);

      final expectation = expectLater(
        transport.done,
        throwsA(
          isA<SSHDisconnectError>()
              .having((e) => e.reasonCode, 'reasonCode', 2)
              .having(
                (e) => e.message,
                'message',
                'no matching key exchange method found',
              ),
        ),
      );

      await invokeHandleMessage(
        transport,
        SSH_Message_Disconnect(
          reasonCode: 2,
          description: 'no matching key exchange method found',
        ).encode(),
      );

      await expectation;
    });

    test('does not reply when the upper layer handles the message', () async {
      final socket = _CaptureSSHSocket();
      final received = <Uint8List>[];
      final transport = SSHTransport(
        socket,
        onMessage: (message) {
          received.add(message);
          return true;
        },
      );
      socket.packets.clear();
      setPrivate(transport, '_kexInProgress', false);
      final channelData = Uint8List.fromList([94, 1, 2, 3]);

      await invokeHandleMessage(transport, channelData);

      expect(received, [channelData]);
      expect(socket.packets, isEmpty);

      await transport.close();
    });

    test('keeps the legacy packet callback behavior', () async {
      final socket = _CaptureSSHSocket();
      final received = <Uint8List>[];
      final transport = SSHTransport(socket, onMessage: (packet) {
        received.add(packet);
        return true;
      });
      socket.packets.clear();
      setPrivate(transport, '_kexInProgress', false);
      final extensionMessage = Uint8List.fromList([200, 1, 2, 3]);

      await invokeHandleMessage(transport, extensionMessage);

      expect(received, [extensionMessage]);
      expect(socket.packets, isEmpty);

      await transport.close();
    });

    test('does not reply to recognized generic transport messages', () async {
      final socket = _CaptureSSHSocket();
      var upperLayerCalls = 0;
      final transport = SSHTransport(
        socket,
        onMessage: (_) {
          upperLayerCalls++;
          return false;
        },
      );
      socket.packets.clear();
      setPrivate(transport, '_kexInProgress', false);

      final messages = [
        SSH_Message_Ignore.empty().encode(),
        SSH_Message_Debug(
          alwaysDisplay: false,
          message: Uint8List.fromList('diagnostic'.codeUnits),
          language: Uint8List(0),
        ).encode(),
        SSH_Message_Unimplemented(12).encode(),
      ];
      for (final message in messages) {
        await invokeHandleMessage(transport, message);
      }

      expect(upperLayerCalls, 0);
      expect(socket.packets, isEmpty);

      await transport.close();
    });

    test('uses the original sequence number for consecutive packets', () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(
        socket,
        onMessage: (_) => false,
      );
      socket.packets.clear();
      setPrivate(transport, '_kexInProgress', false);
      setSequenceValue(transport, 41);

      final buffer = packetBuffer(transport);
      buffer.add(clearTextPacket(Uint8List.fromList([200])));
      buffer.add(clearTextPacket(Uint8List.fromList([201])));

      await invokeProcessPackets(transport);

      expect(socket.packets, hasLength(2));
      expect(
        socket.packets
            .map(sentUnimplemented)
            .map((message) => message.sequenceNumber),
        [41, 42],
      );

      await transport.close();
    });

    test('rejects an unknown message during the initial strict key exchange',
        () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket, onMessage: (_) => false);
      socket.packets.clear();
      setPrivate(transport, '_strictKex', true);
      setPrivate(transport, '_isFirstKex', true);
      setPrivate(transport, '_kexInProgress', true);

      await expectLater(
        invokeHandleMessage(transport, Uint8List.fromList([255])),
        throwsA(isA<SSHHandshakeError>()),
      );
      expect(socket.packets, isEmpty);

      await transport.close();
    });

    test('replies to an unknown message during a strict rekey', () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket, onMessage: (_) => false);
      socket.packets.clear();
      setPrivate(transport, '_strictKex', true);
      setPrivate(transport, '_isFirstKex', false);
      setPrivate(transport, '_kexInProgress', true);
      setSequenceValue(transport, 9);

      await invokeHandleMessage(transport, Uint8List.fromList([255]));

      expect(socket.packets, hasLength(1));
      expect(sentUnimplemented(socket.packets.single).sequenceNumber, 9);

      await transport.close();
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
