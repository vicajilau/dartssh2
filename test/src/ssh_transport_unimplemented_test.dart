import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/ssh_transport.dart';
import 'package:dartssh2/src/message/msg_debug.dart';
import 'package:dartssh2/src/message/msg_disconnect.dart';
import 'package:dartssh2/src/message/msg_ignore.dart';
import 'package:dartssh2/src/message/msg_unimplemented.dart';
import 'package:dartssh2/src/ssh_packet.dart';
import 'package:test/test.dart';

void main() {
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
      transportTestHooks(transport).kexInProgress = false;
      transportTestHooks(transport).remotePacketSN.value = 37;

      await transportTestHooks(transport)
          .handleMessage(Uint8List.fromList([255]));

      expect(socket.packets, hasLength(1));
      expect(sentUnimplemented(socket.packets.single).sequenceNumber, 37);

      await transport.close();
    });

    test('surfaces the reason the peer gave for disconnecting', () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);
      transportTestHooks(transport).kexInProgress = false;

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

      await transportTestHooks(transport).handleMessage(SSH_Message_Disconnect(
        reasonCode: 2,
        description: 'no matching key exchange method found',
      ).encode());

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
      transportTestHooks(transport).kexInProgress = false;
      final channelData = Uint8List.fromList([94, 1, 2, 3]);

      await transportTestHooks(transport).handleMessage(channelData);

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
      transportTestHooks(transport).kexInProgress = false;
      final extensionMessage = Uint8List.fromList([200, 1, 2, 3]);

      await transportTestHooks(transport).handleMessage(extensionMessage);

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
      transportTestHooks(transport).kexInProgress = false;

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
        await transportTestHooks(transport).handleMessage(message);
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
      transportTestHooks(transport).kexInProgress = false;
      transportTestHooks(transport).remotePacketSN.value = 41;

      final buffer = transportTestHooks(transport).buffer;
      buffer.add(clearTextPacket(Uint8List.fromList([200])));
      buffer.add(clearTextPacket(Uint8List.fromList([201])));

      await transportTestHooks(transport).processPackets();

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
      transportTestHooks(transport).strictKex = true;
      transportTestHooks(transport).isFirstKex = true;
      transportTestHooks(transport).kexInProgress = true;

      await expectLater(
        transportTestHooks(transport).handleMessage(Uint8List.fromList([255])),
        throwsA(isA<SSHHandshakeError>()),
      );
      expect(socket.packets, isEmpty);

      await transport.close();
    });

    test('replies to an unknown message during a strict rekey', () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket, onMessage: (_) => false);
      socket.packets.clear();
      transportTestHooks(transport).strictKex = true;
      transportTestHooks(transport).isFirstKex = false;
      transportTestHooks(transport).kexInProgress = true;
      transportTestHooks(transport).remotePacketSN.value = 9;

      await transportTestHooks(transport)
          .handleMessage(Uint8List.fromList([255]));

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
