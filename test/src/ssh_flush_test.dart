@TestOn('vm')
library;

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/ssh_channel.dart';
import 'package:test/test.dart';

void main() {
  group('SSHSocket base class', () {
    test('default flush implementation completes normally', () async {
      final socket = _TestSSHSocket();
      await expectLater(socket.flush(), completes);
    });
  });

  group('SSHNativeSocket', () {
    test('native socket flush works', () async {
      final server = await ServerSocket.bind('127.0.0.1', 0);
      final socket = await SSHSocket.connect('127.0.0.1', server.port);
      await socket.flush();
      await socket.close();
      await server.close();
    });
  });

  group('SSHTransport.flush', () {
    test('delegates to socket.flush', () async {
      final socket = _FakeSSHSocket();
      final transport = SSHTransport(socket);
      await transport.flush();
      expect(socket.flushCount, 1);
      transport.close();
    });
  });

  group('SSHClient.flush and channel callback delegation', () {
    test('delegates to transport and sets up onFlush', () async {
      final socket = _FakeSSHSocket();
      final client = SSHClient(socket, username: 'demo');
      await client.flush();
      expect(socket.flushCount, 1);

      final channelController = client.testHooks.acceptChannel(
        localChannelId: 1,
        remoteChannelId: 2,
        remoteInitialWindowSize: 1024,
        remoteMaximumPacketSize: 1024,
      );

      expect(channelController.onFlush, isNotNull);
      await channelController.flush();
      expect(socket.flushCount, 2);

      client.close();
    });
  });

  group('SSHChannel.flush', () {
    test('delegates to controller.flush', () async {
      var flushed = false;
      final controller = SSHChannelController(
        localId: 1,
        localMaximumPacketSize: 1024,
        localInitialWindowSize: 1024,
        remoteId: 2,
        remoteMaximumPacketSize: 1024,
        remoteInitialWindowSize: 1024,
        sendMessage: (msg) {},
        onFlush: () async {
          flushed = true;
        },
      );
      final channel = controller.channel;
      await channel.flush();
      expect(flushed, isTrue);
    });
  });

  group('SSHSession.flush', () {
    test('exposes channel and delegates flush', () async {
      var flushed = false;
      final controller = SSHChannelController(
        localId: 1,
        localMaximumPacketSize: 1024,
        localInitialWindowSize: 1024,
        remoteId: 2,
        remoteMaximumPacketSize: 1024,
        remoteInitialWindowSize: 1024,
        sendMessage: (msg) {},
        onFlush: () async {
          flushed = true;
        },
      );
      final channel = controller.channel;
      final session = SSHSession(channel);
      expect(session.channel, channel);

      await session.flush();
      expect(flushed, isTrue);
    });
  });

  group('SSHForwardChannel.flush', () {
    test('delegates to channel.flush', () async {
      var flushed = false;
      final controller = SSHChannelController(
        localId: 1,
        localMaximumPacketSize: 1024,
        localInitialWindowSize: 1024,
        remoteId: 2,
        remoteMaximumPacketSize: 1024,
        remoteInitialWindowSize: 1024,
        sendMessage: (msg) {},
        onFlush: () async {
          flushed = true;
        },
      );
      final forwardChannel = SSHForwardChannel(controller.channel);
      await forwardChannel.flush();
      expect(flushed, isTrue);
    });
  });
}

class _TestSSHSocket extends SSHSocket {
  @override
  Stream<Uint8List> get stream => throw UnimplementedError();

  @override
  StreamSink<List<int>> get sink => throw UnimplementedError();

  @override
  Future<void> get done => throw UnimplementedError();

  @override
  Future<void> close() => throw UnimplementedError();

  @override
  void destroy() => throw UnimplementedError();
}

class _FakeSSHSocket implements SSHSocket {
  int flushCount = 0;
  final _streamController = StreamController<Uint8List>();
  final _sinkController = StreamController<List<int>>();

  @override
  Stream<Uint8List> get stream => _streamController.stream;

  @override
  StreamSink<List<int>> get sink => _sinkController.sink;

  @override
  Future<void> get done => _streamController.done;

  @override
  Future<void> close() async {
    await _streamController.close();
    await _sinkController.close();
  }

  @override
  void destroy() {}

  @override
  Future<void> flush() async {
    flushCount++;
  }
}
