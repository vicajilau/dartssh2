import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/ssh_client.dart';
import 'package:dartssh2/src/ssh_transport.dart';
import 'package:dartssh2/src/message/msg_channel.dart';
import 'package:dartssh2/src/ssh_channel.dart';
import 'package:dartssh2/src/ssh_channel_id.dart';
import 'package:test/test.dart';

void main() {
  group('SSHClient channel open state', () {
    late _FakeSSHSocket socket;
    late SSHClient client;

    setUp(() {
      socket = _FakeSSHSocket();
      client = SSHClient(
        socket,
        username: 'test',
        onX11Forward: (_) {},
      );
    });

    tearDown(() async {
      await client.close();
    });

    test('records the opening state before sending SSH_MSG_CHANNEL_OPEN',
        () async {
      _disableRekeyBuffer(client);
      var pendingAtSend = false;
      socket.onWrite = (_) {
        pendingAtSend = _pendingChannelOpens(client).contains(0);
      };

      final openFuture = _openSessionChannel(client);
      final expectation = expectLater(
        openFuture,
        throwsA(isA<SSHStateError>()),
      );
      socket.onWrite = null;

      expect(pendingAtSend, isTrue);
      expect(_pendingChannelOpens(client), contains(0));

      await client.close();
      await expectation;
    });

    test('registers a confirmed channel before dispatching following data',
        () async {
      final openFuture = _openSessionChannel(client);

      client.handlePacket(_confirmation(0).encode());
      expect(_openChannels(client), contains(0));
      expect(_pendingChannelOpens(client), isEmpty);

      client.handlePacket(
        SSH_Message_Channel_Data(
          recipientChannel: 0,
          data: Uint8List.fromList([1, 2, 3]),
        ).encode(),
      );

      final controller = await openFuture;
      expect(controller.remoteId, 42);
      expect(
        await controller.channel.stream.first,
        isA<SSHChannelData>().having(
          (data) => data.bytes,
          'bytes',
          orderedEquals([1, 2, 3]),
        ),
      );
    });

    test('registers an accepted inbound channel before sending confirmation',
        () {
      _disableRekeyBuffer(client);
      var openAtSend = false;
      socket.onWrite = (_) {
        openAtSend = _openChannels(client).containsKey(0);
      };

      client.handlePacket(
        SSH_Message_Channel_Open.x11(
          senderChannel: 42,
          initialWindowSize: 1024,
          maximumPacketSize: 1024,
          originatorIP: '127.0.0.1',
          originatorPort: 1234,
        ).encode(),
      );
      socket.onWrite = null;

      expect(openAtSend, isTrue);
      expect(_openChannels(client), contains(0));
    });

    test('completes a matching failure and releases its channel ID', () async {
      final openFuture = _openSessionChannel(client);
      final expectation = expectLater(
        openFuture,
        throwsA(
          isA<SSHChannelOpenError>()
              .having((error) => error.code, 'code', 2)
              .having((error) => error.description, 'description', 'denied'),
        ),
      );

      client.handlePacket(
        SSH_Message_Channel_Open_Failure(
          recipientChannel: 0,
          reasonCode: 2,
          description: 'denied',
        ).encode(),
      );

      await expectation;
      expect(_pendingChannelOpens(client), isEmpty);
      expect(_allocatedChannelIds(client), isEmpty);
    });

    test('rejects unsolicited channel open confirmations', () {
      expect(
        () => client.handlePacket(_confirmation(7).encode()),
        throwsA(isA<SSHStateError>()),
      );
      expect(_openChannels(client), isEmpty);
    });

    test('rejects unsolicited channel open failures', () {
      final failure = SSH_Message_Channel_Open_Failure(
        recipientChannel: 7,
        reasonCode: 2,
        description: 'denied',
      );

      expect(
        () => client.handlePacket(failure.encode()),
        throwsA(isA<SSHStateError>()),
      );
    });

    test('rejects duplicate channel open confirmations', () async {
      final openFuture = _openSessionChannel(client);
      final confirmation = _confirmation(0);

      client.handlePacket(confirmation.encode());
      await openFuture;

      expect(
        () => client.handlePacket(confirmation.encode()),
        throwsA(isA<SSHStateError>()),
      );
    });

    test('fails pending opens and releases their IDs when transport closes',
        () async {
      final openFuture = _openSessionChannel(client);
      final expectation = expectLater(
        openFuture,
        throwsA(isA<SSHStateError>()),
      );

      await client.close();
      await expectation;

      expect(_pendingChannelOpens(client), isEmpty);
      expect(_allocatedChannelIds(client), isEmpty);
    });

    test('a channel protocol violation does not take the connection down',
        () async {
      _disableRekeyBuffer(client);

      final first = _openSessionChannel(client);
      client.handlePacket(_confirmation(0).encode());
      final firstChannel = await first;

      final second = _openSessionChannel(client);
      client.handlePacket(_confirmation(1).encode());
      final secondChannel = await second;

      final failed = expectLater(
        firstChannel.channel.stream,
        emitsError(isA<SSHStateError>()),
      );

      // The peer overruns the maximum packet size the client advertised
      // (32768) on the first channel. That channel has to fail, but the
      // connection carries other channels and must survive.
      client.handlePacket(
        SSH_Message_Channel_Data(
          recipientChannel: 0,
          data: Uint8List(40000),
        ).encode(),
      );

      await failed;
      expect(client.isClosed, isFalse);

      // The surviving channel still delivers data.
      client.handlePacket(
        SSH_Message_Channel_Data(
          recipientChannel: 1,
          data: Uint8List.fromList([7, 8, 9]),
        ).encode(),
      );

      expect(
        await secondChannel.channel.stream.first,
        isA<SSHChannelData>().having(
          (data) => data.bytes,
          'bytes',
          orderedEquals([7, 8, 9]),
        ),
      );
    });
  });
}

SSH_Message_Channel_Confirmation _confirmation(int recipientChannel) {
  return SSH_Message_Channel_Confirmation(
    recipientChannel: recipientChannel,
    senderChannel: 42,
    initialWindowSize: 1024,
    maximumPacketSize: 1024,
    data: Uint8List(0),
  );
}

Future<SSHChannelController> _openSessionChannel(SSHClient client) =>
    clientTestHooks(client).openSessionChannel();

/// The channel IDs with an open still awaiting a confirmation or failure.
Iterable<SSHChannelId> _pendingChannelOpens(SSHClient client) =>
    clientTestHooks(client).pendingChannelOpens;

Map<SSHChannelId, SSHChannelController> _openChannels(SSHClient client) =>
    clientTestHooks(client).channels;

Set<SSHChannelId> _allocatedChannelIds(SSHClient client) =>
    clientTestHooks(client).channelIdAllocator.allocatedIds;

void _disableRekeyBuffer(SSHClient client) {
  transportTestHooks(clientTestHooks(client).transport).kexInProgress = false;
}

class _FakeSSHSocket implements SSHSocket {
  final _input = StreamController<Uint8List>();
  final _output = StreamController<List<int>>.broadcast(sync: true);

  void Function(List<int>)? onWrite;

  _FakeSSHSocket() {
    _output.stream.listen((data) => onWrite?.call(data));
  }

  @override
  Stream<Uint8List> get stream => _input.stream;

  @override
  StreamSink<List<int>> get sink => _output.sink;

  @override
  Future<void> get done => _input.done;

  @override
  Future<void> close() async {
    if (!_input.isClosed) await _input.close();
    if (!_output.isClosed) await _output.close();
  }

  @override
  Future<void> flush() async {}

  @override
  void destroy() {
    _input.close();
    _output.close();
  }
}
