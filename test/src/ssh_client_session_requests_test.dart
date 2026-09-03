// Uses dart:mirrors to read the channel's private reply queue, which is
// VM-only.
@TestOn('vm')
library;

import 'dart:async';
import 'dart:mirrors';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/message/msg_channel.dart';
import 'package:dartssh2/src/ssh_channel.dart';
import 'package:dartssh2/src/ssh_message.dart';
import 'package:dartssh2/src/ssh_packet.dart';
import 'package:dartssh2/src/utils/async_queue.dart';
import 'package:test/test.dart';

void main() {
  group('SSHClient session requests', () {
    late _FakeSSHSocket socket;
    late List<String?> debug;

    setUp(() {
      socket = _FakeSSHSocket();
      debug = <String>[];
    });

    SSHClient newClient({
      required bool pipeline,
      SSHAgentHandler? agentHandler,
    }) {
      final client = SSHClient(
        socket,
        username: 'test',
        printDebug: debug.add,
        pipelineChannelRequests: pipeline,
        agentHandler: agentHandler,
        keepAliveInterval: null,
      );
      _authenticate(client);
      _disableRekeyBuffer(client);
      return client;
    }

    test('by default each request waits for its reply before the next is sent',
        () async {
      final client = newClient(pipeline: false);
      final session = client.execute(
        'true',
        pty: const SSHPtyConfig(),
        environment: {'FOO': '1'},
      );

      await _openChannel(client, socket);

      // One request on the wire and one slot taken: this is the round trip
      // per request that the flag exists to remove.
      expect(socket.channelRequests.map((r) => r.requestType), ['env']);
      expect(_replyQueue(client).length, 1);

      client.handlePacket(_success().encode());
      await pumpEventQueue();

      expect(socket.channelRequests.map((r) => r.requestType), [
        'env',
        'pty-req',
      ]);
      expect(_replyQueue(client).length, 1);

      client.handlePacket(_success().encode());
      client.handlePacket(_success().encode());
      await session;

      expect(socket.channelRequests.map((r) => r.requestType), [
        'env',
        'pty-req',
        'exec',
      ]);
      await client.close();
    });

    test(
        'by default a refused environment variable is reported before the '
        'map is read any further', () async {
      final client = newClient(pipeline: false);
      final session = client.execute('true', environment: _EnvThatThrows());

      await _openChannel(client, socket);

      // Only FOO has been taken from the map, and its reply is outstanding.
      expect(socket.channelRequests.map((r) => r.variableName), ['FOO']);

      client.handlePacket(_failure().encode());

      // The refusal ends the call. Reading the map up front would have hit
      // its second entry before anything reached the wire and reported the
      // map's own error with no request sent at all.
      await expectLater(
        session,
        _throwsRequestError('Failed to set environment variable: FOO'),
      );
      expect(socket.channelRequests, hasLength(1));
      await client.close();
    });

    test(
        'by default a map that throws part way through has already sent the '
        'entries before it', () async {
      final client = newClient(pipeline: false);
      final session = client.execute('true', environment: _EnvThatThrows());

      await _openChannel(client, socket);

      expect(socket.channelRequests.map((r) => r.variableName), ['FOO']);

      client.handlePacket(_success().encode());

      await expectLater(session, throwsA(isA<_EnvIterationError>()));
      expect(socket.channelRequests, hasLength(1));
      await client.close();
    });

    test(
        'every request that wants a reply takes exactly one queue slot, '
        'in issue order', () async {
      final client = newClient(pipeline: true, agentHandler: _StubAgent());
      final issued = <(String, int)>[];

      final session = client.execute(
        'true',
        pty: const SSHPtyConfig(),
        x11: const SSHX11Config(authenticationCookie: 'cookie'),
        environment: {'FOO': '1', 'BAR': '2'},
      );

      // _sendRequest reserves the request's slot before it transmits, so the
      // depth seen as the nth request reaches the wire is exactly n. #148 was
      // a request that wanted a reply without reserving a slot at all, which
      // leaves the depth one short here and shifts every reply after it onto
      // the wrong request; a double reservation makes the depth jump instead.
      // Neither is visible from the end state alone, so record it per send.
      socket.onChannelRequest = (request) {
        issued.add((request.requestType, _replyQueue(client).length));
      };

      await _openChannel(client, socket);

      expect(issued, [
        (SSHChannelRequestType.env, 1),
        (SSHChannelRequestType.env, 2),
        (SSHChannelRequestType.authAgent, 3),
        (SSHChannelRequestType.pty, 4),
        (SSHChannelRequestType.x11, 5),
        (SSHChannelRequestType.exec, 6),
      ]);
      expect(socket.channelRequests.every((r) => r.wantReply), isTrue);
      expect(
        socket.channelRequests.map((r) => r.variableName).take(2),
        ['FOO', 'BAR'],
      );

      // Answer with a pattern no two requests share, so a pair of replies
      // swapped with each other changes which descriptions come back.
      const accepted = [true, false, false, true, false, true];
      for (var i = 0; i < accepted.length; i++) {
        client.handlePacket((accepted[i] ? _success() : _failure()).encode());
        await pumpEventQueue();
        expect(
          _replyQueue(client).length,
          accepted.length - i - 1,
          reason: 'one slot released per reply, after reply ${i + 1}',
        );
      }

      await expectLater(session, completes);

      // Every refusal is reported against the request it belongs to, and the
      // two that were accepted are not reported at all.
      expect(debug.where((line) => line!.contains('refused to')), [
        contains('refused to set environment variable: BAR'),
        contains('refused to request agent forwarding'),
        contains('refused to request x11 forwarding'),
      ]);

      await client.close();
    });

    test('pipelined requests are all sent before any reply is read', () async {
      final client = newClient(pipeline: true);
      final session = client.execute('true', pty: const SSHPtyConfig());

      await _openChannel(client, socket);

      expect(socket.channelRequests, hasLength(2));
      expect(_replyQueue(client).length, 2);

      client.handlePacket(_success().encode());
      client.handlePacket(_success().encode());

      await expectLater(session, completes);
      await client.close();
    });

    test('a refused pty is reported through printDebug and the command runs',
        () async {
      final client = newClient(pipeline: true);
      final session = client.execute('true', pty: const SSHPtyConfig());

      await _openChannel(client, socket);

      // What a server with `PermitTTY no` answers.
      client.handlePacket(_failure().encode());
      client.handlePacket(_success().encode());

      await expectLater(session, completes);
      expect(
        debug,
        contains(contains('refused to start pty')),
      );
      await client.close();
    });

    test('a refused exec still fails the call when pipelining', () async {
      final client = newClient(pipeline: true);
      final session = client.execute('true', pty: const SSHPtyConfig());

      await _openChannel(client, socket);

      client.handlePacket(_success().encode());
      client.handlePacket(_failure().encode());

      await expectLater(session, _throwsRequestError('Failed to execute'));
      await client.close();
    });

    test(
        'the default reports the refused pty, not the channel error that '
        'follows it', () async {
      final client = newClient(pipeline: false);
      final session = client.execute('true', pty: const SSHPtyConfig());

      await _openChannel(client, socket);

      client.handlePacket(_failure().encode());
      client.handlePacket(_close().encode());

      await expectLater(session, _throwsRequestError('Failed to start pty'));
      await client.close();
    });

    test('a pipelined refusal is read before a later reply that cannot arrive',
        () async {
      final client = newClient(pipeline: true);
      final session = client.execute('true', pty: const SSHPtyConfig());

      await _openChannel(client, socket);

      // The pty-req is refused and the channel goes away before the exec is
      // answered. Future.wait would surface the channel error and never look
      // at the refusal that had already come back.
      client.handlePacket(_failure().encode());
      client.handlePacket(_close().encode());

      await expectLater(session, throwsA(isA<SSHStateError>()));
      expect(debug, contains(contains('refused to start pty')));
      await client.close();
    });

    test('a pipelined refusal is read before a later refusal', () async {
      final client = newClient(pipeline: true);
      final session = client.execute('true', pty: const SSHPtyConfig());

      await _openChannel(client, socket);

      client.handlePacket(_failure().encode());
      client.handlePacket(_failure().encode());
      client.handlePacket(_close().encode());

      await expectLater(session, _throwsRequestError('Failed to execute'));
      expect(debug, contains(contains('refused to start pty')));
      await client.close();
    });

    test('shell pipelines its requests the same way', () async {
      final client = newClient(pipeline: true);
      final session = client.shell(environment: {'FOO': '1'});

      await _openChannel(client, socket);

      expect(socket.channelRequests.map((r) => r.requestType), [
        'env',
        'pty-req',
        'shell',
      ]);
      expect(_replyQueue(client).length, 3);

      client.handlePacket(_failure().encode());
      client.handlePacket(_success().encode());
      client.handlePacket(_failure().encode());

      await expectLater(session, _throwsRequestError('Failed to start shell'));
      expect(
        debug,
        contains(contains('refused to set environment variable: FOO')),
      );
      await client.close();
    });
  });
}

Matcher _throwsRequestError(String message) {
  return throwsA(
    isA<SSHChannelRequestError>()
        .having((error) => error.message, 'message', message),
  );
}

/// Lets the client send its channel open, then confirms it and lets the
/// session requests that follow reach the socket.
Future<void> _openChannel(SSHClient client, _FakeSSHSocket socket) async {
  await pumpEventQueue();
  socket.channelRequests.clear();
  client.handlePacket(
    SSH_Message_Channel_Confirmation(
      recipientChannel: 0,
      senderChannel: 42,
      initialWindowSize: 1024 * 1024,
      maximumPacketSize: 32768,
      data: Uint8List(0),
    ).encode(),
  );
  await pumpEventQueue();
}

SSH_Message_Channel_Success _success() =>
    SSH_Message_Channel_Success(recipientChannel: 0);

SSH_Message_Channel_Failure _failure() =>
    SSH_Message_Channel_Failure(recipientChannel: 0);

SSH_Message_Channel_Close _close() =>
    SSH_Message_Channel_Close(recipientChannel: 0);

/// The channel's queue of replies it has asked for and not yet received.
AsyncQueue<bool> _replyQueue(SSHClient client) {
  final channels =
      reflect(client).getField(_clientSymbol('_channels')).reflectee as Map;
  final controller = channels[0] as SSHChannelController;
  final library = reflectClass(SSHChannelController).owner as LibraryMirror;
  final symbol = MirrorSystem.getSymbol('_requestReplyQueue', library);
  return reflect(controller).getField(symbol).reflectee as AsyncQueue<bool>;
}

void _authenticate(SSHClient client) {
  final completer = reflect(client).getField(_clientSymbol('_authenticated'));
  completer.invoke(#complete, [null]);
}

Symbol _clientSymbol(String name) {
  final library = reflectClass(SSHClient).owner as LibraryMirror;
  return MirrorSystem.getSymbol(name, library);
}

void _disableRekeyBuffer(SSHClient client) {
  final transport = reflect(client).getField(_clientSymbol('_transport'));
  final library = transport.type.owner as LibraryMirror;
  final symbol = MirrorSystem.getSymbol('_kexInProgress', library);
  transport.setField(symbol, false);
}

class _FakeSSHSocket implements SSHSocket {
  final _input = StreamController<Uint8List>();
  final _output = StreamController<List<int>>.broadcast(sync: true);

  /// Every SSH_MSG_CHANNEL_REQUEST written to the socket, in order. Nothing is
  /// encrypted before the key exchange completes, so the payload of each
  /// packet can be read straight back off the wire.
  final channelRequests = <SSH_Message_Channel_Request>[];

  /// Called as each request reaches the wire, which is the only moment the
  /// reply queue can be read before the next request has reserved its slot.
  void Function(SSH_Message_Channel_Request)? onChannelRequest;

  _FakeSSHSocket() {
    _output.stream.listen((data) {
      final packet = Uint8List.fromList(data);
      if (packet.length < SSHPacket.headerLength) return;
      final length = SSHPacket.readPacketLength(packet);
      // Skips the version exchange line, which is not a binary packet.
      if (length + 4 != packet.length) return;
      final payload = packet.sublist(
        SSHPacket.headerLength,
        packet.length - SSHPacket.readPaddingLength(packet),
      );
      if (payload.isEmpty) return;
      if (SSHMessage.readMessageId(payload) !=
          SSH_Message_Channel_Request.messageId) {
        return;
      }
      final request = SSH_Message_Channel_Request.decode(payload);
      channelRequests.add(request);
      onChannelRequest?.call(request);
    });
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

class _StubAgent implements SSHAgentHandler {
  @override
  Future<Uint8List> handleRequest(Uint8List request) async => Uint8List(0);
}

/// Thrown by [_EnvThatThrows] when it is asked for a second entry.
class _EnvIterationError implements Exception {}

/// An environment map that yields `FOO` and then fails.
///
/// It stands in for any map read lazily by the caller: one with a computed or
/// filtered `entries`, or one mutated while the session is being set up. When
/// each entry reaches the wire before the next is taken, `FOO` is sent and
/// answered first; when the map is read to the end up front, it is not sent at
/// all. Nothing else on [Map] is used, so nothing else is implemented.
class _EnvThatThrows implements Map<String, String> {
  @override
  Iterable<MapEntry<String, String>> get entries sync* {
    yield const MapEntry('FOO', '1');
    throw _EnvIterationError();
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}
