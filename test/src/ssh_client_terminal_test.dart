// Uses dart:mirrors, which is VM-only.
@TestOn('vm')
library;

import 'dart:async';
// Deprecated in Dart 3.14, still needed here to reach private state.
// ignore: deprecated_member_use
import 'dart:mirrors';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/ssh_channel.dart';
import 'package:test/test.dart';

void main() {
  final clientLibrary = reflectClass(SSHClient).owner as LibraryMirror;
  Symbol privateSymbol(String name) =>
      MirrorSystem.getSymbol(name, clientLibrary);
  final transportLibrary = reflectClass(SSHTransport).owner as LibraryMirror;
  Symbol transportPrivateSymbol(String name) =>
      MirrorSystem.getSymbol(name, transportLibrary);

  test('transport termination fails every pending SSH reply waiter', () async {
    final socket = _FakeSSHSocket();
    final client = SSHClient(socket, username: 'demo', keepAliveInterval: null);
    final clientMirror = reflect(client);
    final authenticated = clientMirror
        .getField(privateSymbol('_authenticated'))
        .reflectee as Completer<void>;
    authenticated.complete();

    final channelController =
        clientMirror.invoke(privateSymbol('_acceptChannel'), const [], {
      #localChannelId: 99,
      #remoteChannelId: 100,
      #remoteInitialWindowSize: 0,
      #remoteMaximumPacketSize: 1024,
    }).reflectee as SSHChannelController;

    final ping = client.ping();
    final open = client.forwardLocal('example.com', 22);
    final request = channelController.channel.sendShell();
    await Future<void>.delayed(Duration.zero);

    final expectations = [
      expectLater(ping, throwsA(isA<SSHStateError>())),
      expectLater(open, throwsA(isA<SSHStateError>())),
      expectLater(request, throwsA(isA<SSHStateError>())),
    ];

    await socket.closeRemote();

    await Future.wait(expectations);
    expect(
      () => clientMirror.invoke(privateSymbol('_handleTransportClosed'), [
        SSHStateError('later'),
      ]),
      returnsNormally,
    );

    final writesBeforeRetry = socket.writeCount;
    await expectLater(client.ping(), throwsA(isA<SSHStateError>()));
    await expectLater(
      client.forwardLocal('example.com', 22),
      throwsA(isA<SSHStateError>()),
    );
    await expectLater(
      channelController.channel.sendShell(),
      throwsA(isA<SSHStateError>()),
    );
    expect(socket.writeCount, writesBeforeRetry);

    await client.close();
  });

  test('send failure terminates reply waiters without leaving a gap', () async {
    final socket = _FakeSSHSocket();
    final client = SSHClient(
      socket,
      username: 'demo',
      keepAliveInterval: null,
    );
    final authenticated = reflect(client)
        .getField(privateSymbol('_authenticated'))
        .reflectee as Completer<void>;
    authenticated.complete();
    final transport = reflect(client)
        .getField(privateSymbol('_transport'))
        .reflectee as SSHTransport;
    reflect(transport).setField(
      transportPrivateSymbol('_kexInProgress'),
      false,
    );

    final error = StateError('write failed');
    socket.writeError = error;

    await expectLater(client.ping(), throwsA(same(error)));
    final writesBeforeRetry = socket.writeCount;
    await expectLater(
      client.forwardLocal('example.com', 22),
      throwsA(same(error)),
    );
    expect(socket.writeCount, writesBeforeRetry);

    socket.writeError = null;
    await client.close();
  });
}

class _FakeSSHSocket implements SSHSocket {
  final _inputController = StreamController<Uint8List>();
  final _doneCompleter = Completer<void>();
  late final _sink = _RecordingSink(_recordWrite);

  var writeCount = 0;
  Object? writeError;

  void _recordWrite() {
    writeCount++;
    final error = writeError;
    if (error != null) throw error;
  }

  @override
  Stream<Uint8List> get stream => _inputController.stream;

  @override
  StreamSink<List<int>> get sink => _sink;

  @override
  Future<void> get done => _doneCompleter.future;

  @override
  Future<void> close() async {
    if (!_doneCompleter.isCompleted) {
      _doneCompleter.complete();
    }
    await _inputController.close();
  }

  Future<void> closeRemote() => _inputController.close();

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

class _RecordingSink implements StreamSink<List<int>> {
  _RecordingSink(this._onAdd);

  final void Function() _onAdd;

  @override
  void add(List<int> data) => _onAdd();

  @override
  void addError(Object error, [StackTrace? stackTrace]) {}

  @override
  Future<void> addStream(Stream<List<int>> stream) async {
    await for (final data in stream) {
      add(data);
    }
  }

  @override
  Future<void> close() async {}

  @override
  Future<void> get done async {}
}
