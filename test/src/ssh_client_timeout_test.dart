// Uses dart:mirrors, which is VM-only.
@TestOn('vm')
library;

import 'dart:async';
import 'dart:convert';
// Deprecated in Dart 3.14, still needed here to reach private state.
// ignore: deprecated_member_use
import 'dart:mirrors';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:test/test.dart';

void main() {
  final clientLibrary = reflectClass(SSHClient).owner as LibraryMirror;
  Symbol privateSymbol(String name) =>
      MirrorSystem.getSymbol(name, clientLibrary);

  group('SSHClient timeouts', () {
    test('fails authentication future when handshake times out', () async {
      final socket = _FakeSSHSocket();
      final client = SSHClient(
        socket,
        username: 'demo',
        handshakeTimeout: const Duration(milliseconds: 10),
      );

      await expectLater(
        client.authenticated,
        throwsA(isA<SSHHandshakeError>()),
      );

      client.close();
    });

    test('fails authentication future when auth times out', () async {
      final socket = _FakeSSHSocket();
      final client = SSHClient(
        socket,
        username: 'demo',
        authTimeout: const Duration(milliseconds: 10),
      );

      reflect(client).invoke(privateSymbol('_handleTransportReady'), const []);

      await expectLater(
        client.authenticated,
        throwsA(isA<SSHAuthAbortError>()),
      );

      client.close();
    });
  });
}

class _FakeSSHSocket implements SSHSocket {
  final _inputController = StreamController<Uint8List>();
  final _doneCompleter = Completer<void>();
  final _sink = _RecordingSink();

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
  @override
  void add(List<int> data) {
    latin1.decode(data);
  }

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
