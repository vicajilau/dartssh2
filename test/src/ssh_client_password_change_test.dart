import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/message/msg_service.dart';
import 'package:dartssh2/src/message/msg_userauth.dart';
import 'package:test/test.dart';

void main() {
  group('SSHClient password change request', () {
    test('without a handler moves on to the next method', () async {
      final debug = <String>[];
      final client = SSHClient(
        _FakeSSHSocket(),
        username: 'test-user',
        onPasswordRequest: () => 'expired',
        onUserInfoRequest: (_) => const [],
        printDebug: (message) => debug.add('$message'),
      );
      client.sessionId = Uint8List(32);

      client.handlePacket(SSH_Message_Service_Accept('ssh-userauth').encode());
      await Future<void>.delayed(Duration.zero);

      client.handlePacket(
        SSH_Message_Userauth_Passwd_ChangeReq(prompt: 'Password expired')
            .encode(),
      );
      await Future<void>.delayed(Duration.zero);

      expect(client.isClosed, isFalse);
      expect(debug, contains('SSHClient._authWithKeyboardInteractive'));

      client.handlePacket(SSH_Message_Userauth_Success().encode());
      await client.authenticated;
      await client.close();
    });

    test('without a handler or another method fails authentication', () async {
      final client = SSHClient(
        _FakeSSHSocket(),
        username: 'test-user',
        onPasswordRequest: () => 'expired',
      );
      client.sessionId = Uint8List(32);
      final failed = expectLater(
        client.authenticated,
        throwsA(isA<SSHAuthFailError>()),
      );

      client.handlePacket(SSH_Message_Service_Accept('ssh-userauth').encode());
      await Future<void>.delayed(Duration.zero);

      client.handlePacket(
        SSH_Message_Userauth_Passwd_ChangeReq(prompt: 'Password expired')
            .encode(),
      );
      await Future<void>.delayed(Duration.zero);

      // The client falls back to the 'none' method, which the server refuses.
      client.handlePacket(
        SSH_Message_Userauth_Failure(
          methodsLeft: const ['password'],
          partialSuccess: false,
        ).encode(),
      );

      await failed;
      await client.close();
    });
  });
}

class _FakeSSHSocket implements SSHSocket {
  final _inputController = StreamController<Uint8List>();
  final _doneCompleter = Completer<void>();

  @override
  Stream<Uint8List> get stream => _inputController.stream;

  @override
  StreamSink<List<int>> get sink => _NullSink();

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

class _NullSink implements StreamSink<List<int>> {
  @override
  void add(List<int> data) {}

  @override
  void addError(Object error, [StackTrace? stackTrace]) {}

  @override
  Future<void> addStream(Stream<List<int>> stream) => stream.drain();

  @override
  Future<void> close() async {}

  @override
  Future<void> get done async {}
}
