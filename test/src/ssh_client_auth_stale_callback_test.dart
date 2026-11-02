import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/message/msg_service.dart';
import 'package:dartssh2/src/message/msg_userauth.dart';
import 'package:test/test.dart';

/// A credential callback or signer can complete long after the attempt it
/// was asked for: the user takes a while to type, a hardware key waits for a
/// touch. By then authentication may have moved on, succeeded, timed out or
/// been closed, and the late result must neither reach the wire nor close the
/// connection.
void main() {
  Future<void> tick() => Future<void>.delayed(Duration.zero);

  late List<String> sent;
  late SSHClient client;

  void create({
    SSHPasswordRequestHandler? password,
    SSHUserInfoRequestHandler? interactive,
    SSHChangePasswordRequestHandler? changePassword,
    List<SSHIdentity>? identities,
    List<SSHIdentity>? hostbased,
  }) {
    sent = [];
    client = SSHClient(
      _FakeSSHSocket(),
      username: 'test-user',
      onPasswordRequest: password,
      onUserInfoRequest: interactive,
      onChangePasswordRequest: changePassword,
      identities: identities,
      hostbasedIdentities: hostbased,
      hostName: hostbased == null ? null : 'client.example.',
      userNameOnClientHost: hostbased == null ? null : 'test-user',
      keepAliveInterval: null,
      printTrace: (message) {
        if (message != null && message.startsWith('-> ')) sent.add(message);
      },
    );
    client.sessionId = Uint8List(32);
  }

  Future<void> start() async {
    client.handlePacket(SSH_Message_Service_Accept('ssh-userauth').encode());
    await tick();
  }

  Future<void> failure(List<String> methodsLeft) async {
    client.handlePacket(
      SSH_Message_Userauth_Failure(
        methodsLeft: methodsLeft,
        partialSuccess: false,
      ).encode(),
    );
    await tick();
  }

  Future<void> infoRequest() async {
    client.handlePacket(
      SSH_Message_Userauth_InfoRequest(
        name: '',
        instruction: '',
        lang: '',
        prompts: [SSHUserInfoPrompt('Password: ', false)],
      ).encode(),
    );
    await tick();
  }

  SSHIdentity identity(int id, Future<SSHSignature> Function() sign,
          {bool probe = false}) =>
      SSHIdentity.custom(
        type: 'ssh-ed25519',
        publicKey: SSHRawHostKey(Uint8List.fromList([id])),
        shouldProbe: probe,
        signer: (_) => sign(),
      );

  SSHIdentity quickIdentity(int id) => identity(
        id,
        () async => SSHRawSignature(Uint8List.fromList([id])),
      );

  /// Builds a client whose first attempt for [method] stays pending until
  /// the returned callback completes it, either with a value or an error.
  ///
  /// The client is tried in a fixed order (publickey, password,
  /// keyboard-interactive, hostbased), so each case is given a fallback that
  /// comes later in it, or a second identity of the same kind. The returned
  /// method name is what the server offers to move authentication on to it.
  Future<(void Function({Object? error}), String)> pendingAttempt(
    String method,
  ) async {
    final password = Completer<String?>();
    final responses = Completer<List<String>?>();
    final change = Completer<SSHChangePasswordResponse?>();
    final signature = Completer<SSHSignature>();
    final completers = [password, responses, change, signature];
    // Only one of these is awaited by the client; the rest must not report
    // their error as unhandled.
    for (final completer in completers) {
      completer.future.ignore();
    }

    late String fallback;
    switch (method) {
      case 'password':
        create(
          password: () => password.future,
          interactive: (_) => ['fallback'],
        );
        fallback = 'keyboard-interactive';
      case 'keyboard-interactive':
        create(
          interactive: (_) => responses.future,
          hostbased: [quickIdentity(2)],
        );
        fallback = 'hostbased';
      case 'password change':
        create(
          password: () => 'expired',
          changePassword: (_) => change.future,
          interactive: (_) => ['fallback'],
        );
        fallback = 'keyboard-interactive';
      case 'publickey':
        create(identities: [
          identity(1, () => signature.future),
          quickIdentity(2),
        ]);
        fallback = 'publickey';
      case 'publickey probe':
        create(identities: [
          identity(1, () => signature.future, probe: true),
          quickIdentity(2),
        ]);
        fallback = 'publickey';
      case 'hostbased':
        create(hostbased: [
          identity(1, () => signature.future),
          quickIdentity(2),
        ]);
        fallback = 'hostbased';
    }

    await start();
    if (method == 'keyboard-interactive') await infoRequest();
    if (method == 'password change') {
      client.handlePacket(
        SSH_Message_Userauth_Passwd_ChangeReq(prompt: 'expired').encode(),
      );
      await tick();
    }
    if (method == 'publickey probe') {
      final key = SSHRawHostKey(Uint8List.fromList([1]));
      client.handlePacket(
        SSH_Message_Userauth_PK_Ok(
          publicKeyAlgorithm: 'ssh-ed25519',
          publicKey: key.encode(),
        ).encode(),
      );
      await tick();
    }

    void complete({Object? error}) {
      if (error != null) {
        for (final completer in completers) {
          completer.completeError(error);
        }
        return;
      }
      password.complete('late');
      responses.complete(['late']);
      change.complete(SSHChangePasswordResponse('old', 'new'));
      signature.complete(SSHRawSignature(Uint8List.fromList([9])));
    }

    return (complete, fallback);
  }

  const methods = [
    'password',
    'keyboard-interactive',
    'password change',
    'publickey',
    'publickey probe',
    'hostbased',
  ];

  for (final method in methods) {
    group('late $method', () {
      test('is not sent after authentication succeeds', () async {
        final (complete, _) = await pendingAttempt(method);
        client.handlePacket(SSH_Message_Userauth_Success().encode());
        await client.authenticated;
        final before = sent.length;

        complete();
        await tick();

        expect(sent, hasLength(before));
        await client.close();
      });

      test('failure does not close an authenticated client', () async {
        final (complete, _) = await pendingAttempt(method);
        client.handlePacket(SSH_Message_Userauth_Success().encode());
        await client.authenticated;

        complete(error: StateError('late failure'));
        await tick();

        expect(client.isClosed, isFalse);
        await client.close();
      });

      test('is not sent after the client is closed', () async {
        final (complete, _) = await pendingAttempt(method);
        final aborted = expectLater(
          client.authenticated,
          throwsA(isA<SSHAuthAbortError>()),
        );
        await client.close();
        await aborted;
        final before = sent.length;

        complete();
        await tick();

        expect(sent, hasLength(before));
      });

      test('is not sent after authentication moved on', () async {
        final (complete, fallback) = await pendingAttempt(method);
        // The server rejects the pending attempt while the callback is still
        // running, and the client moves on to its next method.
        await failure([fallback]);
        final before = sent.length;

        complete();
        await tick();

        expect(sent, hasLength(before));
        client.handlePacket(SSH_Message_Userauth_Success().encode());
        await client.authenticated;
        await client.close();
      });
    });
  }
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
