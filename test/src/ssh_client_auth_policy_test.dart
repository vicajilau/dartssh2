@TestOn('vm')
library;

import 'dart:async';
import 'dart:mirrors';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/message/msg_service.dart';
import 'package:dartssh2/src/message/msg_userauth.dart';
import 'package:dartssh2/src/ssh_message.dart';
import 'package:test/test.dart';

Future<void> tick() => Future<void>.delayed(Duration.zero);

void main() {
  late _Socket socket;
  SSHClient? client;
  late List<String> methods;

  SSHClient create({
    List<SSHAuthMethod>? preferred,
    int passwordAttempts = 1,
    int interactiveAttempts = 1,
    SSHPasswordRequestHandler? password,
    SSHUserInfoRequestHandler? interactive,
    SSHChangePasswordRequestHandler? changePassword,
    List<SSHIdentity>? identities,
  }) {
    final result = SSHClient(
      socket,
      username: 'user',
      preferredAuthMethods: preferred,
      maxPasswordAttempts: passwordAttempts,
      maxKeyboardInteractiveAttempts: interactiveAttempts,
      onPasswordRequest: password,
      onUserInfoRequest: interactive,
      onChangePasswordRequest: changePassword,
      identities: identities,
      keepAliveInterval: null,
      printDebug: (message) {
        const prefix = '_currentAuthMethod = ';
        if (message != null && message.startsWith(prefix)) {
          methods.add(message.substring(prefix.length));
        }
      },
    );
    client = result;
    result.sessionId = Uint8List(32);
    return result;
  }

  List<Uint8List> authPackets() {
    final library = reflectClass(SSHClient).owner as LibraryMirror;
    final transport = reflect(client!)
        .getField(MirrorSystem.getSymbol('_transport', library))
        .reflectee;
    final transportLibrary = reflect(transport).type.owner as LibraryMirror;
    return (reflect(transport)
            .getField(MirrorSystem.getSymbol(
                '_rekeyPendingPackets', transportLibrary))
            .reflectee as Iterable<Uint8List>)
        .where((packet) =>
            packet.first == SSH_Message_Userauth_Request.messageId ||
            packet.first == SSH_Message_Userauth_InfoResponse.messageId)
        .toList();
  }

  Future<void> start() async {
    client!.handlePacket(SSH_Message_Service_Accept('ssh-userauth').encode());
    await tick();
  }

  Future<void> failure(List<String> allowed, {bool partial = false}) async {
    client!.handlePacket(SSH_Message_Userauth_Failure(
      methodsLeft: allowed,
      partialSuccess: partial,
    ).encode());
    await tick();
  }

  Future<void> info([List<SSHUserInfoPrompt>? prompts]) async {
    client!.handlePacket(SSH_Message_Userauth_InfoRequest(
      name: 'login',
      instruction: '',
      lang: '',
      prompts: prompts ?? [SSHUserInfoPrompt('Password:', false)],
    ).encode());
    await tick();
  }

  Future<void> success() async {
    client!.handlePacket(SSH_Message_Userauth_Success().encode());
    await client!.authenticated;
  }

  setUp(() {
    socket = _Socket();
    methods = [];
  });
  tearDown(() async {
    await client?.close();
    client = null;
  });

  test('default preference and one attempt per credential method are retained',
      () async {
    create(
        password: () => 'secret',
        interactive: (_) => ['secret'],
        identities: [_identity(1)]);
    await start();
    await failure(['keyboard-interactive', 'password', 'publickey']);
    await failure(['keyboard-interactive', 'password', 'publickey']);
    await info();
    final failed =
        expectLater(client!.authenticated, throwsA(isA<SSHAuthFailError>()));
    await failure(['keyboard-interactive', 'password', 'publickey']);
    await failed;
    expect(methods, [
      'SSHAuthMethod.publicKey',
      'SSHAuthMethod.password',
      'SSHAuthMethod.keyboardInteractive'
    ]);
  });

  test(
      'explicit preference is copied, deduplicated, and omits disabled methods',
      () async {
    final preferred = [
      SSHAuthMethod.none,
      SSHAuthMethod.keyboardInteractive,
      SSHAuthMethod.keyboardInteractive
    ];
    var passwordCalls = 0;
    create(
        preferred: preferred,
        password: () {
          passwordCalls++;
          return 'secret';
        },
        interactive: (_) => ['secret']);
    preferred.clear();
    expect(() => client!.preferredAuthMethods!.clear(), throwsUnsupportedError);
    await start();
    await failure(['password', 'keyboard-interactive']);
    await info();
    final failed =
        expectLater(client!.authenticated, throwsA(isA<SSHAuthFailError>()));
    await failure(['password', 'keyboard-interactive']);
    await failed;
    expect(
        methods, ['SSHAuthMethod.none', 'SSHAuthMethod.keyboardInteractive']);
    expect(passwordCalls, 0);
  });

  test('empty preference fails without sending an authentication request',
      () async {
    create(preferred: [], password: () => 'secret');
    final failed =
        expectLater(client!.authenticated, throwsA(isA<SSHAuthFailError>()));
    await start();
    await failed;
    expect(methods, isEmpty);
  });

  test('attempt limits must be positive before transport starts', () {
    for (final limit in [0, -1]) {
      expect(() => create(passwordAttempts: limit), throwsArgumentError);
      expect(() => create(interactiveAttempts: limit), throwsArgumentError);
    }
    expect(socket.sink.writes, isEmpty);
  });

  test('rejected password retries on the same connection up to its limit',
      () async {
    var calls = 0;
    create(
        passwordAttempts: 2,
        password: () {
          calls++;
          return 'secret-$calls';
        });
    await start();
    await failure(['password']);
    expect(calls, 2);
    final passwords = authPackets().map((packet) {
      final reader = SSHMessageReader(packet)..skip(1);
      reader.readUtf8();
      reader.readUtf8();
      expect(reader.readUtf8(), 'password');
      expect(reader.readBool(), isFalse);
      return reader.readUtf8();
    });
    expect(passwords, ['secret-1', 'secret-2']);
    final failed =
        expectLater(client!.authenticated, throwsA(isA<SSHAuthFailError>()));
    await failure(['password']);
    await failed;
    expect(calls, 2);
    expect(methods, ['SSHAuthMethod.password', 'SSHAuthMethod.password']);
  });

  test('retry follows the server allow-list', () async {
    var calls = 0;
    create(
        passwordAttempts: 3,
        password: () {
          calls++;
          return 'secret';
        },
        interactive: (_) => ['secret']);
    await start();
    await failure(['keyboard-interactive']);
    await info();
    await success();
    expect(calls, 1);
    expect(methods.last, 'SSHAuthMethod.keyboardInteractive');
  });

  test('multiple interactive rounds consume one conversation attempt',
      () async {
    var prompts = 0;
    create(
        interactiveAttempts: 2,
        interactive: (request) {
          prompts++;
          return [for (final _ in request.prompts) 'secret'];
        });
    await start();
    await info([]);
    await info();
    await info();
    expect(methods, ['SSHAuthMethod.keyboardInteractive']);
    await failure(['keyboard-interactive']);
    await info();
    final failed =
        expectLater(client!.authenticated, throwsA(isA<SSHAuthFailError>()));
    await failure(['keyboard-interactive']);
    await failed;
    expect(methods, [
      'SSHAuthMethod.keyboardInteractive',
      'SSHAuthMethod.keyboardInteractive'
    ]);
    expect(prompts, 4);
  });

  test('null password skips method without consuming remaining retries',
      () async {
    var calls = 0;
    create(
        passwordAttempts: 3,
        password: () {
          calls++;
          return null;
        },
        interactive: (_) => ['secret']);
    await start();
    await info();
    final failed =
        expectLater(client!.authenticated, throwsA(isA<SSHAuthFailError>()));
    await failure(['password', 'keyboard-interactive']);
    await failed;
    expect(calls, 1);
  });

  test('null interactive response skips remaining retries for this factor',
      () async {
    create(
        preferred: [SSHAuthMethod.keyboardInteractive, SSHAuthMethod.password],
        interactiveAttempts: 3,
        interactive: (_) => null,
        password: () => 'secret');
    await start();
    await info();
    final failed =
        expectLater(client!.authenticated, throwsA(isA<SSHAuthFailError>()));
    await failure(['password', 'keyboard-interactive']);
    await failed;
    expect(methods,
        ['SSHAuthMethod.keyboardInteractive', 'SSHAuthMethod.password']);
  });

  test('missing password-change handler skips password safely', () async {
    create(password: () => 'expired', interactive: (_) => ['secret']);
    await start();
    client!.handlePacket(
        SSH_Message_Userauth_Passwd_ChangeReq(prompt: 'change').encode());
    await tick();
    expect(methods.last, 'SSHAuthMethod.keyboardInteractive');
    await success();
  });

  test('password-change exchange belongs to the initial password attempt',
      () async {
    var calls = 0;
    create(
      passwordAttempts: 2,
      password: () {
        calls++;
        return 'expired';
      },
      changePassword: (_) => SSHChangePasswordResponse('expired', 'new'),
    );
    await start();
    client!.handlePacket(
        SSH_Message_Userauth_Passwd_ChangeReq(prompt: 'change').encode());
    await tick();
    await failure(['password']);
    expect(calls, 2);
    expect(authPackets(), hasLength(3));
    final failed =
        expectLater(client!.authenticated, throwsA(isA<SSHAuthFailError>()));
    await failure(['password']);
    await failed;
  });

  test('password budget resets for another successful factor', () async {
    var calls = 0;
    create(
        passwordAttempts: 2,
        password: () {
          calls++;
          return 'secret';
        });
    await start();
    await failure(['password']);
    await failure(['password'], partial: true);
    await failure(['password']);
    await success();
    expect(calls, 4);
  });

  test('completed public-key blobs are excluded across factor resets',
      () async {
    final signed = <int>[];
    create(identities: [
      _identity(1, signed),
      _identity(1, signed),
      _identity(2, signed)
    ], password: () => 'secret');
    await start();
    await failure(['publickey'], partial: true);
    expect(signed, [1, 2]);
    await failure(['password'], partial: true);
    await success();
    expect(signed, [1, 2]);
  });

  test('previously rejected key may be retried for a later factor', () async {
    final signed = <int>[];
    create(identities: [_identity(1, signed), _identity(2, signed)]);
    await start();
    await failure(['publickey']);
    await failure(['publickey'], partial: true);
    expect(signed, [1, 2, 1]);
    await success();
  });

  for (final method in ['password', 'interactive', 'sign']) {
    test('late $method errors do not close an authenticated client', () async {
      final pending = Completer<Never>();
      create(
        password: method == 'password' ? () => pending.future : null,
        interactive: method == 'interactive' ? (_) => pending.future : null,
        identities: method == 'sign'
            ? [
                SSHIdentity.custom(
                  type: 'ssh-ed25519',
                  publicKey: SSHRawHostKey(Uint8List.fromList([1])),
                  signer: (_) => pending.future,
                )
              ]
            : null,
      );
      await start();
      if (method == 'interactive') await info();
      await success();
      pending.completeError(StateError('late callback error'));
      await tick();
      expect(client!.isClosed, isFalse);
    });
  }

  for (final method in [
    'password',
    'interactive',
    'changePassword',
    'sign',
    'probe',
    'hostbased'
  ]) {
    for (final end in ['close', 'timeout', 'success', 'advance']) {
      test('ignores late $method completion after $end', () async {
        final credential = Completer<String?>();
        final response = Completer<List<String>?>();
        final changed = Completer<SSHChangePasswordResponse?>();
        final signature = Completer<SSHSignature>();
        final identity = SSHIdentity.custom(
            type: 'ssh-ed25519',
            publicKey: SSHRawHostKey(Uint8List.fromList([1])),
            shouldProbe: method == 'probe',
            signer: (_) => signature.future);
        if (method == 'hostbased') {
          client = SSHClient(socket,
              username: 'user',
              hostbasedIdentities: [identity],
              hostName: 'client.',
              userNameOnClientHost: 'user',
              onPasswordRequest: () => 'fallback',
              preferredAuthMethods: [
                SSHAuthMethod.hostbased,
                SSHAuthMethod.password
              ],
              keepAliveInterval: null);
          client!.sessionId = Uint8List(32);
        } else {
          SSHPasswordRequestHandler? password;
          if (method == 'password') password = () => credential.future;
          if (method == 'changePassword') password = () => 'expired';
          create(
              password: password,
              interactive:
                  method == 'interactive' ? (_) => response.future : null,
              changePassword: (_) => changed.future,
              identities: ['sign', 'probe'].contains(method)
                  ? [identity, _identity(2)]
                  : null);
        }
        await start();
        if (method == 'interactive') await info();
        if (method == 'changePassword') {
          client!.handlePacket(
              SSH_Message_Userauth_Passwd_ChangeReq(prompt: 'change').encode());
          await tick();
        }
        if (method == 'probe') {
          client!.handlePacket(SSH_Message_Userauth_PK_Ok(
                  publicKeyAlgorithm: identity.type,
                  publicKey: identity.toPublicKey().encode())
              .encode());
          await tick();
        }
        if (end == 'success') {
          await success();
        } else if (end == 'advance') {
          // Advance while the callback is pending; even another attempt of the
          // same method must not accept this attempt's eventual response.
          unawaited(client!.authenticated.catchError((_) {}));
          await failure(method == 'hostbased' ? ['password'] : ['publickey']);
        } else {
          final failed = expectLater(
              client!.authenticated, throwsA(isA<SSHAuthAbortError>()));
          if (end == 'close') {
            await client!.close();
          } else {
            final library = reflectClass(SSHClient).owner as LibraryMirror;
            reflect(client!).invoke(
                MirrorSystem.getSymbol('_handleAuthTimeout', library), []);
          }
          await failed;
        }
        final packetsBefore = authPackets().length;
        credential.complete('late');
        response.complete(['late']);
        changed.complete(SSHChangePasswordResponse('old', 'new'));
        signature.complete(SSHRawSignature(Uint8List.fromList([9])));
        await tick();
        expect(authPackets().length, packetsBefore);
        if (end == 'advance' && !client!.isClosed) await success();
      });
    }
  }
}

SSHIdentity _identity(int id, [List<int>? signed]) => SSHIdentity.custom(
      type: 'ssh-ed25519',
      publicKey: SSHRawHostKey(Uint8List.fromList([id])),
      signer: (_) {
        signed?.add(id);
        return SSHRawSignature(Uint8List.fromList([id]));
      },
    );

class _Socket implements SSHSocket {
  final _input = StreamController<Uint8List>();
  final _done = Completer<void>();
  @override
  final _Sink sink = _Sink();
  @override
  Stream<Uint8List> get stream => _input.stream;
  @override
  Future<void> get done => _done.future;
  @override
  Future<void> close() async {
    if (!_done.isCompleted) _done.complete();
    await _input.close();
  }

  @override
  void destroy() {
    if (!_done.isCompleted) _done.complete();
    unawaited(_input.close());
  }

  @override
  Future<void> flush() async {}
}

class _Sink implements StreamSink<List<int>> {
  final writes = <List<int>>[];
  @override
  void add(List<int> data) => writes.add(List.of(data));
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
