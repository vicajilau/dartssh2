// Uses test_utils.dart, which imports dart:io.
@TestOn('vm')
library;

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/message/msg_service.dart';
import 'package:dartssh2/src/message/msg_userauth.dart';
import 'package:dartssh2/src/ssh_message.dart';
import 'package:test/test.dart';

import '../test_utils.dart';

class _MinimalIdentity extends SSHIdentity {
  @override
  String get type => 'minimal';

  @override
  SSHHostKey toPublicKey() => SSHRawHostKey(Uint8List(0));

  @override
  SSHSignature sign(Uint8List data) => SSHRawSignature(Uint8List(0));
}

void main() {
  group('SSHIdentity', () {
    test('SSHKeyPair implements SSHIdentity', () async {
      final keyPairs = await getTestKeyPairs();
      final keyPair = keyPairs.first;

      expect(keyPair, isA<SSHIdentity>());
      expect(keyPair.type, 'ssh-ed25519');
      expect(keyPair.toPublicKey(), isA<SSHHostKey>());
      expect(keyPair.shouldProbe, isFalse);

      final signature = keyPair.sign(Uint8List.fromList([1, 2, 3, 4]));
      expect(signature, isA<SSHSignature>());
    });

    test('SSHIdentity base class default getters', () {
      final identity = _MinimalIdentity();
      expect(identity.comment, isNull);
      expect(identity.shouldProbe, isFalse);
    });

    test('SSHRawHostKey and SSHRawSignature encode correctly', () {
      final rawKeyBytes =
          Uint8List.fromList([0, 0, 0, 11, ...utf8.encode('ssh-ed25519')]);
      final rawSigBytes = Uint8List.fromList(
          [0, 0, 0, 11, ...utf8.encode('ssh-ed25519'), 0, 0, 0, 4, 1, 2, 3, 4]);

      final rawHostKey = SSHRawHostKey(rawKeyBytes);
      expect(rawHostKey.encode(), equals(rawKeyBytes));

      final rawSignature = SSHRawSignature(rawSigBytes);
      expect(rawSignature.encode(), equals(rawSigBytes));
    });

    test('SSHHostKey.getType and SSHSignature.getType parse types', () {
      final rawKeyBytes =
          Uint8List.fromList([0, 0, 0, 11, ...utf8.encode('ssh-ed25519')]);
      final rawSigBytes = Uint8List.fromList(
          [0, 0, 0, 11, ...utf8.encode('ssh-ed25519'), 0, 0, 0, 4, 1, 2, 3, 4]);

      expect(SSHHostKey.getType(rawKeyBytes), 'ssh-ed25519');
      expect(SSHSignature.getType(rawSigBytes), 'ssh-ed25519');

      expect(() => SSHHostKey.getType(Uint8List(2)), throwsArgumentError);
      expect(() => SSHSignature.getType(Uint8List(2)), throwsArgumentError);
    });

    test('SSHIdentity.custom works with synchronous signer and metadata', () {
      final dummyKey = SSHRawHostKey(Uint8List.fromList([1, 2, 3]));
      final dummySig = SSHRawSignature(Uint8List.fromList([4, 5, 6]));

      final identity = SSHIdentity.custom(
        type: 'custom-type',
        publicKey: dummyKey,
        signer: (data) => dummySig,
        comment: 'id_custom_key',
        shouldProbe: true,
      );

      expect(identity.type, 'custom-type');
      expect(identity.comment, 'id_custom_key');
      expect(identity.shouldProbe, isTrue);
      expect(identity.toPublicKey(), same(dummyKey));
      final sig = identity.sign(Uint8List.fromList([7, 8, 9]));
      expect(sig, same(dummySig));
    });

    test('SSHIdentity.custom works with asynchronous signer', () async {
      final dummyKey = SSHRawHostKey(Uint8List.fromList([1, 2, 3]));
      final dummySig = SSHRawSignature(Uint8List.fromList([4, 5, 6]));

      final identity = SSHIdentity.custom(
        type: 'custom-type',
        publicKey: dummyKey,
        signer: (data) async {
          await Future.delayed(const Duration(milliseconds: 10));
          return dummySig;
        },
      );

      expect(identity.type, 'custom-type');
      expect(identity.comment, isNull);
      expect(identity.shouldProbe, isFalse);
      expect(identity.toPublicKey(), same(dummyKey));
      final sig = await identity.sign(Uint8List.fromList([7, 8, 9]));
      expect(sig, same(dummySig));
    });

    test('SSH_Message_Userauth_PK_Ok encodes, decodes and formats string', () {
      final original = SSH_Message_Userauth_PK_Ok(
        publicKeyAlgorithm: 'ssh-ed25519',
        publicKey: Uint8List.fromList([1, 2, 3, 4]),
      );

      final encoded = original.encode();
      final decoded = SSH_Message_Userauth_PK_Ok.decode(encoded);

      expect(decoded.publicKeyAlgorithm, 'ssh-ed25519');
      expect(decoded.publicKey, equals(Uint8List.fromList([1, 2, 3, 4])));
      expect(decoded.toString(), contains('ssh-ed25519'));
    });
  });

  group('SSHClient with asynchronous SSHIdentity', () {
    test('authenticates successfully with async signer without probe',
        () async {
      final socket = _FakeSSHSocket();
      final signerCompleter = Completer<SSHSignature>();
      var signCallCount = 0;

      final identity = SSHIdentity.custom(
        type: 'ssh-ed25519',
        publicKey: SSHRawHostKey(Uint8List.fromList([1, 2, 3, 4])),
        signer: (data) {
          signCallCount++;
          return signerCompleter.future;
        },
      );

      final client = SSHClient(
        socket,
        username: 'test-user',
        identities: [identity],
      );
      client.sessionId = Uint8List(32);

      // Start userauth service.
      client.handlePacket(SSH_Message_Service_Accept('ssh-userauth').encode());
      await Future<void>.delayed(Duration.zero);

      expect(signCallCount, 1);

      // Complete the async signing operation.
      signerCompleter
          .complete(SSHRawSignature(Uint8List.fromList([5, 6, 7, 8])));
      await Future<void>.delayed(Duration.zero);

      // Server accepts authentication.
      client.handlePacket(SSH_Message_Userauth_Success().encode());
      await client.authenticated;

      await client.close();
    });

    test('public-key probing (RFC 4252 §7.8) probes before signing on PK_Ok',
        () async {
      final socket = _FakeSSHSocket();
      var signCallCount = 0;

      final identity = SSHIdentity.custom(
        type: 'ssh-ed25519',
        publicKey: SSHRawHostKey(Uint8List.fromList([1, 2, 3, 4])),
        comment: 'yubikey_fido2',
        shouldProbe: true,
        signer: (data) async {
          signCallCount++;
          return SSHRawSignature(Uint8List.fromList([9, 8, 7, 6]));
        },
      );

      final client = SSHClient(
        socket,
        username: 'test-user',
        identities: [identity],
      );
      client.sessionId = Uint8List(32);

      // Start userauth service.
      client.handlePacket(SSH_Message_Service_Accept('ssh-userauth').encode());
      await Future<void>.delayed(Duration.zero);

      // Verify signer was NOT called yet because the client sent an unsigned probe.
      expect(signCallCount, 0);

      // Server responds with PK_Ok.
      client.handlePacket(
        SSH_Message_Userauth_PK_Ok(
          publicKeyAlgorithm: 'ssh-ed25519',
          publicKey: Uint8List.fromList([1, 2, 3, 4]),
        ).encode(),
      );
      await Future<void>.delayed(Duration.zero);

      // Now signer should have been called upon PK_Ok.
      expect(signCallCount, 1);

      // Server accepts authentication.
      client.handlePacket(SSH_Message_Userauth_Success().encode());
      await client.authenticated;

      await client.close();
    });

    test('public-key probing rejects key without invoking signer', () async {
      final socket = _FakeSSHSocket();
      var identity1SignCount = 0;
      var identity2SignCount = 0;

      final identity1 = SSHIdentity.custom(
        type: 'ssh-ed25519',
        publicKey: SSHRawHostKey(Uint8List.fromList([1, 1, 1])),
        shouldProbe: true,
        signer: (data) async {
          identity1SignCount++;
          return SSHRawSignature(Uint8List.fromList([11]));
        },
      );

      final identity2 = SSHIdentity.custom(
        type: 'ssh-ed25519',
        publicKey: SSHRawHostKey(Uint8List.fromList([2, 2, 2])),
        shouldProbe: false,
        signer: (data) async {
          identity2SignCount++;
          return SSHRawSignature(Uint8List.fromList([22]));
        },
      );

      final client = SSHClient(
        socket,
        username: 'test-user',
        identities: [identity1, identity2],
      );
      client.sessionId = Uint8List(32);

      // Start userauth service.
      client.handlePacket(SSH_Message_Service_Accept('ssh-userauth').encode());
      await Future<void>.delayed(Duration.zero);

      expect(identity1SignCount, 0);

      // Server rejects the probed identity.
      client.handlePacket(
        SSH_Message_Userauth_Failure(
          methodsLeft: ['publickey'],
          partialSuccess: false,
        ).encode(),
      );
      await Future<void>.delayed(Duration.zero);

      // Identity 1 was never signed! Identity 2 was signed directly.
      expect(identity1SignCount, 0);
      expect(identity2SignCount, 1);

      // Server accepts identity 2.
      client.handlePacket(SSH_Message_Userauth_Success().encode());
      await client.authenticated;

      await client.close();
    });

    test('advances to next identity when async identity is rejected', () async {
      final socket = _FakeSSHSocket();
      final signedIdentities = <String>[];

      final identity1 = SSHIdentity.custom(
        type: 'key-1',
        publicKey: SSHRawHostKey(Uint8List.fromList([1])),
        signer: (data) async {
          signedIdentities.add('key-1');
          return SSHRawSignature(Uint8List.fromList([10]));
        },
      );

      final identity2 = SSHIdentity.custom(
        type: 'key-2',
        publicKey: SSHRawHostKey(Uint8List.fromList([2])),
        signer: (data) async {
          signedIdentities.add('key-2');
          return SSHRawSignature(Uint8List.fromList([20]));
        },
      );

      final client = SSHClient(
        socket,
        username: 'test-user',
        identities: [identity1, identity2],
      );
      client.sessionId = Uint8List(32);

      // Start userauth service.
      client.handlePacket(SSH_Message_Service_Accept('ssh-userauth').encode());
      await Future<void>.delayed(Duration.zero);

      expect(signedIdentities, ['key-1']);

      // Server rejects first identity.
      client.handlePacket(
        SSH_Message_Userauth_Failure(
          methodsLeft: ['publickey'],
          partialSuccess: false,
        ).encode(),
      );
      await Future<void>.delayed(Duration.zero);

      expect(signedIdentities, ['key-1', 'key-2']);

      // Server accepts second identity.
      client.handlePacket(SSH_Message_Userauth_Success().encode());
      await client.authenticated;

      await client.close();
    });

    test(
        'does not send packets or crash if client is closed while async signing',
        () async {
      final socket = _FakeSSHSocket();
      final signerCompleter = Completer<SSHSignature>();

      final identity = SSHIdentity.custom(
        type: 'ssh-ed25519',
        publicKey: SSHRawHostKey(Uint8List.fromList([1, 2, 3])),
        signer: (data) => signerCompleter.future,
      );

      final client = SSHClient(
        socket,
        username: 'test-user',
        identities: [identity],
      );
      client.sessionId = Uint8List(32);

      // Start userauth service.
      client.handlePacket(SSH_Message_Service_Accept('ssh-userauth').encode());
      await Future<void>.delayed(Duration.zero);

      // Close client while signer is in progress.
      final closeFuture = client.close();
      expect(closeFuture, isA<Future<void>>());

      // Signer completes after client is closed.
      signerCompleter.complete(SSHRawSignature(Uint8List.fromList([9, 9, 9])));
      await Future<void>.delayed(const Duration(milliseconds: 10));

      expect(client.isClosed, isTrue);
    });

    test('closes with SSHInternalError when async signer throws', () async {
      final socket = _FakeSSHSocket();

      final identity = SSHIdentity.custom(
        type: 'ssh-ed25519',
        publicKey: SSHRawHostKey(Uint8List.fromList([1, 2, 3])),
        signer: (data) async {
          throw Exception('Hardware token detached');
        },
      );

      final client = SSHClient(
        socket,
        username: 'test-user',
        identities: [identity],
      );
      client.sessionId = Uint8List(32);

      // Start userauth service.
      client.handlePacket(SSH_Message_Service_Accept('ssh-userauth').encode());

      await expectLater(
        client.authenticated,
        throwsA(
          predicate((error) {
            return error is SSHAuthAbortError &&
                error.reason is SSHInternalError &&
                (error.reason as SSHInternalError)
                    .error
                    .toString()
                    .contains('Hardware token detached');
          }),
        ),
      );

      await client.close();
    });

    test('ignores unsolicited PK_Ok when no identity was probed', () async {
      final socket = _FakeSSHSocket();
      final client = SSHClient(
        socket,
        username: 'test-user',
      );
      client.sessionId = Uint8List(32);

      // Send unsolicited PK_Ok packet.
      client.handlePacket(
        SSH_Message_Userauth_PK_Ok(
          publicKeyAlgorithm: 'ssh-ed25519',
          publicKey: Uint8List.fromList([1, 2, 3]),
        ).encode(),
      );

      await Future<void>.delayed(Duration.zero);
      await client.close();
    });

    test('hostbased signs the RFC 4252 challenge with an async identity',
        () async {
      final socket = _FakeSSHSocket();
      final sessionId = Uint8List.fromList([1, 2, 3, 4]);
      final hostKeyWriter = SSHMessageWriter()..writeUtf8('ssh-rsa');
      final hostKey = hostKeyWriter.takeBytes();
      late Uint8List signedChallenge;

      final identity = SSHIdentity.custom(
        type: 'rsa-sha2-512',
        publicKey: SSHRawHostKey(hostKey),
        signer: (challenge) async {
          signedChallenge = challenge;
          return SSHRawSignature(Uint8List.fromList([9, 8, 7]));
        },
      );
      final client = SSHClient(
        socket,
        username: 'remote-user',
        hostbasedIdentities: [identity],
        hostName: 'client.example.com.',
        userNameOnClientHost: 'local-user',
      );
      client.sessionId = sessionId;

      client.handlePacket(SSH_Message_Service_Accept('ssh-userauth').encode());
      await Future<void>.delayed(Duration.zero);

      final reader = SSHMessageReader(signedChallenge);
      expect(reader.readString(), sessionId);
      expect(reader.readUint8(), SSH_Message_Userauth_Request.messageId);
      expect(reader.readUtf8(), 'remote-user');
      expect(reader.readUtf8(), 'ssh-connection');
      expect(reader.readUtf8(), 'hostbased');
      expect(reader.readUtf8(), 'rsa-sha2-512');
      expect(reader.readString(), hostKey);
      expect(SSHHostKey.getType(hostKey), 'ssh-rsa');
      expect(reader.readUtf8(), 'client.example.com.');
      expect(reader.readUtf8(), 'local-user');

      client.handlePacket(SSH_Message_Userauth_Success().encode());
      await client.authenticated;
      await client.close();
    });

    test('methodsLeft preserves client preference and drops exhausted keys',
        () async {
      final socket = _FakeSSHSocket();
      final attempts = <String>[];
      var passwordRequests = 0;

      SSHIdentity identity(String name) => SSHIdentity.custom(
            type: 'ssh-ed25519',
            publicKey: SSHRawHostKey(Uint8List.fromList([name.length])),
            signer: (challenge) {
              attempts.add(name);
              return SSHRawSignature(Uint8List.fromList([name.length]));
            },
          );

      final client = SSHClient(
        socket,
        username: 'test-user',
        identities: [identity('first'), identity('second')],
        onPasswordRequest: () {
          passwordRequests++;
          return 'secret';
        },
      );
      client.sessionId = Uint8List(32);

      client.handlePacket(SSH_Message_Service_Accept('ssh-userauth').encode());
      await Future<void>.delayed(Duration.zero);
      expect(attempts, ['first']);

      client.handlePacket(
        SSH_Message_Userauth_Failure(
          methodsLeft: const ['password', 'publickey'],
        ).encode(),
      );
      await Future<void>.delayed(Duration.zero);
      expect(attempts, ['first', 'second']);
      expect(passwordRequests, 0);

      client.handlePacket(
        SSH_Message_Userauth_Failure(
          methodsLeft: const ['publickey', 'password'],
        ).encode(),
      );
      await Future<void>.delayed(Duration.zero);
      expect(attempts, ['first', 'second']);
      expect(passwordRequests, 1);

      client.handlePacket(SSH_Message_Userauth_Success().encode());
      await client.authenticated;
      await client.close();
    });

    test('methodsLeft stops an identity method the server no longer allows',
        () async {
      final socket = _FakeSSHSocket();
      final signedIdentities = <int>[];
      var passwordRequests = 0;

      SSHIdentity identity(int id) => SSHIdentity.custom(
            type: 'ssh-ed25519',
            publicKey: SSHRawHostKey(Uint8List.fromList([id])),
            signer: (challenge) {
              signedIdentities.add(id);
              return SSHRawSignature(Uint8List.fromList([id]));
            },
          );

      final client = SSHClient(
        socket,
        username: 'test-user',
        identities: [identity(1), identity(2)],
        onPasswordRequest: () {
          passwordRequests++;
          return 'secret';
        },
      );
      client.sessionId = Uint8List(32);

      client.handlePacket(SSH_Message_Service_Accept('ssh-userauth').encode());
      await Future<void>.delayed(Duration.zero);
      expect(signedIdentities, [1]);

      client.handlePacket(
        SSH_Message_Userauth_Failure(
          methodsLeft: const ['password'],
        ).encode(),
      );
      await Future<void>.delayed(Duration.zero);
      expect(signedIdentities, [1]);
      expect(passwordRequests, 1);

      client.handlePacket(SSH_Message_Userauth_Success().encode());
      await client.authenticated;
      await client.close();
    });

    test('hostbased remains available while an identity is untried', () async {
      final socket = _FakeSSHSocket();
      final attempts = <int>[];

      SSHIdentity identity(int id) => SSHIdentity.custom(
            type: 'ssh-ed25519',
            publicKey: SSHRawHostKey(Uint8List.fromList([id])),
            signer: (challenge) {
              attempts.add(id);
              return SSHRawSignature(Uint8List.fromList([id]));
            },
          );

      final client = SSHClient(
        socket,
        username: 'remote-user',
        hostbasedIdentities: [identity(1), identity(2)],
        hostName: 'client.example.com.',
        userNameOnClientHost: 'local-user',
      );
      client.sessionId = Uint8List(32);

      client.handlePacket(SSH_Message_Service_Accept('ssh-userauth').encode());
      await Future<void>.delayed(Duration.zero);
      expect(attempts, [1]);

      client.handlePacket(
        SSH_Message_Userauth_Failure(
          methodsLeft: const ['hostbased'],
        ).encode(),
      );
      await Future<void>.delayed(Duration.zero);
      expect(attempts, [1, 2]);

      client.handlePacket(SSH_Message_Userauth_Success().encode());
      await client.authenticated;
      await client.close();
    });

    test('partial success continues with a different publickey identity',
        () async {
      final socket = _FakeSSHSocket();
      var signCount = 0;
      final identity = SSHIdentity.custom(
        type: 'ssh-ed25519',
        publicKey: SSHRawHostKey(Uint8List.fromList([1, 2, 3])),
        signer: (challenge) {
          signCount++;
          return SSHRawSignature(Uint8List.fromList([4, 5, 6]));
        },
      );
      final client = SSHClient(
        socket,
        username: 'test-user',
        identities: [
          identity,
          SSHIdentity.custom(
            type: 'ssh-ed25519',
            publicKey: SSHRawHostKey(Uint8List.fromList([7, 8, 9])),
            signer: (_) {
              signCount++;
              return SSHRawSignature(Uint8List.fromList([4, 5, 6]));
            },
          ),
        ],
      );
      client.sessionId = Uint8List(32);

      client.handlePacket(SSH_Message_Service_Accept('ssh-userauth').encode());
      await Future<void>.delayed(Duration.zero);
      expect(signCount, 1);

      client.handlePacket(
        SSH_Message_Userauth_Failure(
          methodsLeft: const ['publickey'],
          partialSuccess: true,
        ).encode(),
      );
      await Future<void>.delayed(Duration.zero);
      expect(signCount, 2);

      client.handlePacket(SSH_Message_Userauth_Success().encode());
      await client.authenticated;
      await client.close();
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
  final sentData = <List<int>>[];

  @override
  void add(List<int> data) {
    sentData.add(data);
  }

  @override
  void addError(Object error, [StackTrace? stackTrace]) {}

  @override
  Future<void> addStream(Stream<List<int>> stream) async {
    await for (final data in stream) {
      sentData.add(data);
    }
  }

  @override
  Future<void> close() async {}

  @override
  Future<void> get done async {}
}
