// Also uses test_utils.dart, which imports dart:io.
@TestOn('vm')
@Tags(['integration'])
library;

import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:test/test.dart';

import '../../test_utils.dart';

/// Interop tests against a real OpenSSH server.
///
/// Unit tests can only prove that this library agrees with itself. These prove
/// that what it puts on the wire is what OpenSSH accepts, which is the only way
/// to catch a wire-format mistake: an encoding bug looks perfectly correct to a
/// round-trip test that encodes and decodes with the same code.
void main() {
  group('OpenSSH interop', () {
    test('connects and runs a command', () async {
      final client = await getLocalClient();
      final output = await client.run('echo dartssh2');
      expect(String.fromCharCodes(output).trim(), 'dartssh2');
      await client.close();
    });

    // One connection per algorithm, each forced on its own, so a failure names
    // the algorithm that OpenSSH refused rather than "the handshake broke".
    for (final cipher in const [
      SSHCipherType.chacha20poly1305,
      SSHCipherType.aes256gcm,
      SSHCipherType.aes128gcm,
      SSHCipherType.aes256ctr,
      SSHCipherType.aes128ctr,
    ]) {
      test('negotiates ${cipher.name}', () async {
        final client = await getLocalClient(
          algorithms: SSHAlgorithms(cipher: [cipher]),
        );
        final output = await client.run('echo ${cipher.name}');
        expect(String.fromCharCodes(output).trim(), cipher.name);
        await client.close();
      });
    }

    for (final kex in const [
      SSHKexType.x25519,
      SSHKexType.nistp256,
      SSHKexType.nistp384,
      SSHKexType.nistp521,
      SSHKexType.dhGexSha256,
      SSHKexType.dh14Sha256,
    ]) {
      test('negotiates ${kex.name}', () async {
        final client = await getLocalClient(
          algorithms: SSHAlgorithms(kex: [kex]),
        );
        // A server that does not offer the algorithm answers with
        // SSH_MSG_DISCONNECT, and SSHDisconnectError carries its explanation,
        // so a failure here says which side refused and why.
        expect(await client.run('echo kex'), isNotEmpty);
        await client.close();
      });
    }

    for (final mac in const [
      SSHMacType.hmacSha256Etm,
      SSHMacType.hmacSha512Etm,
      SSHMacType.hmacSha256,
      SSHMacType.hmacSha512,
    ]) {
      test('negotiates ${mac.name}', () async {
        final client = await getLocalClient(
          // Force a non-AEAD cipher, otherwise the MAC is never negotiated.
          algorithms: SSHAlgorithms(
            cipher: [SSHCipherType.aes256ctr],
            mac: [mac],
          ),
        );
        expect(await client.run('echo mac'), isNotEmpty);
        await client.close();
      });
    }

    // The host key comparison on rekey is the one change here that can turn a
    // connection which used to survive into one that drops, so it gets an
    // exercise against a real server rather than a fake transport only.
    group('rekey', () {
      test('a rekey keeps the connection usable', () async {
        var verifications = 0;
        final client = SSHClient(
          await SSHSocket.connect(localSshdHost, localSshdPort),
          username: localSshdUser,
          onPasswordRequest: () => localSshdPassword,
          onVerifyHostKey: (type, fingerprint) {
            verifications++;
            return true;
          },
        );

        expect(
          String.fromCharCodes(await client.run('echo before')).trim(),
          'before',
        );
        expect(verifications, 1);

        // The future comes back once NEWKEYS is in effect, so a rekey that
        // fell over shows up here rather than as a later timeout.
        await client.rekey();

        // Outgoing packets are buffered until the exchange completes, so this
        // only comes back if the rekey went through, host key comparison and
        // all. A mismatch would have terminated the connection instead.
        expect(
          String.fromCharCodes(await client.run('echo after')).trim(),
          'after',
        );

        // The server presents the same host key, so the connection survives
        // and onVerifyHostKey is not consulted a second time.
        expect(verifications, 1);

        await client.close();
      });

      test('an open session survives a rekey', () async {
        final client = await getLocalClient();
        final session = await client.shell();

        await client.rekey();

        session
            .write(Uint8List.fromList('echo through-rekey\nexit\n'.codeUnits));
        final output = String.fromCharCodes(
          await session.stdout.expand((chunk) => chunk).toList(),
        );

        expect(output, contains('through-rekey'));

        await session.done;
        await client.close();
      });

      test('repeated rekeys are safe', () async {
        final client = await getLocalClient();

        for (var i = 0; i < 3; i++) {
          final first = client.rekey();
          // A second request while one is in progress does not start another
          // exchange, it waits on the one already running. Both futures
          // resolve off the same NEWKEYS.
          final second = client.rekey();
          await Future.wait([first, second]);
          expect(await client.run('echo rekey-$i'), isNotEmpty);
        }

        await client.close();
      });
    });

    group('session request pipelining', () {
      // The `dartssh2-nopty` account is the one the server refuses a pty to.
      // That is the case the flag changes: by default the exec is not sent
      // until the pty-req has been answered, so the command never runs, while
      // a pipelined exec is already on the wire when the refusal arrives.
      test('the default refuses to run the command without its pty', () async {
        final marker =
            '/tmp/dartssh2-nopty-default-${DateTime.now().microsecondsSinceEpoch}';
        final client = await getLocalClient(username: localSshdNoPtyUser);

        await expectLater(
          client.run('touch $marker', runInPty: true),
          throwsA(
            isA<SSHChannelRequestError>().having(
              (error) => error.message,
              'message',
              'Failed to start pty',
            ),
          ),
        );

        expect(await _exists(client, marker), isFalse);
        await client.close();
      });

      test('pipelining runs the command and reports the refused pty', () async {
        final marker =
            '/tmp/dartssh2-nopty-pipelined-${DateTime.now().microsecondsSinceEpoch}';
        final client = await getLocalClient(
          username: localSshdNoPtyUser,
          pipelineChannelRequests: true,
        );

        final output = await client.run(
          'touch $marker; echo ran',
          runInPty: true,
        );

        expect(String.fromCharCodes(output).trim(), 'ran');
        expect(await _exists(client, marker), isTrue);

        await client.run('rm -f $marker');
        await client.close();
      });

      test('pipelining runs the command despite a refused env request',
          () async {
        // AcceptEnv is unset on this server, so it refuses every env request.
        // By default that throws before the command is sent.
        final client = await getLocalClient(pipelineChannelRequests: true);

        final output = await client.run(
          'echo \$DARTSSH2_PIPELINE',
          environment: {'DARTSSH2_PIPELINE': 'set'},
        );

        // The variable never arrived, but the command still ran.
        expect(String.fromCharCodes(output).trim(), isEmpty);
        await client.close();
      });
    });

    test('transfers a file over SFTP', () async {
      final client = await getLocalClient();
      final sftp = await client.sftp();

      final file = await sftp.open(
        '/tmp/dartssh2-interop',
        mode: SftpFileOpenMode.create |
            SftpFileOpenMode.write |
            SftpFileOpenMode.truncate,
      );
      await file.writeBytes(Uint8List.fromList('interop'.codeUnits));
      await file.close();

      final read = await sftp.open('/tmp/dartssh2-interop');
      expect(String.fromCharCodes(await read.readBytes()), 'interop');
      await read.close();

      await sftp.close();
      await client.close();
    });
  }, skip: skipWithoutLocalSshd);
}

/// Whether [path] exists on the remote side.
Future<bool> _exists(SSHClient client, String path) async {
  final output = await client.run('test -e $path && echo yes || echo no');
  return String.fromCharCodes(output).trim() == 'yes';
}
