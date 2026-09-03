import 'dart:io';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/message/msg_channel.dart';

/// A honeypot that accepts all passwords and public-keys
Future<SSHClient> getHoneypotClient({
  SSHAlgorithms algorithms = const SSHAlgorithms(),
}) async {
  return SSHClient(
    await SSHSocket.connect('test.rebex.net', 22),
    username: 'demo',
    onPasswordRequest: () => 'password',
    onUserInfoRequest: (req) => [for (final _ in req.prompts) 'password'],
    algorithms: algorithms,
  );
}

/// A test server provided by test.rebex.net.
Future<SSHClient> getTestClient() async {
  return SSHClient(
    await SSHSocket.connect('test.rebex.net', 22),
    username: 'demo',
    onPasswordRequest: () => 'password',
    onUserInfoRequest: (req) => [for (final _ in req.prompts) 'password'],
  );
}

/// Connection details of the OpenSSH server started by CI.
///
/// Interop tests run against a real `sshd` rather than a third-party host, so
/// they cannot break because someone else's server is down, and they can prove
/// that what this library puts on the wire is what OpenSSH expects.
const localSshdHost = '127.0.0.1';
const localSshdPort = 2222;
const localSshdUser = 'dartssh2';
const localSshdPassword = 'dartssh2-test-password';

/// An account on the same server that `PermitTTY no` applies to, so a pty-req
/// is answered with SSH_MSG_CHANNEL_FAILURE.
const localSshdNoPtyUser = 'dartssh2-nopty';

/// Whether the local OpenSSH server is running. CI sets this.
bool get hasLocalSshd => Platform.environment['DARTSSH2_LOCAL_SSHD'] == '1';

/// Reason to skip a test when no local OpenSSH server is available.
Object? get skipWithoutLocalSshd => hasLocalSshd
    ? null
    : 'needs the local OpenSSH server, start it with '
        'tool/start_test_sshd.sh or set DARTSSH2_LOCAL_SSHD=1';

/// A client connected to the OpenSSH server started by CI.
Future<SSHClient> getLocalClient({
  SSHAlgorithms algorithms = const SSHAlgorithms(),
  String username = localSshdUser,
  bool pipelineChannelRequests = false,
}) async {
  return SSHClient(
    await SSHSocket.connect(localSshdHost, localSshdPort),
    username: username,
    onPasswordRequest: () => localSshdPassword,
    algorithms: algorithms,
    pipelineChannelRequests: pipelineChannelRequests,
  );
}

Future<List<SSHKeyPair>> getTestKeyPairs() async {
  final ed25519Private = fixture('ssh-ed25519/id_ed25519');
  return SSHKeyPair.fromPem(ed25519Private);
}

/// Get the contents of a test fixture.
///
/// The path is relative to the test/fixtures directory.
String fixture(String path) {
  return File('test/fixtures/$path')
      .readAsStringSync()
      .replaceAll('\r\n', '\n');
}

/// Create a [SSH_Message_Channel_Close] message.
Uint8List createChannelCloseMessage(int recipientChannel) {
  final message = SSH_Message_Channel_Close(
    recipientChannel: recipientChannel,
  );
  return message.encode();
}
