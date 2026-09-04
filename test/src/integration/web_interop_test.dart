// Proves that dartssh2 compiled to JavaScript really speaks SSH to a real
// OpenSSH server.
//
// Everything else that runs under `-p chrome` shows that the pieces compile
// and behave: the AEAD nonce arithmetic, the SFTP wire encoding, the HTTP
// parsing. None of it puts a packet on a wire. Without this, "web is
// supported" rested on the parts having been checked individually, which is
// exactly the gap that let every AEAD cipher and the whole of SFTP sit broken
// on the web until 4.0.0.
//
// A browser cannot open a TCP socket, which is why the README tells web users
// to bring their own `SSHSocket`. `tool/ws_bridge.dart` provides the other end
// and CI starts it alongside the sshd container.
@TestOn('browser')
@Tags(['integration'])
library;

import 'dart:async';
import 'dart:js_interop';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:test/test.dart';
import 'package:web/web.dart' as web;

/// Where `tool/ws_bridge.dart` listens. Matches the CI workflow.
const _bridgeUrl = 'ws://127.0.0.1:8022';

const _user = 'dartssh2';
const _password = 'dartssh2-test-password';

/// Whether [_bridgeUrl] answered during [setUpAll].
///
/// Decided at run time rather than through a compile-time define, because
/// `dart test` has no way to pass one: there is no `--define`, and the browser
/// has no `Platform.environment` for the VM interop tests' `DARTSSH2_LOCAL_SSHD`
/// trick. Probing the bridge is also a truer test of the same thing.
var _bridgeIsUp = false;

const _skipReason = 'needs tool/ws_bridge.dart and the interop sshd, which CI '
    'starts. Run tool/start_test_sshd.sh and dart run tool/ws_bridge.dart.';

/// Skips the calling test when the bridge is not there, the way the VM interop
/// tests skip without the server. Returns whether the test should go on.
bool _requireBridge() {
  if (_bridgeIsUp) return true;
  markTestSkipped(_skipReason);
  return false;
}

/// Opens [_bridgeUrl] and closes it again, to see whether anything answers.
Future<bool> _probeBridge() async {
  final socket = web.WebSocket(_bridgeUrl);
  final opened = Completer<bool>();
  socket.onopen = ((web.Event _) {
    if (!opened.isCompleted) opened.complete(true);
  }).toJS;
  socket.onerror = ((web.Event _) {
    if (!opened.isCompleted) opened.complete(false);
  }).toJS;
  final up = await opened.future
      .timeout(const Duration(seconds: 5), onTimeout: () => false);
  socket.close();
  return up;
}

void main() {
  group('dartssh2 compiled to JavaScript, against a real OpenSSH server', () {
    late SSHClient client;

    setUpAll(() async {
      _bridgeIsUp = await _probeBridge();
    });

    setUp(() async {
      if (!_bridgeIsUp) return;
      client = SSHClient(
        await _WebSocketSSHSocket.connect(_bridgeUrl),
        username: _user,
        onPasswordRequest: () => _password,
      );
      await client.authenticated;
    });

    tearDown(() {
      if (_bridgeIsUp) client.close();
    });

    test('completes a handshake and reports the server version', () async {
      if (!_requireBridge()) return;

      // Getting here at all means the version exchange, key exchange, host
      // key signature check and userauth all ran in the browser.
      expect(client.remoteVersion, startsWith('SSH-2.0-'));
    });

    test('runs a command and reads its output', () async {
      if (!_requireBridge()) return;

      final output = await client.run('echo web-interop');
      expect(String.fromCharCodes(output).trim(), 'web-interop');
    });

    test('negotiates an AEAD cipher, which is what W-01 broke', () async {
      if (!_requireBridge()) return;

      // aes256-gcm is first in the default cipher list and its nonce counter
      // is the code that threw under dart2js before 4.0.0. A command that
      // returns proves it encrypted and decrypted for real.
      final aeadOnly = SSHClient(
        await _WebSocketSSHSocket.connect(_bridgeUrl),
        username: _user,
        onPasswordRequest: () => _password,
        algorithms: const SSHAlgorithms(cipher: [SSHCipherType.aes256gcm]),
      );
      final output = await aeadOnly.run('echo aead');
      expect(String.fromCharCodes(output).trim(), 'aead');
      aeadOnly.close();
    });

    test('round-trips a file over SFTP', () async {
      if (!_requireBridge()) return;

      // SFTP was the other half of W-01: every size and offset on the wire is
      // a 64-bit field, and reading one threw under dart2js.
      final sftp = await client.sftp();
      final path = '/tmp/dartssh2-web-interop';
      final payload = Uint8List.fromList('web sftp round trip'.codeUnits);

      final write = await sftp.open(
        path,
        mode: SftpFileOpenMode.create |
            SftpFileOpenMode.write |
            SftpFileOpenMode.truncate,
      );
      await write.writeBytes(payload);
      await write.close();

      final read = await sftp.open(path);
      expect(await read.readBytes(), payload);
      expect((await read.stat()).size, payload.length);
      await read.close();

      await sftp.remove(path);
      sftp.close();
    });
  });
}

/// The `SSHSocket` the README tells web users to write, in its smallest form.
class _WebSocketSSHSocket implements SSHSocket {
  _WebSocketSSHSocket._(this._socket);

  final web.WebSocket _socket;

  final _incoming = StreamController<Uint8List>();
  final _outgoing = StreamController<List<int>>();
  final _done = Completer<void>();

  static Future<SSHSocket> connect(String url) async {
    final socket = web.WebSocket(url)..binaryType = 'arraybuffer';
    final opened = Completer<void>();

    socket.onopen = ((web.Event _) {
      if (!opened.isCompleted) opened.complete();
    }).toJS;
    socket.onerror = ((web.Event _) {
      if (!opened.isCompleted) {
        opened.completeError(StateError('cannot reach $url'));
      }
    }).toJS;

    await opened.future.timeout(const Duration(seconds: 10));
    return _WebSocketSSHSocket._(socket).._wire();
  }

  void _wire() {
    _socket.onmessage = ((web.MessageEvent event) {
      final buffer = event.data as JSArrayBuffer;
      _incoming.add(buffer.toDart.asUint8List());
    }).toJS;

    _socket.onclose = ((web.CloseEvent _) {
      if (!_incoming.isClosed) _incoming.close();
      if (!_done.isCompleted) _done.complete();
    }).toJS;

    _outgoing.stream.listen((data) {
      _socket.send(Uint8List.fromList(data).toJS);
    });
  }

  @override
  Stream<Uint8List> get stream => _incoming.stream;

  @override
  StreamSink<List<int>> get sink => _outgoing.sink;

  @override
  Future<void> get done => _done.future;

  @override
  Future<void> close() async {
    _socket.close();
    return done;
  }

  @override
  void destroy() => _socket.close();

  @override
  Future<void> flush() async {}
}
