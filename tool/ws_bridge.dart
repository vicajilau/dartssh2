// A WebSocket to TCP bridge, so a browser can reach the interop sshd.
//
// The web tests exist to prove that dartssh2 compiled to JavaScript really
// speaks SSH to a real OpenSSH server, not just that its pieces compile.
// A browser cannot open a TCP socket, which is the whole reason the README
// tells web users to bring their own `SSHSocket` over a WebSocket. This is
// the smallest possible version of that: every frame received is written to
// the sshd connection, every byte read back is sent as one binary frame.
//
//   dart run tool/ws_bridge.dart [--port 8022] [--target-port 2222]
//
// Nothing here is part of the published package. It is test scaffolding, and
// it deliberately binds to the loopback interface only.
import 'dart:async';
import 'dart:io';

Future<void> main(List<String> args) async {
  var port = 8022;
  var targetPort = 2222;
  const targetHost = '127.0.0.1';

  for (var i = 0; i < args.length - 1; i++) {
    if (args[i] == '--port') port = int.parse(args[i + 1]);
    if (args[i] == '--target-port') targetPort = int.parse(args[i + 1]);
  }

  final server = await HttpServer.bind(InternetAddress.loopbackIPv4, port);
  stdout.writeln('ws bridge on ws://127.0.0.1:$port '
      '-> $targetHost:$targetPort');

  await for (final request in server) {
    if (!WebSocketTransformer.isUpgradeRequest(request)) {
      request.response.statusCode = HttpStatus.badRequest;
      await request.response.close();
      continue;
    }
    unawaited(_bridge(request, targetHost, targetPort));
  }
}

Future<void> _bridge(HttpRequest request, String host, int port) async {
  final socket = await WebSocketTransformer.upgrade(request);
  Socket? tcp;
  try {
    tcp = await Socket.connect(host, port);
  } catch (error) {
    stderr.writeln('ws bridge: cannot reach $host:$port: $error');
    await socket.close();
    return;
  }

  // Either side closing tears down the other, so a test that ends without
  // closing cleanly does not leave the bridge holding a connection open.
  final tcpDone = Completer<void>();
  tcp.listen(
    socket.add,
    onError: (Object error) {
      stderr.writeln('ws bridge: tcp error: $error');
      if (!tcpDone.isCompleted) tcpDone.complete();
    },
    onDone: () {
      if (!tcpDone.isCompleted) tcpDone.complete();
    },
    cancelOnError: true,
  );

  socket.listen(
    (frame) {
      if (frame is List<int>) tcp!.add(frame);
    },
    onError: (Object error) => stderr.writeln('ws bridge: ws error: $error'),
    onDone: () => tcp?.destroy(),
    cancelOnError: true,
  );

  await tcpDone.future;
  await socket.close();
}
