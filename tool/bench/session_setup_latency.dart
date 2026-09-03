import 'dart:async';
import 'dart:io';
import 'dart:typed_data';
import 'package:dartssh2/dartssh2.dart';

/// Adds [delay] to every byte in each direction, so one request/reply
/// exchange costs 2*delay of simulated RTT.
class DelayedSocket implements SSHSocket {
  DelayedSocket(this._inner, this.delay);
  final SSHSocket _inner;
  final Duration delay;

  @override
  Stream<Uint8List> get stream => _inner.stream.asyncMap((d) async {
        await Future<void>.delayed(delay);
        return d;
      });

  @override
  StreamSink<List<int>> get sink => _DelayedSink(_inner.sink, delay);

  @override
  Future<void> close() => _inner.close();
  @override
  Future<void> get done => _inner.done;
  @override
  void destroy() => _inner.destroy();
  @override
  Future<void> flush() => _inner.flush();
}

class _DelayedSink implements StreamSink<List<int>> {
  _DelayedSink(this._inner, this._delay);
  final StreamSink<List<int>> _inner;
  final Duration _delay;
  var _closed = false;
  var _inFlight = 0;

  // Each write is delayed independently rather than chained: a real link
  // carries back-to-back writes concurrently, and serialising them here would
  // charge the unpipelined baseline a second delay it does not actually pay.
  // Equal-duration Future.delayed callbacks fire in scheduling order, so byte
  // order is preserved.
  @override
  void add(List<int> data) {
    _inFlight++;
    Future<void>.delayed(_delay).then((_) {
      _inFlight--;
      if (_closed) return;
      try {
        _inner.add(data);
      } catch (_) {}
    });
  }

  @override
  void addError(Object e, [StackTrace? st]) => _inner.addError(e, st);
  @override
  Future<void> addStream(Stream<List<int>> s) => _inner.addStream(s);
  @override
  Future<void> close() async {
    while (_inFlight > 0) {
      await Future<void>.delayed(_delay);
    }
    _closed = true;
    await _inner.close();
  }

  @override
  Future<void> get done => _inner.done;
}

Future<int> timeSession(Duration oneWay, {required bool pipeline}) async {
  final raw = await SSHSocket.connect('127.0.0.1', 2225,
      timeout: const Duration(seconds: 10));
  final client = SSHClient(
    DelayedSocket(raw, oneWay),
    username: Platform.environment['USER']!,
    identities:
        SSHKeyPair.fromPem(File('/tmp/ds2-bench/client').readAsStringSync()),
    onVerifyHostKey: (h, k) => true,
    pipelineChannelRequests: pipeline,
  );
  await client.authenticated;
  final sw = Stopwatch()..start();
  final session = await client.execute('true', pty: const SSHPtyConfig());
  sw.stop();
  session.close();
  client.close();
  try {
    await client.done.timeout(const Duration(seconds: 5));
  } catch (_) {}
  return sw.elapsedMilliseconds;
}

Future<void> main() async {
  const oneWay = Duration(milliseconds: 40); // 80 ms RTT
  for (final pipeline in [false, true]) {
    final samples = <int>[];
    for (var i = 0; i < 5; i++) {
      samples.add(await timeSession(oneWay, pipeline: pipeline));
    }
    samples.sort();
    final label = pipeline ? 'pipelineChannelRequests' : 'default           ';
    print('execute() with pty at 80ms RTT, $label: '
        'samples=$samples median=${samples[2]}ms');
  }
  exit(0);
}
