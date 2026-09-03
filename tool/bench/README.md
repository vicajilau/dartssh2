# Throwaway benchmark harnesses

Not part of the package. These are the two harnesses behind the numbers in
https://github.com/vicajilau/dartssh2/issues/242 and
https://github.com/vicajilau/dartssh2/issues/243, kept on a branch so they
can be re-run rather than rewritten.

## window_adjust_count.dart

Counts `SSH_MSG_CHANNEL_WINDOW_ADJUST` messages emitted by
`SSHChannelController` for a given packet size and total transfer. No network
and no server — it drives the controller directly, so it is deterministic.

    dart run tool/bench/window_adjust_count.dart

On upstream `main` every inbound packet produces one adjust. Compare against
a branch that thresholds.

## session_setup_latency.dart

Times `execute('true', pty: SSHPtyConfig())` against a real OpenSSH server
through an `SSHSocket` wrapper that delays each direction, so the round trip
is whatever you set (40 ms each way = 80 ms RTT). It runs five sessions with
`SSHClient.pipelineChannelRequests` off and five with it on, and prints the
median of each.

Needs a throwaway sshd — never point it at a real one:

    FIX=/tmp/ds2-bench; mkdir -p "$FIX"; chmod 700 "$FIX"
    ssh-keygen -q -t ed25519 -N '' -f "$FIX/hostkey"
    ssh-keygen -q -t ed25519 -N '' -f "$FIX/client"
    cp "$FIX/client.pub" "$FIX/authorized_keys"; chmod 600 "$FIX/authorized_keys"
    cat > "$FIX/sshd.conf" <<EOF
    Port 2225
    ListenAddress 127.0.0.1
    HostKey $FIX/hostkey
    AuthorizedKeysFile $FIX/authorized_keys
    PidFile $FIX/sshd.pid
    StrictModes no
    UsePAM no
    PasswordAuthentication no
    LogLevel ERROR
    EOF
    /usr/sbin/sshd -f "$FIX/sshd.conf"
    dart run tool/bench/session_setup_latency.dart
    kill "$(cat "$FIX/sshd.pid")"

Two traps worth remembering. Delay each write independently rather than
chaining them, or the unpipelined baseline is charged a second delay it does
not actually pay and the result is flattering. And run `dart pub get` before
`dart format` — until dependencies resolve, `analysis_options.yaml` cannot
load `package:lints`, the formatter silently falls back to a different
language version, and `dart format .` rewrites all 177 files.
