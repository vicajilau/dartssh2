import 'dart:async';
import 'dart:collection';
import 'dart:typed_data';

import 'package:dartssh2/src/http/http_client.dart';
import 'package:dartssh2/src/sftp/sftp_client.dart';
import 'package:dartssh2/src/forward/dynamic_forward.dart';
import 'package:dartssh2/src/ssh_algorithm.dart';
import 'package:dartssh2/src/ssh_agent.dart';
import 'package:dartssh2/src/ssh_channel.dart';
import 'package:dartssh2/src/ssh_channel_id.dart';
import 'package:dartssh2/src/ssh_errors.dart';
import 'package:dartssh2/src/forward/ssh_forward.dart';
import 'package:dartssh2/src/ssh_keepalive.dart';
import 'package:dartssh2/src/ssh_identity.dart';
import 'package:dartssh2/src/ssh_session.dart';
import 'package:dartssh2/src/ssh_transport.dart';
import 'package:dartssh2/src/utils/async_queue.dart';
import 'package:dartssh2/src/utils/auth_methods.dart';
import 'package:dartssh2/src/utils/pending_requests.dart';
import 'package:dartssh2/src/utils/terminal_state.dart';
import 'package:dartssh2/src/message/msg_channel.dart';
import 'package:dartssh2/src/message/msg_request.dart';
import 'package:dartssh2/src/message/msg_service.dart';
import 'package:dartssh2/src/message/msg_userauth.dart';
import 'package:dartssh2/src/ssh_message.dart';
import 'package:dartssh2/src/socket/ssh_socket.dart';
import 'package:dartssh2/src/ssh_userauth.dart';
import 'package:meta/meta.dart';

/// https://datatracker.ietf.org/doc/html/rfc4252#section-8
typedef SSHPasswordRequestHandler = FutureOr<String?> Function();

typedef SSHChangePasswordRequestHandler = FutureOr<SSHChangePasswordResponse?>
    Function(String prompt);

/// https://datatracker.ietf.org/doc/html/rfc4256#section-3.3
typedef SSHUserInfoRequestHandler = FutureOr<List<String>?> Function(
  SSHUserInfoRequest request,
);

/// https://datatracker.ietf.org/doc/html/rfc4252#section-5.4
typedef SSHUserauthBannerHandler = void Function(String banner);

typedef SSHAuthenticatedHandler = void Function();

typedef SSHRemoteConnectionFilter = bool Function(String host, int port);

typedef SSHX11ForwardHandler = void Function(SSHX11Channel channel);

// /// Function called when the host has sent additional host keys after the initial
// /// key exchange.
// typedef SSHHostKeysHandler = void Function(List<Uint8List>);

const _initialWindowSize = 1024 * 1024 * 2;

const _maximumPacketSize = 32768;

class SSHPtyConfig {
  /// Type of terminal, for example 'xterm', 'xterm-256color'.
  final String type;

  /// Width of the terminal in number of columns.
  final int width;

  /// Height of the terminal in number of rows.
  final int height;

  /// Width of the terminal in pixels. 0 if unknown.
  final int pixelWidth;

  /// Height of the terminal in pixels. 0 if unknown.
  final int pixelHeight;

  const SSHPtyConfig({
    this.type = 'xterm-256color',
    this.width = 80,
    this.height = 24,
    this.pixelWidth = 0,
    this.pixelHeight = 0,
  });
}

class SSHX11Config {
  /// Whether only a single forwarded X11 connection should be accepted.
  final bool singleConnection;

  /// X11 authentication protocol name.
  final String authenticationProtocol;

  /// X11 authentication cookie value.
  final String authenticationCookie;

  /// X11 screen number.
  final int screenNumber;

  const SSHX11Config({
    required this.authenticationCookie,
    this.singleConnection = false,
    this.authenticationProtocol = 'MIT-MAGIC-COOKIE-1',
    this.screenNumber = 0,
  });
}

class SSHRunResult {
  /// Combined output stream based on [SSHClient.runWithResult] capture flags.
  final Uint8List output;

  /// Captured stdout bytes. Empty when stdout capture is disabled.
  final Uint8List stdout;

  /// Captured stderr bytes. Empty when stderr capture is disabled.
  final Uint8List stderr;

  /// Exit code reported by the remote process if available.
  final int? exitCode;

  /// Exit signal reported by the remote process if available.
  final SSHSessionExitSignal? exitSignal;

  const SSHRunResult({
    required this.output,
    required this.stdout,
    required this.stderr,
    required this.exitCode,
    required this.exitSignal,
  });
}

/// One of the channel requests that set up a session, with the description
/// used in the error message when the server refuses it.
class _SessionRequest {
  _SessionRequest(this.description, this.send, {this.required = false});

  /// Completes the sentence "Failed to ...".
  final String description;

  /// Sends the request and returns its reply. A thunk rather than a started
  /// future, so that the default path still sends nothing after a refusal.
  final Future<bool> Function() send;

  /// Whether a refusal fails the call even with
  /// [SSHClient.pipelineChannelRequests] set. True for the exec or shell
  /// request, which is the point of the call and has run nothing when it is
  /// refused.
  final bool required;
}

/// The reply to one channel request, kept as a value rather than as a future
/// so that a pipeline of them can be inspected in issue order.
typedef _SessionRequestOutcome = ({
  bool? accepted,
  Object? error,
  StackTrace? stackTrace,
});

class SSHClient {
  final SSHSocket socket;

  /// The username to authenticate as.
  final String username;

  /// Function invoked with debug messages.
  final SSHPrintHandler? printDebug;

  /// Function invoked with network traffic messages.
  final SSHPrintHandler? printTrace;

  /// Crypto algorithms available for the client.
  final SSHAlgorithms algorithms;

  /// Function called when the first host key is received. The callback receives
  /// the host key type and fingerprint, and should return true to accept the key
  /// or false to reject it and close the connection. If this is null, all host
  /// keys are accepted automatically. Warning: the signature check alone only
  /// proves the peer owns the key it presented, not that it is the expected host.
  /// Leaving this null exposes the connection to man-in-the-middle attacks. Supply
  /// this callback and verify the fingerprint against a known-hosts entry or a
  /// trusted certificate store.
  final SSHHostkeyVerifyHandler? onVerifyHostKey;

  /// List of identities (key pairs or external signers) to use for
  /// authentication. Set this field to enable authentication with public key.
  final List<SSHIdentity>? identities;

  /// Identities to use for RFC 4252 hostbased authentication.
  ///
  /// Unlike [identities], these represent keys belonging to the client host,
  /// not the user logging in to the server.
  final List<SSHIdentity>? hostbasedIdentities;

  /// Fully qualified client host name sent during hostbased authentication.
  final String? hostName;

  /// Local account name sent during hostbased authentication.
  final String? userNameOnClientHost;

  /// Set this field to enable the 'password' authentication method. Return null
  /// to skip to the next available authentication method.
  final SSHPasswordRequestHandler? onPasswordRequest;

  /// Set this field to enable setting new passwords when the server requests
  /// changing password when using the 'password' authentication method. Return
  /// null to skip to the next available authentication method.
  final SSHChangePasswordRequestHandler? onChangePasswordRequest;

  /// Set this field to enable the 'keyboard-interactive' authentication method.
  /// This may be called multiple times to request additional prompts. Return
  /// null to skip to the next available authentication method.
  final SSHUserInfoRequestHandler? onUserInfoRequest;

  /// The SSH server may send banner message at any time before authentication
  /// is successful. Set this field to receive the banner message.
  final SSHUserauthBannerHandler? onUserauthBanner;

  /// A [Future] that completes normally when the client is connected to the
  // Future<void> get handshake => _handshakeCompleter.future;

  /// Function called when authentication is complete.
  final SSHAuthenticatedHandler? onAuthenticated;

  /// Function called when the server opens an incoming forwarded X11 channel.
  final SSHX11ForwardHandler? onX11Forward;

  /// Optional handler for SSH agent forwarding requests.
  final SSHAgentHandler? agentHandler;

  /// The interval at which to send a keep-alive message through the [ping]
  /// method. Set this to null to disable automatic keep-alive messages.
  final Duration? keepAliveInterval;

  /// Maximum time to wait for the SSH transport handshake to complete.
  final Duration? handshakeTimeout;

  /// Maximum time to wait for authentication after the transport is ready.
  final Duration? authTimeout;

  /// Function called when additional host keys are received. This is an OpenSSH
  /// extension. May not be called if the server does not support the extension.
  // final SSHHostKeysHandler? onHostKeys;

  /// Allow to disable hostkey verification, which can be slow in debug mode.
  final bool disableHostkeyVerification;

  /// Send all of a session's channel requests before reading any reply, and
  /// report a refused one instead of throwing.
  ///
  /// [execute] and [shell] send `env`, agent forwarding, `pty-req` and
  /// `x11-req` before `exec` or `shell`, and by default wait for each reply
  /// before sending the next request, so setting up a session costs one round
  /// trip per request. With this set they go out back to back, which RFC 4254
  /// §5.4 permits and `ssh(1)` does; §4 requires the peer to answer the
  /// requests on a channel in the order it received them, so the replies still
  /// line up. Against a server 40 ms away, `execute` with a pty measured
  /// 246 ms before and 206 ms after.
  ///
  /// **A refused request no longer stops the command running.** It is already
  /// on the wire when the refusal arrives, so it cannot be held back: against
  /// a server with `PermitTTY no`, `execute` runs the command and reports the
  /// refused `pty-req` through [printDebug], the way `ssh(1)` prints
  /// `PTY allocation request failed on channel 0` and carries on. A refused
  /// environment variable, agent forwarding or X11 request is treated the same
  /// way. Only a refused `exec` or `shell` still throws
  /// [SSHChannelRequestError], because nothing has run when that one fails.
  ///
  /// Leave this false if the caller relies on [execute] throwing *before* the
  /// command runs.
  final bool pipelineChannelRequests;

  /// Identification string advertised during the SSH version exchange (the part
  /// after `SSH-2.0-`). Defaults to `'DartSSH_2.0'`
  final String ident;

  /// A [Future] that completes when the transport is closed, or when an error
  /// occurs. After this [Future] completes, [isClosed] will be true and no more
  /// data can be sent or received.
  Future<void> get done => _transport.done;

  /// true if the connection is closed normally or due to an error.
  bool get isClosed => _transport.isClosed;

  SSHClient(
    this.socket, {
    required this.username,
    this.printDebug,
    this.printTrace,
    this.algorithms = const SSHAlgorithms(),
    this.onVerifyHostKey,
    this.identities,
    this.hostbasedIdentities,
    this.hostName,
    this.userNameOnClientHost,
    this.onPasswordRequest,
    this.onChangePasswordRequest,
    this.onUserInfoRequest,
    this.onUserauthBanner,
    this.onAuthenticated,
    this.onX11Forward,
    this.agentHandler,
    this.keepAliveInterval = const Duration(seconds: 10),
    this.handshakeTimeout,
    this.authTimeout,
    this.disableHostkeyVerification = false,
    this.pipelineChannelRequests = false,
    String ident = 'DartSSH_2.0',
  }) : ident = _validateIdent(ident) {
    _transport = SSHTransport(
      socket,
      isServer: false,
      printDebug: printDebug,
      printTrace: printTrace,
      algorithms: algorithms,
      onVerifyHostKey: onVerifyHostKey,
      onReady: _handleTransportReady,
      onMessage: _handlePacket,
      disableHostkeyVerification: disableHostkeyVerification,
      version: ident,
    );

    _transport.done.then(
      (_) => _handleTransportClosed(null),
      onError: (Object error, StackTrace stackTrace) => _handleTransportClosed(
        error is SSHError ? error : SSHSocketError(error),
        stackTrace,
      ),
    );

    _authenticated.future.catchError(
      (error, stackTrace) => _transport.closeWithError(error, stackTrace),
    );

    if (identities != null) {
      _identitiesLeft.addAll(identities!);
    }

    if (hostbasedIdentities != null) {
      _hostbasedIdentitiesLeft.addAll(hostbasedIdentities!);
    }

    final handshakeTimeout = this.handshakeTimeout;
    if (handshakeTimeout != null) {
      _handshakeTimeoutTimer = Timer(handshakeTimeout, _handleHandshakeTimeout);
    }
  }

  static String _validateIdent(String ident) {
    if (ident.isEmpty) {
      throw ArgumentError.value(
        ident,
        'ident',
        'must not be empty',
      );
    }

    if (ident.contains('\r') || ident.contains('\n')) {
      throw ArgumentError.value(
        ident,
        'ident',
        'must not contain carriage return or newline characters',
      );
    }

    return ident;
  }

  late final SSHTransport _transport;

  /// A [Completer] that completes when the client has authenticated, or
  /// completes with an error if the client could not authenticate.
  final _authenticated = Completer<void>();

  final _terminalState = TerminalState();

  late final _globalRequestReplyQueue = AsyncQueue<SSHMessage>(
    terminalState: _terminalState,
  );

  final _channelIdAllocator = SSHChannelIdAllocator();

  /// Channels for which SSH_MSG_CHANNEL_OPEN has been sent and a matching
  /// confirmation or failure has not yet been received.
  late final _pendingChannelOpens =
      PendingRequests<SSHChannelId, SSHChannelController>(
    terminalState: _terminalState,
  );

  final _channels = <int, SSHChannelController>{};

  final _authMethodsLeft = Queue<SSHAuthMethod>();

  final _preferredAuthMethods = <SSHAuthMethod>[];

  final _exhaustedAuthMethods = <SSHAuthMethod>{};

  final _identitiesLeft = Queue<SSHIdentity>();

  final _hostbasedIdentitiesLeft = Queue<SSHIdentity>();

  final _remoteForwards = <SSHRemoteForward>{};

  late final _keepAlive = keepAliveInterval != null
      ? SSHKeepAlive(ping: ping, interval: keepAliveInterval!)
      : null;

  SSHAuthMethod? _currentAuthMethod;

  SSHIdentity? _currentProbedIdentity;

  var _transportReady = false;

  Timer? _handshakeTimeoutTimer;

  Timer? _authTimeoutTimer;

  /// A [Future] that completes when the client has authenticated, or
  /// completes with an error if the client could not authenticate.
  Future<void> get authenticated => _authenticated.future;

  /// Identification string sent by the other side. For example,
  /// "SSH-2.0-OpenSSH_7.4p1". May be null if the handshake has not yet
  /// completed.
  String? get remoteVersion => _transport.remoteVersion;

  /// Whether strict key exchange is in effect for this connection.
  ///
  /// It is negotiated automatically and requires the server to support it too.
  /// Strict key exchange is the countermeasure against the Terrapin attack
  /// (CVE-2023-48795), so a `false` here on an untrusted network means the
  /// connection is only as safe as the negotiated cipher makes it.
  ///
  /// Meaningless before the first key exchange completes.
  bool get strictKex => _transport.strictKex;

  /// The signature algorithms the server accepts for `publickey`
  /// authentication, taken from the `server-sig-algs` extension of
  /// SSH_MSG_EXT_INFO (RFC 8308 §3.1).
  ///
  /// `null` when the server sent no EXT_INFO or omitted the extension.
  List<String>? get serverSigAlgs => _transport.serverSigAlgs;

  /// Request connections to a port on the other side be forwarded to the local
  /// side.
  /// Set [host] to null to listen on all interfaces, `"0.0.0.0"` to
  /// listen on all IPv4 interfaces, `"::"` to listen on all IPv6 interfaces,
  /// and `"localhost"` to listen on the loopback interface on all protocols.
  /// Set [port] to null to listen on a random port.
  Future<SSHRemoteForward?> forwardRemote({
    String? host,
    int? port,
    SSHRemoteConnectionFilter? filter,
  }) async {
    await _authenticated.future;

    // Lisning on all interfaces if not specified.
    host ??= '';

    // Lisning on a random port if not specified.
    port ??= 0;

    final reply = await _sendGlobalRequest(
      SSH_Message_Global_Request.tcpipForward(host, port),
    );

    if (reply is SSH_Message_Request_Failure) return null;

    if (reply is! SSH_Message_Request_Success) {
      throw SSHStateError('Unexpected reply to tcpip-forward request: $reply');
    }

    final reader = SSHMessageReader(reply.requestData);
    final assignedPort = port != 0 ? port : reader.readUint32();

    final remoteForward = SSHRemoteForward(this, host, assignedPort, filter);
    _remoteForwards.add(remoteForward);

    return remoteForward;
  }

  /// Cancel a previous request to forward connections to a port on the other
  /// side. Returns [true] if successful, [false] otherwise.
  /// See also: [forwardRemote].
  Future<bool> cancelForwardRemote(SSHRemoteForward forward) async {
    await _authenticated.future;

    if (!_remoteForwards.remove(forward)) return false;

    final reply = await _sendGlobalRequest(
      SSH_Message_Global_Request.cancelTcpipForward(
        bindAddress: forward.host,
        bindPort: forward.port,
      ),
    );

    if (reply is SSH_Message_Request_Failure) {
      return false;
    }

    return true;
  }

  /// Forward connections to a [localHost]:[localPort] to [remoteHost]:[remotePort]
  /// [localHost] and [localPort] are only required by the protocol and do not
  /// need to be specified in most cases.
  Future<SSHForwardChannel> forwardLocal(
    String remoteHost,
    int remotePort, {
    String localHost = 'localhost',
    int localPort = 0,
  }) async {
    await _authenticated.future;
    final channelController = await _openForwardLocalChannel(
      localHost,
      localPort,
      remoteHost,
      remotePort,
    );
    return SSHForwardChannel(channelController.channel);
  }

  /// Start a local SOCKS5 server that forwards outbound `CONNECT` requests
  /// through this SSH connection.
  ///
  /// This is similar to `ssh -D`. Only SOCKS5 with `NO AUTH` and `CONNECT`
  /// is supported. Use [filter] to optionally deny specific target
  /// destinations. Use [options] to tune timeouts and connection limits.
  ///
  /// Not supported on platforms without `dart:io`.
  Future<SSHDynamicForward> forwardDynamic({
    String bindHost = '127.0.0.1',
    int? bindPort,
    SSHDynamicForwardOptions options = const SSHDynamicForwardOptions(),
    SSHDynamicConnectionFilter? filter,
  }) async {
    await _authenticated.future;
    return startDynamicForward(
      bindHost: bindHost,
      bindPort: bindPort,
      options: options,
      filter: filter,
      dial: forwardLocal,
    );
  }

  /// Forward local connections to a remote Unix domain socket at [remoteSocketPath] on the
  /// remote side via a `direct-streamlocal@openssh.com` channel.
  ///
  /// This is the equivalent of `ssh -L localPort:remoteSocketPath`.
  Future<SSHForwardChannel> forwardLocalUnix(
    String remoteSocketPath,
  ) async {
    await _authenticated.future;
    final channelController = await _openForwardLocalUnixChannel(
      remoteSocketPath,
    );
    return SSHForwardChannel(channelController.channel);
  }

  /// Execute [command] on the remote side. Returns a [SSHChannel] that can be
  /// used to read and write to the remote side.
  Future<SSHSession> execute(
    String command, {
    SSHPtyConfig? pty,
    SSHX11Config? x11,
    Map<String, String>? environment,
  }) async {
    await _authenticated.future;

    final channelController = await _openSessionChannel();

    await _setUpSession(
      channelController,
      _sessionSetupRequests(
        channelController,
        pty: pty,
        x11: x11,
        environment: environment,
      ).followedBy([
        _SessionRequest(
          'execute',
          () => channelController.sendExec(command),
          required: true,
        ),
      ]),
    );

    return SSHSession(channelController.channel);
  }

  /// Start a shell on the remote side. Returns a [SSHSession] that can be
  /// used to read, write and control the pty on the remote side.
  Future<SSHSession> shell({
    SSHPtyConfig? pty = const SSHPtyConfig(),
    SSHX11Config? x11,
    Map<String, String>? environment,
  }) async {
    await _authenticated.future;

    final channelController = await _openSessionChannel();

    await _setUpSession(
      channelController,
      _sessionSetupRequests(
        channelController,
        pty: pty,
        x11: x11,
        environment: environment,
      ).followedBy([
        _SessionRequest(
          'start shell',
          channelController.sendShell,
          required: true,
        ),
      ]),
    );

    return SSHSession(channelController.channel);
  }

  /// The channel requests that configure a session before the exec or shell
  /// request that follows them. The order is the order they go on the wire.
  ///
  /// Lazy on purpose, and consumed lazily by the sequential path in
  /// [_setUpSession], so that naming the requests changes nothing about when
  /// [environment] is read: an entry is taken from the map, sent, and its
  /// reply awaited before the map is asked for the next one, which is what
  /// the code this replaces did by awaiting inside `for (final pair in
  /// environment.entries)`. Materialising them up front would read the whole
  /// map before anything reached the wire, so a map whose iterator throws
  /// part way through would fail with nothing sent rather than after the
  /// entries before it, and a map mutated while the session is being set up
  /// would be read at different points than it used to be.
  Iterable<_SessionRequest> _sessionSetupRequests(
    SSHChannelController channel, {
    required SSHPtyConfig? pty,
    required SSHX11Config? x11,
    required Map<String, String>? environment,
  }) sync* {
    if (environment != null) {
      for (final pair in environment.entries) {
        yield _SessionRequest(
          'set environment variable: ${pair.key}',
          () => channel.sendEnv(pair.key, pair.value),
        );
      }
    }

    if (agentHandler != null) {
      yield _SessionRequest(
        'request agent forwarding',
        channel.sendAgentForwardingRequest,
      );
    }

    if (pty != null) {
      yield _SessionRequest(
        'start pty',
        () => channel.sendPtyReq(
          terminalType: pty.type,
          terminalWidth: pty.width,
          terminalHeight: pty.height,
          terminalPixelWidth: pty.pixelWidth,
          terminalPixelHeight: pty.pixelHeight,
        ),
      );
    }

    if (x11 != null) {
      yield _SessionRequest(
        'request x11 forwarding',
        () => channel.sendX11Req(
          singleConnection: x11.singleConnection,
          authenticationProtocol: x11.authenticationProtocol,
          authenticationCookie: x11.authenticationCookie,
          screenNumber: x11.screenNumber,
        ),
      );
    }
  }

  /// Issues [requests] on [channel] and reports the first one that fails.
  ///
  /// Without [pipelineChannelRequests] each request waits for its reply before
  /// the next one is sent, so a refusal means the requests after it were never
  /// sent at all. With it, everything is sent first and the replies are read
  /// afterwards; see the flag for what that changes.
  ///
  /// [requests] is an [Iterable] rather than a [List] so that the sequential
  /// path below advances it one request at a time; see [_sessionSetupRequests]
  /// for why that matters.
  Future<void> _setUpSession(
    SSHChannelController channel,
    Iterable<_SessionRequest> requests,
  ) async {
    if (!pipelineChannelRequests) {
      // Each request is taken from [requests] only once the one before it has
      // been answered, so nothing past a refusal is even constructed, let
      // alone sent.
      for (final request in requests) {
        if (!await request.send()) {
          channel.close();
          throw SSHChannelRequestError('Failed to ${request.description}');
        }
      }
      return;
    }

    // Pipelining needs to know the whole set before it transmits any of it, so
    // this is the one path that reads [requests] to the end up front. If that
    // fails nothing has gone out, which is the same all-or-nothing the
    // sequential path gives for a request it never reaches.
    final pipelined = requests.toList(growable: false);

    // Send everything before reading a single reply. SSHChannelController
    // reserves a request's slot in its FIFO reply queue before it transmits,
    // and RFC 4254 §4 requires the peer to answer the requests on a channel in
    // the order it received them, so the replies still line up with [requests]
    // one for one.
    //
    // Each outcome is captured the moment the request is issued. Attaching the
    // handler only when the loop below reaches it would let a reply that fails
    // while an earlier one is still outstanding escape as an unhandled
    // asynchronous error.
    final outcomes = [
      for (final request in pipelined)
        request.send().then<_SessionRequestOutcome>(
              (accepted) => (accepted: accepted, error: null, stackTrace: null),
              onError: (Object error, StackTrace stackTrace) =>
                  (accepted: null, error: error, stackTrace: stackTrace),
            ),
    ];

    // Deliberately not Future.wait, which propagates whichever error arrives
    // first rather than the first request that went wrong: a channel that dies
    // before the exec reply would hide a pty-req refusal that had already come
    // back, and report an SSHStateError where the unpipelined path reports
    // SSHChannelRequestError('Failed to start pty').
    for (var i = 0; i < outcomes.length; i++) {
      final request = pipelined[i];
      final outcome = await outcomes[i];

      final error = outcome.error;
      if (error != null) {
        Error.throwWithStackTrace(error, outcome.stackTrace!);
      }

      if (outcome.accepted!) continue;

      if (request.required) {
        channel.close();
        throw SSHChannelRequestError('Failed to ${request.description}');
      }

      printDebug?.call(
        'SSHClient._setUpSession: the server refused to '
        '${request.description}, continuing',
      );
    }
  }

  Future<void> subsystem(String subsystem) async {
    await _authenticated.future;

    final channelController = await _openSessionChannel();
    channelController.sendSubsystem(subsystem);
  }

  /// Open a new SFTP session. Returns a [SftpClient] that can be used to
  /// interact with the remote side.
  Future<SftpClient> sftp() async {
    await _authenticated.future;

    final channelController = await _openSessionChannel();
    channelController.sendSubsystem('sftp');

    return SftpClient(
      channelController.channel,
      printDebug: printDebug,
      printTrace: printTrace,
    );
  }

  /// Create a new [SSHHttpClient] that can be used to make HTTP requests
  /// that are tunneled over the SSH connection. The returned [SSHHttpClient]
  /// is a very basic implementation, only intended for making simple requests.
  SSHHttpClient httpClient() {
    return SSHHttpClient(this);
  }

  /// Execute [command] on the remote side non-interactively. Returns a
  /// [Future<Uint8List>] that completes with the combined command output.
  /// This is a convenience method over [execute]. If [stdout] is false,
  /// the standard output of the command will be ignored. If [stderr] is
  /// false, the standard error of the command will be ignored.
  ///
  /// Use [runWithResult] when you need separate stdout/stderr bytes or exit
  /// metadata (`exitCode`/`exitSignal`).
  Future<Uint8List> run(
    String command, {
    bool runInPty = false,
    bool stdout = true,
    bool stderr = true,
    Map<String, String>? environment,
  }) async {
    final result = await runWithResult(
      command,
      runInPty: runInPty,
      stdout: stdout,
      stderr: stderr,
      environment: environment,
    );

    return result.output;
  }

  /// Execute [command] on the remote side non-interactively and return
  /// output together with exit metadata.
  ///
  /// If the standard output or standard error stream emits an error, the
  /// session is closed and that error is rethrown to the caller.
  Future<SSHRunResult> runWithResult(
    String command, {
    bool runInPty = false,
    bool stdout = true,
    bool stderr = true,
    Map<String, String>? environment,
  }) async {
    final session = await execute(
      command,
      pty: runInPty ? const SSHPtyConfig() : null,
      environment: environment,
    );

    final outputBuilder = BytesBuilder(copy: false);
    final stdoutBuilder = BytesBuilder(copy: false);
    final stderrBuilder = BytesBuilder(copy: false);
    final stdoutDone = Completer<void>();
    final stderrDone = Completer<void>();

    final stdoutSubscription = session.stdout.listen(
      stdout
          ? (data) {
              outputBuilder.add(data);
              stdoutBuilder.add(data);
            }
          : (_) {},
      onDone: stdoutDone.complete,
      onError: stdoutDone.completeError,
      cancelOnError: true,
    );

    final stderrSubscription = session.stderr.listen(
      stderr
          ? (data) {
              outputBuilder.add(data);
              stderrBuilder.add(data);
            }
          : (_) {},
      onDone: stderrDone.complete,
      onError: stderrDone.completeError,
      cancelOnError: true,
    );

    // Both futures must be awaited together. Awaiting them one after the other
    // would leave the second one without an error handler until the first one
    // completes, turning an error on that stream into an uncaught error.
    try {
      await Future.wait(
        [stdoutDone.future, stderrDone.future],
        eagerError: true,
      );
      await session.done;
    } catch (_) {
      await stdoutSubscription.cancel();
      await stderrSubscription.cancel();
      session.close();
      rethrow;
    }

    return SSHRunResult(
      output: outputBuilder.takeBytes(),
      stdout: stdoutBuilder.takeBytes(),
      stderr: stderrBuilder.takeBytes(),
      exitCode: session.exitCode,
      exitSignal: session.exitSignal,
    );
  }

  /// Send a empty message to the server to keep the connection alive.
  Future<void> ping() async {
    await _authenticated.future;
    await _sendGlobalRequest(SSH_Message_Global_Request.keepAlive());
  }

  /// Shutdown the entire SSH connection. Sessions and channels will also be
  /// closed immediately.
  Future<void> close() async {
    _handshakeTimeoutTimer?.cancel();
    _authTimeoutTimer?.cancel();
    final error = SSHStateError('SSH client closed');
    _terminatePendingOperations(error);
    _closeChannels(error);
    await _transport.close();
  }

  /// Force flush any buffered outgoing data to the socket.
  Future<void> flush() async {
    await _transport.flush();
  }

  /// Starts a new key exchange on an established connection, refreshing the
  /// session keys.
  ///
  /// Outgoing packets are buffered until the exchange completes, so channels
  /// and sessions keep working across it. A no-op while a key exchange is
  /// already in progress. The server may also start one on its own.
  ///
  /// The host key is re-checked against the one already accepted for this
  /// connection, and a mismatch terminates the connection with an
  /// [SSHHostkeyError]; [onVerifyHostKey] is not consulted again.
  ///
  /// The returned future completes once the new keys are in effect. If an
  /// exchange is already running, whether this side or the server started it,
  /// no second one is sent and the future tracks the exchange in flight. If
  /// the connection ends first the future completes with the error that ended
  /// it, so awaiting this is enough to notice a failed rekey without watching
  /// [done].
  Future<void> rekey() {
    return _transport.rekey();
  }

  /// Close all channels that are currently open.
  void _closeChannels([Object? error, StackTrace? stackTrace]) {
    for (final channel in _channels.values) {
      channel.destroy(error, stackTrace);
      _channelIdAllocator.release(channel.localId);
    }

    _channels.clear();
  }

  void _handleTransportReady() {
    printDebug?.call('SSHClient._onTransportReady');
    _transportReady = true;
    _handshakeTimeoutTimer?.cancel();
    _handshakeTimeoutTimer = null;

    final authTimeout = this.authTimeout;
    if (authTimeout != null) {
      _authTimeoutTimer = Timer(authTimeout, _handleAuthTimeout);
    }

    _requestAuthentication();
  }

  void _handleTransportClosed(SSHError? error, [StackTrace? stackTrace]) {
    printDebug?.call('SSHClient._onTransportClosed');
    _handshakeTimeoutTimer?.cancel();
    _handshakeTimeoutTimer = null;
    _authTimeoutTimer?.cancel();
    _authTimeoutTimer = null;

    if (!_authenticated.isCompleted) {
      _authenticated.completeError(
        SSHAuthAbortError('Connection closed before authentication', error),
      );
    }
    _keepAlive?.stop();

    final terminalError = error ?? SSHStateError('SSH connection closed');
    _terminatePendingOperations(terminalError, stackTrace);

    try {
      _closeChannels(terminalError, stackTrace);
    } catch (e) {
      printDebug?.call("SSHClient::_handleTransportClosed - error: $e");
    }
  }

  void _terminatePendingOperations(Object error, [StackTrace? stackTrace]) {
    _globalRequestReplyQueue.closeWithError(error, stackTrace);

    for (final id in _pendingChannelOpens.keys) {
      _channelIdAllocator.release(id);
    }
    _pendingChannelOpens.closeWithError(error, stackTrace);
  }

  Future<SSHMessage> _sendGlobalRequest(SSHMessage request) async {
    final reply = _globalRequestReplyQueue.next;
    try {
      _sendMessage(request);
    } catch (error, stackTrace) {
      _terminatePendingOperations(error, stackTrace);
    }
    return await reply;
  }

  bool _handlePacket(Uint8List payload) {
    try {
      return _dispatchMessage(payload);
    } catch (e) {
      rethrow;
    }
  }

  /// Handles a raw SSH packet. This method is only exposed for testing purposes.
  @visibleForTesting
  void handlePacket(Uint8List packet) => _handlePacket(packet);

  /// Sets the session ID on transport. This method is only exposed for testing purposes.
  @visibleForTesting
  set sessionId(Uint8List? value) => _transport.sessionId = value;

  void _sendMessage(SSHMessage message) {
    printTrace?.call('-> $socket: $message');
    _transport.sendPacket(message.encode());
  }

  void _catch(FutureOr<dynamic> Function() fn) {
    Future.sync(fn).catchError((e, st) {
      _transport.closeWithError(SSHInternalError(e), st);
    });
  }

  bool _dispatchMessage(Uint8List message) {
    final messageId = SSHMessage.readMessageId(message);
    switch (messageId) {
      case SSH_Message_Service_Accept.messageId:
        _handleServiceAccept(message);
        return true;
      case SSH_Message_Userauth_Success.messageId:
        _handleUserauthSuccess();
        return true;
      case SSH_Message_Userauth_Failure.messageId:
        _handleUserauthFailure(message);
        return true;
      case SSH_Message_Userauth_Passwd_ChangeReq.messageId:
        _handleUserauthIntermidiate(message);
        return true;
      case SSH_Message_Userauth_Banner.messageId:
        _handleUserauthBanner(message);
        return true;
      case SSH_Message_Global_Request.messageId:
        _handleGlobalRequest(message);
        return true;
      case SSH_Message_Request_Success.messageId:
        _handleGlobalRequestSuccess(message);
        return true;
      case SSH_Message_Request_Failure.messageId:
        _handleGlobalRequestFailure(message);
        return true;
      case SSH_Message_Channel_Open.messageId:
        _handleChannelOpen(message);
        return true;
      case SSH_Message_Channel_Confirmation.messageId:
        _handleChannelConfirmation(message);
        return true;
      case SSH_Message_Channel_Open_Failure.messageId:
        _handleChannelOpenFailure(message);
        return true;
      case SSH_Message_Channel_Window_Adjust.messageId:
        _handleChannelWindowAdjust(message);
        return true;
      case SSH_Message_Channel_Success.messageId:
        _handleChannelSuccess(message);
        return true;
      case SSH_Message_Channel_Failure.messageId:
        _handleChannelFailure(message);
        return true;
      case SSH_Message_Channel_Data.messageId:
        _handleChannelData(message);
        return true;
      case SSH_Message_Channel_Extended_Data.messageId:
        _handleChannelExtendedData(message);
        return true;
      case SSH_Message_Channel_EOF.messageId:
        _handleChannelEOF(message);
        return true;
      case SSH_Message_Channel_Close.messageId:
        _handleChannelClose(message);
        return true;
      case SSH_Message_Channel_Request.messageId:
        _handleChannelRequest(message);
        return true;
      default:
        printDebug?.call('unknown messageId: $messageId');
        return false;
    }
  }

  void _handleServiceAccept(Uint8List payload) {
    final message = SSH_Message_Service_Accept.decode(payload);
    printTrace?.call('<- $socket: $message');

    switch (message.serviceName) {
      case 'ssh-userauth':
        return _startAuthentication();
      default:
        printDebug?.call('unknown serviceName: ${message.serviceName}');
    }
  }

  void _handleUserauthSuccess() {
    printTrace?.call('<- $socket: SSH_Message_Userauth_Success');
    printDebug?.call('SSHClient._handleUserauthSuccess');
    _authTimeoutTimer?.cancel();
    _authTimeoutTimer = null;
    _authenticated.complete();
    onAuthenticated?.call();
    _keepAlive?.start();
  }

  void _handleHandshakeTimeout() {
    if (_authenticated.isCompleted || _transportReady) return;

    _handshakeTimeoutTimer = null;
    final error = SSHHandshakeError('Handshake timed out');
    _authenticated.completeError(error, StackTrace.current);
  }

  void _handleAuthTimeout() {
    if (_authenticated.isCompleted) return;

    _authTimeoutTimer = null;
    _authenticated.completeError(
      SSHAuthAbortError('Authentication timed out'),
      StackTrace.current,
    );
  }

  void _handleUserauthFailure(Uint8List payload) {
    final message = SSH_Message_Userauth_Failure.decode(payload);
    printTrace?.call('<- $socket: $message');
    printDebug?.call('SSHClient._handleUserauthFailure');
    _currentProbedIdentity = null;

    if (message.partialSuccess) {
      printDebug?.call(
        'Authentication partially succeeded with '
        '${_currentAuthMethod?.name}',
      );
      _resetAuthStateForNextFactor();
    } else {
      _markCurrentAuthMethodAttempted();
    }

    final continuableMethods = selectContinuableAuthMethods(
      preferredMethods: _preferredAuthMethods,
      serverMethods: message.methodsLeft,
      availableMethods: _availableAuthMethods,
      onNote: printDebug,
    );
    _authMethodsLeft
      ..clear()
      ..addAll(continuableMethods);

    _tryNextAuthMethod();
  }

  void _handleUserauthIntermidiate(Uint8List payload) {
    printDebug?.call('SSHClient._handleUserauthIntermidiate');

    switch (_currentAuthMethod) {
      case SSHAuthMethod.password:
        return _catch(() => _handleUserauthPasswordChangeRequest(payload));
      case SSHAuthMethod.keyboardInteractive:
        return _catch(() => _handleUserauthInfoRequest(payload));
      case SSHAuthMethod.publicKey:
        return _catch(() => _handleUserauthPKOk(payload));
      default:
        printDebug?.call('unknown auth method: $_currentAuthMethod');
    }
  }

  Future<void> _handleUserauthPKOk(Uint8List payload) async {
    printDebug?.call('SSHClient._handleUserauthPKOk');
    final message = SSH_Message_Userauth_PK_Ok.decode(payload);
    printTrace?.call('<- $socket: $message');

    final identity = _currentProbedIdentity;
    if (identity == null) return;
    _currentProbedIdentity = null;

    final publicKeyBlob = identity.toPublicKey().encode();
    final challenge = _transport.composeChallenge(
      username: username,
      service: 'ssh-connection',
      publicKeyAlgorithm: identity.type,
      publicKey: publicKeyBlob,
    );

    final signature = await identity.sign(challenge);

    if (isClosed || _currentAuthMethod != SSHAuthMethod.publicKey) {
      return;
    }

    _sendMessage(
      SSH_Message_Userauth_Request.publicKey(
        username: username,
        publicKeyAlgorithm: identity.type,
        publicKey: publicKeyBlob,
        signature: signature.encode(),
      ),
    );
  }

  Future<void> _handleUserauthPasswordChangeRequest(Uint8List payload) async {
    printDebug?.call('SSHClient._handleUserauthPasswordChangeRequest');
    final message = SSH_Message_Userauth_Passwd_ChangeReq.decode(payload);
    printTrace?.call('<- $socket: $message');

    final response = await onChangePasswordRequest!(message.prompt);
    if (response == null) {
      _exhaustedAuthMethods.add(SSHAuthMethod.password);
      return _tryNextAuthMethod();
    }

    _sendMessage(SSH_Message_Userauth_Request.newPassword(
      user: username,
      oldPassword: response.oldPassword,
      newPassword: response.newPassword,
    ));
  }

  Future<void> _handleUserauthInfoRequest(Uint8List payload) async {
    printDebug?.call('SSHClient._handleUserauthInfoRequest');
    final message = SSH_Message_Userauth_InfoRequest.decode(payload);
    printTrace?.call('<- $socket: $message');

    final responses = await onUserInfoRequest!(
      SSHUserInfoRequest(message.name, message.instruction, message.prompts),
    );

    if (responses == null) {
      _exhaustedAuthMethods.add(SSHAuthMethod.keyboardInteractive);
      return _tryNextAuthMethod();
    }

    if (responses.length != message.prompts.length) {
      throw ArgumentError(
        'responses.length (${responses.length}) != message.prompts.length (${message.prompts.length})',
      );
    }

    _sendMessage(SSH_Message_Userauth_InfoResponse(responses: responses));
  }

  void _handleUserauthBanner(Uint8List payload) {
    final message = SSH_Message_Userauth_Banner.decode(payload);
    printDebug?.call('<- $socket: $message');
    onUserauthBanner?.call(message.message);
  }

  void _handleGlobalRequest(Uint8List payload) {
    final message = SSH_Message_Global_Request.decode(payload);
    printTrace?.call('<- $socket: $message');

    // Currently we don't support any global requests on the client side.
    if (message.wantReply) {
      _sendMessage(SSH_Message_Request_Failure());
    }
  }

  // void _handleGlobalRequestHostkey(SSH_Message_Global_Request request) {
  //   printDebug?.call('SSHClient._handleGlobalRequestHostkey');
  //   // sendMessage(SSH_Message_Request_Success.e
  //   if (onHostKeys != null) {
  //     // onHostKeys(request.hostKeyAlgorithms);
  //   }
  // }

  void _handleGlobalRequestSuccess(Uint8List payload) {
    final message = SSH_Message_Request_Success.decode(payload);
    printTrace?.call('<- $socket: $message');
    _globalRequestReplyQueue.add(message);
  }

  void _handleGlobalRequestFailure(Uint8List payload) {
    final message = SSH_Message_Request_Failure.decode(payload);
    printTrace?.call('<- $socket: $message');
    _globalRequestReplyQueue.add(message);
  }

  void _handleChannelOpen(Uint8List payload) {
    final message = SSH_Message_Channel_Open.decode(payload);
    printTrace?.call('<- $socket: $message');

    switch (message.channelType) {
      case 'forwarded-tcpip':
        return _handleForwardedTcpipChannelOpen(message);
      case 'x11':
        return _handleX11ChannelOpen(message);
      case 'auth-agent@openssh.com':
        return _handleAgentChannelOpen(message);
    }

    printDebug?.call('unknown channelType: ${message.channelType}');
    final reply = SSH_Message_Channel_Open_Failure(
      recipientChannel: message.senderChannel,
      reasonCode: SSH_Message_Channel_Open_Failure.codeUnknownChannelType,
      description: 'unknown channel type: ${message.channelType}',
    );
    _sendMessage(reply);
  }

  void _handleForwardedTcpipChannelOpen(SSH_Message_Channel_Open message) {
    printDebug?.call('SSHClient._handleTcpipForwardChannelOpen');

    final remoteForward = _findRemoteForward(message.host!, message.port!);

    if (remoteForward == null) {
      printDebug?.call('unknown remote forward: $message');
      final reply = SSH_Message_Channel_Open_Failure(
        recipientChannel: message.senderChannel,
        reasonCode: SSH_Message_Channel_Open_Failure.codeUnknownChannelType,
        description: 'unknown remote forward: $message',
      );
      _sendMessage(reply);
      return;
    }

    if (remoteForward.filter != null) {
      if (!remoteForward.filter!(message.host!, message.port!)) {
        printDebug?.call('remote forward rejected by filter: $message');
        final reply = SSH_Message_Channel_Open_Failure(
          recipientChannel: message.senderChannel,
          reasonCode: 1, // SSH_OPEN_ADMINISTRATIVELY_PROHIBITED
          description: 'rejected by filter',
        );
        _sendMessage(reply);
        return;
      }
    }

    final localChannelId = _channelIdAllocator.allocate();

    final confirmation = SSH_Message_Channel_Confirmation(
      recipientChannel: message.senderChannel,
      senderChannel: localChannelId,
      initialWindowSize: _initialWindowSize,
      maximumPacketSize: _maximumPacketSize,
      data: Uint8List(0),
    );

    final channelController = _acceptChannel(
      localChannelId: localChannelId,
      remoteChannelId: message.senderChannel,
      remoteInitialWindowSize: message.initialWindowSize,
      remoteMaximumPacketSize: message.maximumPacketSize,
    );

    _sendMessage(confirmation);

    remoteForward._connections.add(
      SSHForwardChannel(channelController.channel),
    );
  }

  void _handleX11ChannelOpen(SSH_Message_Channel_Open message) {
    printDebug?.call('SSHClient._handleX11ChannelOpen');

    if (onX11Forward == null) {
      final reply = SSH_Message_Channel_Open_Failure(
        recipientChannel: message.senderChannel,
        reasonCode: 1, // SSH_OPEN_ADMINISTRATIVELY_PROHIBITED
        description: 'x11 forwarding not enabled',
      );
      _sendMessage(reply);
      return;
    }

    final localChannelId = _channelIdAllocator.allocate();

    final confirmation = SSH_Message_Channel_Confirmation(
      recipientChannel: message.senderChannel,
      senderChannel: localChannelId,
      initialWindowSize: _initialWindowSize,
      maximumPacketSize: _maximumPacketSize,
      data: Uint8List(0),
    );

    final channelController = _acceptChannel(
      localChannelId: localChannelId,
      remoteChannelId: message.senderChannel,
      remoteInitialWindowSize: message.initialWindowSize,
      remoteMaximumPacketSize: message.maximumPacketSize,
    );

    _sendMessage(confirmation);

    onX11Forward!(
      SSHX11Channel(
        channelController.channel,
        originatorIP: message.originatorIP ?? '',
        originatorPort: message.originatorPort ?? 0,
      ),
    );
  }

  void _handleAgentChannelOpen(SSH_Message_Channel_Open message) {
    final handler = agentHandler;
    if (handler == null) {
      final reply = SSH_Message_Channel_Open_Failure(
        recipientChannel: message.senderChannel,
        reasonCode:
            SSH_Message_Channel_Open_Failure.codeAdministrativelyProhibited,
        description: 'agent forwarding not enabled',
      );
      _sendMessage(reply);
      return;
    }

    final localChannelId = _channelIdAllocator.allocate();
    final confirmation = SSH_Message_Channel_Confirmation(
      recipientChannel: message.senderChannel,
      senderChannel: localChannelId,
      initialWindowSize: _initialWindowSize,
      maximumPacketSize: _maximumPacketSize,
      data: Uint8List(0),
    );
    final channelController = _acceptChannel(
      localChannelId: localChannelId,
      remoteChannelId: message.senderChannel,
      remoteInitialWindowSize: message.initialWindowSize,
      remoteMaximumPacketSize: message.maximumPacketSize,
    );

    _sendMessage(confirmation);

    SSHAgentChannel(
      channelController.channel,
      handler,
      printDebug: printDebug,
    );
  }

  /// Finds a remote forward that matches the given host and port.
  SSHRemoteForward? _findRemoteForward(String host, int port) {
    final result = _remoteForwards.where(
      (forward) => forward.host == host && forward.port == port,
    );
    return result.isEmpty ? null : result.first;
  }

  void _handleChannelConfirmation(Uint8List payload) {
    final message = SSH_Message_Channel_Confirmation.decode(payload);
    printTrace?.call('<- $socket: $message');

    _requirePendingChannelOpen(message.recipientChannel, 'confirmation');

    // Register synchronously before completing the future. CHANNEL_DATA may
    // immediately follow the confirmation in the same transport input.
    final channelController = _acceptChannel(
      localChannelId: message.recipientChannel,
      remoteChannelId: message.senderChannel,
      remoteInitialWindowSize: message.initialWindowSize,
      remoteMaximumPacketSize: message.maximumPacketSize,
    );

    _pendingChannelOpens.complete(message.recipientChannel, channelController);
  }

  void _handleChannelOpenFailure(Uint8List payload) {
    final message = SSH_Message_Channel_Open_Failure.decode(payload);
    printTrace?.call('<- $socket: $message');

    _requirePendingChannelOpen(message.recipientChannel, 'failure');

    _channelIdAllocator.release(message.recipientChannel);
    _pendingChannelOpens.fail(
      message.recipientChannel,
      SSHChannelOpenError(message.reasonCode, message.description),
    );
  }

  void _handleChannelWindowAdjust(Uint8List payload) {
    final message = SSH_Message_Channel_Window_Adjust.decode(payload);
    printTrace?.call('<- $socket: $message');
    _channels[message.recipientChannel]?.handleMessage(message);
  }

  void _handleChannelRequest(Uint8List payload) {
    final message = SSH_Message_Channel_Request.decode(payload);
    printTrace?.call('<- $socket: $message');
    _channels[message.recipientChannel]?.handleMessage(message);
  }

  void _handleChannelSuccess(Uint8List payload) {
    final message = SSH_Message_Channel_Success.decode(payload);
    printTrace?.call('<- $socket: $message');
    _channels[message.recipientChannel]?.handleMessage(message);
  }

  void _handleChannelFailure(Uint8List payload) {
    final message = SSH_Message_Channel_Failure.decode(payload);
    printTrace?.call('<- $socket: $message');
    _channels[message.recipientChannel]?.handleMessage(message);
  }

  void _handleChannelData(Uint8List payload) {
    final message = SSH_Message_Channel_Data.decode(payload);
    printTrace?.call('<- $socket: $message');
    _channels[message.recipientChannel]?.handleMessage(message);
  }

  void _handleChannelExtendedData(Uint8List payload) {
    final message = SSH_Message_Channel_Extended_Data.decode(payload);
    printTrace?.call('<- $socket: $message');
    _channels[message.recipientChannel]?.handleMessage(message);
  }

  void _handleChannelEOF(Uint8List payload) {
    final message = SSH_Message_Channel_EOF.decode(payload);
    printTrace?.call('<- $socket: $message');
    _channels[message.recipientChannel]?.handleMessage(message);
  }

  void _handleChannelClose(Uint8List payload) {
    final message = SSH_Message_Channel_Close.decode(payload);
    printTrace?.call('<- $socket: $message');
    final channel = _channels[message.recipientChannel];
    if (channel != null) {
      channel.handleMessage(message);
      _channels.remove(message.recipientChannel);
      _channelIdAllocator.release(message.recipientChannel);
    }
  }

  void _requestAuthentication() {
    printDebug?.call('SSHClient._requestAuthentication');
    _sendMessage(SSH_Message_Service_Request('ssh-userauth'));
  }

  void _startAuthentication() {
    printDebug?.call('SSHClient._startAuthentication');

    if (identities != null && identities!.isNotEmpty) {
      _preferredAuthMethods.add(SSHAuthMethod.publicKey);
    }

    if (onPasswordRequest != null) {
      _preferredAuthMethods.add(SSHAuthMethod.password);
    }

    if (onUserInfoRequest != null) {
      _preferredAuthMethods.add(SSHAuthMethod.keyboardInteractive);
    }

    if (hostbasedIdentities != null &&
        hostbasedIdentities!.isNotEmpty &&
        hostName != null &&
        userNameOnClientHost != null) {
      _preferredAuthMethods.add(SSHAuthMethod.hostbased);
    }

    _authMethodsLeft
      ..addAll(_preferredAuthMethods)
      ..add(SSHAuthMethod.none);

    _tryNextAuthMethod();
  }

  void _tryNextAuthMethod() {
    printDebug?.call('SSHClient._tryNextAuthenticationMethod');

    if (_authMethodsLeft.isEmpty) {
      return _authenticated.completeError(
        SSHAuthFailError('All authentication methods failed'),
        StackTrace.current,
      );
    }

    _currentAuthMethod = _authMethodsLeft.removeFirst();
    printDebug?.call('_currentAuthMethod = $_currentAuthMethod');

    switch (_currentAuthMethod!) {
      case SSHAuthMethod.none:
        return _authWithNone();
      case SSHAuthMethod.password:
        return _catch(() => _authWithPassword());
      case SSHAuthMethod.publicKey:
        return _catch(() => _authWithNextPublicKey());
      case SSHAuthMethod.keyboardInteractive:
        return _authWithKeyboardInteractive();
      case SSHAuthMethod.hostbased:
        return _catch(() => _authWithNextHostbased());
    }
  }

  void _authWithNone() {
    printDebug?.call('SSHClient._authWithNone');
    _sendMessage(SSH_Message_Userauth_Request.none(user: username));
  }

  Future<void> _authWithPassword() async {
    printDebug?.call('SSHClient._authWithPassword');

    final password = await onPasswordRequest!();
    if (password == null) {
      _exhaustedAuthMethods.add(SSHAuthMethod.password);
      _tryNextAuthMethod();
      return;
    }

    _sendMessage(
      SSH_Message_Userauth_Request.password(user: username, password: password),
    );
  }

  Future<void> _authWithNextPublicKey() async {
    printDebug?.call('SSHClient._authWithPublicKey');

    if (_identitiesLeft.isEmpty) {
      _exhaustedAuthMethods.add(SSHAuthMethod.publicKey);
      _tryNextAuthMethod();
      return;
    }

    final identity = _identitiesLeft.removeFirst();
    final publicKey = identity.toPublicKey();
    final publicKeyBlob = publicKey.encode();

    if (identity.shouldProbe) {
      printDebug?.call(
        'Probing public key for identity: ${identity.comment ?? identity.type}',
      );
      _currentProbedIdentity = identity;
      _sendMessage(
        SSH_Message_Userauth_Request.publicKey(
          username: username,
          publicKeyAlgorithm: identity.type,
          publicKey: publicKeyBlob,
          signature: null,
        ),
      );
      return;
    }

    final challenge = _transport.composeChallenge(
      username: username,
      service: 'ssh-connection',
      publicKeyAlgorithm: identity.type,
      publicKey: publicKeyBlob,
    );

    final signature = await identity.sign(challenge);

    if (isClosed || _currentAuthMethod != SSHAuthMethod.publicKey) {
      return;
    }

    _sendMessage(
      SSH_Message_Userauth_Request.publicKey(
        username: username,
        publicKeyAlgorithm: identity.type,
        publicKey: publicKeyBlob,
        signature: signature.encode(),
      ),
    );
  }

  void _authWithKeyboardInteractive() {
    printDebug?.call('SSHClient._authWithKeyboardInteractive');
    _sendMessage(
      SSH_Message_Userauth_Request.keyboardInteractive(user: username),
    );
  }

  Future<void> _authWithNextHostbased() async {
    printDebug?.call('SSHClient._authWithHostbased');

    if (_hostbasedIdentitiesLeft.isEmpty) {
      _exhaustedAuthMethods.add(SSHAuthMethod.hostbased);
      _tryNextAuthMethod();
      return;
    }

    final identity = _hostbasedIdentitiesLeft.removeFirst();
    final hostKey = identity.toPublicKey().encode();
    final challenge = _transport.composeHostbasedChallenge(
      username: username,
      service: 'ssh-connection',
      hostKeyAlgorithm: identity.type,
      hostKey: hostKey,
      clientHostName: hostName!,
      clientUsername: userNameOnClientHost!,
    );
    final signature = await identity.sign(challenge);

    if (isClosed || _currentAuthMethod != SSHAuthMethod.hostbased) {
      return;
    }

    _sendMessage(
      SSH_Message_Userauth_Request.hostbased(
        username: username,
        hostKeyAlgorithm: identity.type,
        hostKey: hostKey,
        clientHostName: hostName!,
        clientUsername: userNameOnClientHost!,
        signature: signature.encode(),
      ),
    );
  }

  Set<SSHAuthMethod> get _availableAuthMethods => {
        if (_identitiesLeft.isNotEmpty) SSHAuthMethod.publicKey,
        if (!_exhaustedAuthMethods.contains(SSHAuthMethod.password) &&
            onPasswordRequest != null)
          SSHAuthMethod.password,
        if (!_exhaustedAuthMethods
                .contains(SSHAuthMethod.keyboardInteractive) &&
            onUserInfoRequest != null)
          SSHAuthMethod.keyboardInteractive,
        if (_hostbasedIdentitiesLeft.isNotEmpty &&
            hostName != null &&
            userNameOnClientHost != null)
          SSHAuthMethod.hostbased,
      };

  void _markCurrentAuthMethodAttempted() {
    switch (_currentAuthMethod) {
      case SSHAuthMethod.password:
      case SSHAuthMethod.keyboardInteractive:
      case SSHAuthMethod.none:
        _exhaustedAuthMethods.add(_currentAuthMethod!);
        break;
      case SSHAuthMethod.publicKey:
        if (_identitiesLeft.isEmpty) {
          _exhaustedAuthMethods.add(SSHAuthMethod.publicKey);
        }
        break;
      case SSHAuthMethod.hostbased:
        if (_hostbasedIdentitiesLeft.isEmpty) {
          _exhaustedAuthMethods.add(SSHAuthMethod.hostbased);
        }
        break;
      case null:
        break;
    }
  }

  void _resetAuthStateForNextFactor() {
    _exhaustedAuthMethods.clear();
    // OpenSSH resets public-key attempt state after partial success so the
    // next authentication factor may use publickey again. Hostbased keys are
    // consumed as they are tried and are intentionally not replenished.
    _identitiesLeft
      ..clear()
      ..addAll(identities ?? const <SSHIdentity>[]);
  }

  Future<SSHChannelController> _openSessionChannel() {
    final localChannelId = _channelIdAllocator.allocate();

    final request = SSH_Message_Channel_Open.session(
      senderChannel: localChannelId,
      initialWindowSize: _initialWindowSize,
      maximumPacketSize: _maximumPacketSize,
    );
    return _openChannel(localChannelId, request);
  }

  Future<SSHChannelController> _openForwardLocalChannel(
    String bindAddress,
    int bindPort,
    String remoteAddress,
    int remotePort,
  ) {
    final localChannelId = _channelIdAllocator.allocate();

    final request = SSH_Message_Channel_Open.directTcpip(
      senderChannel: localChannelId,
      initialWindowSize: _initialWindowSize,
      maximumPacketSize: _maximumPacketSize,
      host: remoteAddress,
      port: remotePort,
      originatorIP: bindAddress,
      originatorPort: bindPort,
    );
    return _openChannel(localChannelId, request);
  }

  Future<SSHChannelController> _openForwardLocalUnixChannel(
    String socketPath,
  ) {
    final localChannelId = _channelIdAllocator.allocate();

    final request = SSH_Message_Channel_Open.directStreamLocal(
      senderChannel: localChannelId,
      initialWindowSize: _initialWindowSize,
      maximumPacketSize: _maximumPacketSize,
      socketPath: socketPath,
    );
    return _openChannel(localChannelId, request);
  }

  Future<SSHChannelController> _openChannel(
    SSHChannelId localChannelId,
    SSH_Message_Channel_Open request,
  ) {
    if (_pendingChannelOpens.isWaiting(localChannelId) ||
        _channels.containsKey(localChannelId)) {
      throw SSHStateError('Channel $localChannelId is already in use');
    }

    // Registered before sending so a reply delivered synchronously by the
    // transport still finds its waiter.
    final reply = _pendingChannelOpens.wait(localChannelId);

    try {
      _sendMessage(request);
    } catch (error, stackTrace) {
      if (_pendingChannelOpens.fail(localChannelId, error, stackTrace)) {
        _channelIdAllocator.release(localChannelId);
      }
      rethrow;
    }

    return reply;
  }

  SSHChannelController _acceptChannel({
    required SSHChannelId localChannelId,
    required SSHChannelId remoteChannelId,
    required int remoteInitialWindowSize,
    required int remoteMaximumPacketSize,
  }) {
    if (_channels.containsKey(localChannelId)) {
      throw SSHStateError('Channel $localChannelId is already open');
    }

    final channelController = SSHChannelController(
      localId: localChannelId,
      localInitialWindowSize: _initialWindowSize,
      localMaximumPacketSize: _maximumPacketSize,
      remoteId: remoteChannelId,
      remoteInitialWindowSize: remoteInitialWindowSize,
      remoteMaximumPacketSize: remoteMaximumPacketSize,
      sendMessage: _sendMessage,
      onFlush: flush,
      printDebug: printDebug,
    );

    _channels[localChannelId] = channelController;
    return channelController;
  }

  void _requirePendingChannelOpen(SSHChannelId id, String replyType) {
    if (_pendingChannelOpens.isWaiting(id)) return;
    throw SSHStateError(
      'Received channel open $replyType for non-opening channel $id',
    );
  }
}

class SSHRemoteForward {
  final String host;

  final int port;

  final SSHRemoteConnectionFilter? filter;

  SSHRemoteForward(this._client, this.host, this.port, this.filter);

  final SSHClient _client;

  final _connections = StreamController<SSHForwardChannel>();

  Stream<SSHForwardChannel> get connections => _connections.stream;

  void close() {
    _connections.close();
    _client.cancelForwardRemote(this);
  }

  @override
  String toString() => '$runtimeType($host:$port)';
}
