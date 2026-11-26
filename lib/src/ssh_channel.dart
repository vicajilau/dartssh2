import 'dart:async';
import 'dart:math';

import 'dart:typed_data';

import 'package:dartssh2/src/ssh_channel_id.dart';
import 'package:dartssh2/src/ssh_errors.dart';
import 'package:dartssh2/src/ssh_transport.dart';
import 'package:dartssh2/src/utils/async_queue.dart';
import 'package:dartssh2/src/message/msg_channel.dart';
import 'package:dartssh2/src/ssh_message.dart';
import 'package:dartssh2/src/utils/stream.dart';
import 'package:dartssh2/src/utils/terminal_state.dart';
import 'package:meta/meta.dart';

const _maxChannelWindow = 0xffffffff;

/// Handler of channel requests. Return true if the request was handled, false
/// if the request was not recognized or could not be handled.
typedef SSHChannelRequestHandler = bool Function(
  SSH_Message_Channel_Request request,
);

class SSHChannelController {
  final int localId;
  final int localMaximumPacketSize;
  final int localInitialWindowSize;

  final int remoteId;
  final int remoteMaximumPacketSize;
  final int remoteInitialWindowSize;

  final SSHPrintHandler? printDebug;

  final void Function(SSHMessage) sendMessage;

  SSHChannel get channel => SSHChannel(this);

  final Future<void> Function()? onFlush;

  SSHChannelController({
    required this.localId,
    required this.localMaximumPacketSize,
    required this.localInitialWindowSize,
    required this.remoteId,
    required this.remoteInitialWindowSize,
    required this.remoteMaximumPacketSize,
    required this.sendMessage,
    this.onFlush,
    this.printDebug,
  }) {
    if (remoteInitialWindowSize > 0) {
      _uploadLoop.activate();
    }
  }

  /// Remaining local receive window size.
  late var _localWindow = localInitialWindowSize;

  /// Remaining remote receive window size.
  late var _remoteWindow = remoteInitialWindowSize;

  /// A [StreamController] that receives data from the remote side.
  ///
  /// Both hooks bypass [_windowAdjustThreshold], and `onListen` has to.
  /// A controller with no listener reports `isPaused`, so every grant is
  /// suppressed until the application subscribes — and Dart delivers that
  /// first subscription as `onListen`, never as `onResume`. Without this a
  /// peer that filled the window before the application got there is left at
  /// zero credit with no further data able to arrive and trigger a grant. The
  /// remote forwarding example in the README reaches it: it awaits
  /// `Socket.connect()` before subscribing to the channel.
  ///
  /// `onResume` does not need the bypass for liveness — a consumer that
  /// paused below the threshold still leaves the peer credit to send into —
  /// but keeps the pre-threshold behaviour of granting whatever was admitted.
  late final _remoteStream = StreamController<SSHChannelData>(
    onListen: () => _sendWindowAdjustIfNeeded(force: true),
    onResume: () => _sendWindowAdjustIfNeeded(force: true),
  );

  /// How many admitted bytes must accumulate before the peer is granted them
  /// back. Counts bytes accepted into [_remoteStream], not bytes the consumer
  /// has read.
  ///
  /// Half the window is one of the two rules OpenSSH applies in `channels.c`,
  /// which refills when `local_window < local_window_max / 2` or when
  /// `local_window_max - local_window > local_maxpacket * 3`, whichever comes
  /// first. Only the first is implemented here, and at this library's sizes
  /// the other is the one that would fire sooner: at a 2 MiB window with
  /// 32 KiB packets OpenSSH refills every three or four packets where this
  /// waits for thirty-two. So this defers further than OpenSSH does, not
  /// less far, which is deliberate because sending fewer grants is the point.
  /// What bounds the deferral is the floor below, not the comparison.
  ///
  /// Never defers past `W - P + 1`, so the peer is always left at least one
  /// maximum-size packet of credit. Below that, a sender holding a chunk
  /// larger than the credit it has left can wait for a grant while this side
  /// waits for data: it may not overrun the window, and nothing obliges it to
  /// split the chunk. Only reachable when the window is under twice the
  /// packet size; the client's own 2 MiB / 32 KiB pair is nowhere near it.
  int get _windowAdjustThreshold {
    final half = localInitialWindowSize ~/ 2;
    final keepOnePacket = localInitialWindowSize - localMaximumPacketSize + 1;
    final threshold = half < keepOnePacket ? half : keepOnePacket;
    return threshold < 1 ? 1 : threshold;
  }

  /// A [StreamController] that accepts data from local end of the channel.
  final _localStream = StreamController<SSHChannelData>();

  late final _locaStreamConsumer = SSHChannelDataConsumer(_localStream.stream);

  /// Handler of channel requests from the remote side.
  late var _requestHandler = _defaultRequestHandler;

  final _terminalState = TerminalState();

  /// An [AsyncQueue] of pending request replies from the remote side.
  late final _requestReplyQueue = AsyncQueue<bool>(
    terminalState: _terminalState,
  );

  /// The replies this channel has asked for and not yet received.
  @visibleForTesting
  AsyncQueue<bool> get requestReplyQueue => _requestReplyQueue;

  /// true if we have sent an EOF message to the remote side.
  var _hasSentEOF = false;

  /// true if we have sent an close message to the remote side.
  var _hasSentClose = false;

  final _done = Completer<void>();

  Future<bool> sendExec(String command) {
    return _sendRequest(
      SSH_Message_Channel_Request.exec(
        recipientChannel: remoteId,
        wantReply: true,
        command: command,
      ),
    );
  }

  Future<bool> sendPtyReq({
    String terminalType = 'xterm-256color',
    int terminalWidth = 80,
    int terminalHeight = 25,
    int terminalPixelWidth = 0,
    int terminalPixelHeight = 0,
    Uint8List? terminalModes,
  }) {
    return _sendRequest(
      SSH_Message_Channel_Request.pty(
        recipientChannel: remoteId,
        termType: terminalType,
        termWidth: terminalWidth,
        termHeight: terminalHeight,
        termPixelWidth: terminalPixelWidth,
        termPixelHeight: terminalPixelHeight,
        termModes: terminalModes ?? Uint8List(0),
        wantReply: true,
      ),
    );
  }

  Future<bool> sendShell() {
    return _sendRequest(
      SSH_Message_Channel_Request.shell(
        recipientChannel: remoteId,
        wantReply: true,
      ),
    );
  }

  Future<bool> sendX11Req({
    bool singleConnection = false,
    String authenticationProtocol = 'MIT-MAGIC-COOKIE-1',
    required String authenticationCookie,
    int screenNumber = 0,
  }) {
    return _sendRequest(
      SSH_Message_Channel_Request.x11(
        recipientChannel: remoteId,
        wantReply: true,
        singleConnection: singleConnection,
        x11AuthenticationProtocol: authenticationProtocol,
        x11AuthenticationCookie: authenticationCookie,
        x11ScreenNumber: screenNumber,
      ),
    );
  }

  Future<bool> sendAgentForwardingRequest() {
    return _sendRequest(
      SSH_Message_Channel_Request(
        recipientChannel: remoteId,
        requestType: SSHChannelRequestType.authAgent,
        wantReply: true,
      ),
    );
  }

  Future<bool> sendSubsystem(String subsystem) {
    return _sendRequest(
      SSH_Message_Channel_Request.subsystem(
        recipientChannel: remoteId,
        subsystemName: subsystem,
        wantReply: true,
      ),
    );
  }

  Future<bool> sendEnv(String name, String value) {
    return _sendRequest(
      SSH_Message_Channel_Request.env(
        recipientChannel: remoteId,
        variableName: name,
        variableValue: value,
        wantReply: true,
      ),
    );
  }

  void sendSignal(String signal) {
    _terminalState.throwIfTerminated();
    sendMessage(
      SSH_Message_Channel_Request.signal(
        recipientChannel: remoteId,
        signalName: signal,
      ),
    );
  }

  void sendTerminalWindowChange({
    required int width,
    required int height,
    required int pixelWidth,
    required int pixelHeight,
  }) {
    _terminalState.throwIfTerminated();
    sendMessage(
      SSH_Message_Channel_Request.windowChange(
        recipientChannel: remoteId,
        termWidth: width,
        termHeight: height,
        termPixelWidth: pixelWidth,
        termPixelHeight: pixelHeight,
      ),
    );
  }

  void handleMessage(SSHMessage message) {
    if (message is SSH_Message_Channel_Data) {
      _handleDataMessage(message.data);
    } else if (message is SSH_Message_Channel_Extended_Data) {
      _handleDataMessage(message.data, type: message.dataTypeCode);
    } else if (message is SSH_Message_Channel_Window_Adjust) {
      _handleWindowAdjustMessage(message.bytesToAdd);
    } else if (message is SSH_Message_Channel_EOF) {
      _handleEOFMessage();
    } else if (message is SSH_Message_Channel_Close) {
      _handleCloseMessage();
    } else if (message is SSH_Message_Channel_Request) {
      _handleRequestMessage(message);
    } else if (message is SSH_Message_Channel_Success) {
      _handleRequestSuccessMessage();
    } else if (message is SSH_Message_Channel_Failure) {
      _handleRequestFailureMessage();
    } else {
      throw UnimplementedError('Unimplemented message: $message');
    }
  }

  /// Closes our side of the channel. Returns a [Future] that completes when
  /// the remote side has closed the channel.
  Future<void> close() async {
    if (_done.isCompleted) return;

    _locaStreamConsumer.cancel();
    _sendEOFIfNeeded();

    if (_remoteStream.isClosed) {
      _sendCloseIfNeeded();
      _finish(SSHStateError('Channel closed before receiving request reply'));
      return;
    }

    return _done.future;
  }

  /// Closes the channel immediately in both directions. This may send a close
  /// message to the remote side. After this no more data can be sent or
  /// received.
  void destroy([Object? error, StackTrace? stackTrace]) {
    if (_done.isCompleted) return;
    _remoteStream.close();
    _locaStreamConsumer.cancel();
    _sendEOFIfNeeded();
    _sendCloseIfNeeded();
    _finish(
      error ?? SSHStateError('Channel destroyed before receiving reply'),
      stackTrace,
    );
  }

  Future<bool> _sendRequest(SSHMessage request) async {
    final reply = _requestReplyQueue.next;
    try {
      sendMessage(request);
    } catch (error, stackTrace) {
      _requestReplyQueue.closeWithError(error, stackTrace);
      rethrow;
    }
    return await reply;
  }

  void _finish(Object error, [StackTrace? stackTrace]) {
    _requestReplyQueue.closeWithError(error, stackTrace);
    if (!_done.isCompleted) {
      _done.complete();
    }
  }

  void _handleWindowAdjustMessage(int bytesToAdd) {
    printDebug?.call('SSHChannel._handleWindowAdjustMessage: $bytesToAdd');

    if (bytesToAdd < 0) {
      throw ArgumentError.value(bytesToAdd, 'bytesToAdd', 'must be positive');
    }

    final adjustedWindow = _remoteWindow + bytesToAdd;
    if (adjustedWindow > _maxChannelWindow) {
      throw SSHStateError(
        'Remote window overflow on channel $localId: '
        '$_remoteWindow + $bytesToAdd exceeds $_maxChannelWindow',
      );
    }

    _remoteWindow = adjustedWindow;

    if (_remoteWindow > 0) {
      _uploadLoop.activate();
    }
  }

  void _handleDataMessage(Uint8List data, {int? type}) {
    printDebug?.call('SSHChannel._handleDataMessage: len=${data.length}');

    if (_remoteStream.isClosed) {
      printDebug?.call('SSHChannel._handleDataMessage: remote already closed');
      return;
    }

    final dataKind = type == null ? 'data' : 'extended data';
    if (data.length > localMaximumPacketSize) {
      _failChannel(
        'Channel $localId closed: the peer sent a $dataKind packet of '
        '${data.length} bytes, over the maximum packet size of '
        '$localMaximumPacketSize it was given',
      );
      return;
    }

    if (data.length > _localWindow) {
      _failChannel(
        'Channel $localId closed: the peer sent a $dataKind packet of '
        '${data.length} bytes, over the $_localWindow bytes left in the '
        'window it was granted',
      );
      return;
    }

    _localWindow -= data.length;
    _remoteStream.add(SSHChannelData(data, type: type));
    _sendWindowAdjustIfNeeded();
  }

  /// Tears down this channel after the peer violated the channel protocol,
  /// leaving the SSH connection and its other channels untouched.
  ///
  /// The error is delivered to whoever is reading the channel, so a caller
  /// waiting on an SFTP download or a shell stream finds out instead of
  /// receiving a silently truncated result. OpenSSH logs and discards the
  /// offending packet here, which is reasonable for an interactive client but
  /// not for a library that hands the bytes to an application.
  ///
  /// Failing the whole connection is the other extreme: applications
  /// multiplex a shell, SFTP and port forwards over a single connection, and
  /// one peer miscounting a window on one channel should not take the rest
  /// down with it.
  void _failChannel(String message) {
    printDebug?.call('SSHChannel._failChannel: $message');

    if (!_remoteStream.isClosed) {
      _remoteStream.addError(SSHStateError(message));
    }

    // Sends EOF and CHANNEL_CLOSE to the peer and completes [done]. The peer's
    // CHANNEL_CLOSE reply is what removes the channel from the client.
    destroy();
  }

  void _handleRequestMessage(SSH_Message_Channel_Request request) {
    printDebug?.call('SSHChannel._handleRequest: ${request.requestType}');

    final success = _requestHandler(request);
    if (!request.wantReply) return;
    success ? _sendRequestSuccess() : _sendRequestFailure();
  }

  void _handleRequestSuccessMessage() {
    printDebug?.call('SSHChannel._handleRequestSuccessMessage');
    _requestReplyQueue.add(true);
  }

  void _handleRequestFailureMessage() {
    printDebug?.call('SSHChannel._handleRequestFailureMessage');
    _requestReplyQueue.add(false);
  }

  void _handleEOFMessage() {
    printDebug?.call('SSHChannel._handleEOFMessage');
    _remoteStream.close();
  }

  void _handleCloseMessage() {
    printDebug?.call('SSHChannel._handleCLoseMessage');
    _remoteStream.close();
    unawaited(close());
  }

  bool _defaultRequestHandler(SSH_Message_Channel_Request request) {
    return false;
  }

  void _sendEOFIfNeeded() {
    printDebug?.call('SSHChannel._sendEOFIfNeeded');
    if (_done.isCompleted) return;
    if (_hasSentEOF) return;
    _hasSentEOF = true;

    try {
      sendMessage(SSH_Message_Channel_EOF(recipientChannel: remoteId));
    } catch (e) {
      printDebug?.call('SSHChannelController._sendEOFIfNeeded - error: $e');
    }
  }

  void _sendCloseIfNeeded() {
    printDebug?.call('SSHChannel._sendCloseIfNeeded');
    if (_done.isCompleted) return;
    if (_hasSentClose) return;
    _hasSentClose = true;

    try {
      sendMessage(SSH_Message_Channel_Close(recipientChannel: remoteId));
    } catch (e) {
      printDebug?.call('SSHChannelController._sendCloseIfNeeded - error: $e');
    }
  }

  void _sendRequestSuccess() {
    printDebug?.call('SSHChannel._sendRequestSuccess');
    sendMessage(SSH_Message_Channel_Success(recipientChannel: remoteId));
  }

  void _sendRequestFailure() {
    printDebug?.call('SSHChannel._sendRequestFailure');
    sendMessage(SSH_Message_Channel_Failure(recipientChannel: remoteId));
  }

  /// Grants admitted receive window back to the peer.
  ///
  /// Deferred until [_windowAdjustThreshold] bytes have accumulated, so a
  /// transfer or a chatty interactive channel stops answering every inbound
  /// packet with an uplink packet of its own.
  ///
  /// [force] bypasses the threshold for the [_remoteStream] hooks; see there
  /// for why the first listener in particular cannot wait for it.
  void _sendWindowAdjustIfNeeded({bool force = false}) {
    printDebug?.call('SSHChannel._sendWindowAdjustIfNeeded');

    if (_done.isCompleted) return;
    if (_remoteStream.isPaused) return;

    final bytesToAdd = localInitialWindowSize - _localWindow;
    if (bytesToAdd <= 0) return;
    if (!force && bytesToAdd < _windowAdjustThreshold) return;

    _localWindow = localInitialWindowSize;

    sendMessage(
      SSH_Message_Channel_Window_Adjust(
        recipientChannel: remoteId,
        bytesToAdd: bytesToAdd,
      ),
    );
  }

  late final _uploadLoop = OnceSimultaneously(() async {
    while (true) {
      if (_remoteWindow <= 0) {
        return;
      }

      final dataToRead = min(_remoteWindow, remoteMaximumPacketSize);
      final data = await _locaStreamConsumer.read(dataToRead);

      if (data == null) {
        _sendEOFIfNeeded();

        if (_remoteStream.isClosed) {
          close();
        }
        return;
      }

      if (_hasSentEOF) {
        return;
      }

      printDebug?.call('SSHChannel._uploadLoop: len=${data.bytes.length}');

      final message = data.isExtendedData
          ? SSH_Message_Channel_Extended_Data(
              recipientChannel: remoteId,
              dataTypeCode: data.type!,
              data: data.bytes,
            )
          : SSH_Message_Channel_Data(
              recipientChannel: remoteId,
              data: data.bytes,
            );

      sendMessage(message);

      _remoteWindow -= data.bytes.length;
    }
  });

  Future<void> flush() {
    return _terminalState.bind(() async {
      await onFlush?.call();
    });
  }
}

class SSHChannel {
  /// The channel id on the local side.
  SSHChannelId get channelId => _controller.localId;

  /// The channel id on the remote side.
  SSHChannelId get remoteChannelId => _controller.remoteId;

  /// The maximum packet size that the remote side can receive.
  int get maximumPacketSize => _controller.remoteMaximumPacketSize;

  /// A [Stream] of data received from the remote side.
  Stream<SSHChannelData> get stream => _controller._remoteStream.stream;

  /// A [StreamSink] that sends data to the remote side. Chucks must be
  /// equal to or less than [maximumPacketSize].
  StreamSink<SSHChannelData> get sink => _controller._localStream.sink;

  Future<void> get done => _controller._done.future;

  SSHChannel(this._controller);

  final SSHChannelController _controller;

  /// Send data to the remote side.
  void addData(Uint8List data, {int? type}) {
    sink.add(SSHChannelData(data, type: type));
  }

  /// Force flush any buffered outgoing data on this channel to the socket.
  Future<void> flush() => _controller.flush();

  void setRequestHandler(SSHChannelRequestHandler handler) {
    _controller._requestHandler = handler;
  }

  Future<bool> sendExec(String command) async {
    return await _controller.sendExec(command);
  }

  Future<bool> sendShell() async {
    return await _controller.sendShell();
  }

  Future<bool> sendX11Req({
    bool singleConnection = false,
    String authenticationProtocol = 'MIT-MAGIC-COOKIE-1',
    required String authenticationCookie,
    int screenNumber = 0,
  }) async {
    return await _controller.sendX11Req(
      singleConnection: singleConnection,
      authenticationProtocol: authenticationProtocol,
      authenticationCookie: authenticationCookie,
      screenNumber: screenNumber,
    );
  }

  void sendTerminalWindowChange({
    required int width,
    required int height,
    int pixelWidth = 0,
    int pixelHeight = 0,
  }) {
    _controller.sendTerminalWindowChange(
      width: width,
      height: height,
      pixelWidth: pixelWidth,
      pixelHeight: pixelHeight,
    );
  }

  void sendSignal(String signal) {
    _controller.sendSignal(signal);
  }

  /// Closes our side of the channel. Returns a [Future] that completes when
  /// both sides of the channel are closed.
  Future<void> close() => _controller.close();

  /// Destroys the channel in both directions. After calling this method,
  /// no more data can be sent or received.
  void destroy() => _controller.destroy();

  @override
  String toString() => 'SSHChannel($channelId:$remoteChannelId)';
}

class SSHChannelData {
  /// Type of the data. Not null if the data is extended data. See: [SSHChannelExtendedDataType]
  final int? type;

  final Uint8List bytes;

  bool get isExtendedData => type != null;

  SSHChannelData(this.bytes, {this.type});
}

class SSHChannelExtendedDataType {
  static const stderr = 1;
}

class SSHChannelDataSplitter
    extends StreamTransformerBase<SSHChannelData, SSHChannelData> {
  SSHChannelDataSplitter(this.maxSize);

  final int maxSize;

  @override
  Stream<SSHChannelData> bind(Stream<SSHChannelData> stream) async* {
    await for (var chunk in stream) {
      if (chunk.bytes.length < maxSize) {
        yield chunk;
        continue;
      }

      final blocks = chunk.bytes.length ~/ maxSize;

      for (var i = 0; i < blocks; i++) {
        yield SSHChannelData(
          Uint8List.sublistView(chunk.bytes, i * maxSize, (i + 1) * maxSize),
          type: chunk.type,
        );
      }

      if (blocks * maxSize < chunk.bytes.length) {
        yield SSHChannelData(
          Uint8List.sublistView(chunk.bytes, blocks * maxSize),
          type: chunk.type,
        );
      }
    }
  }
}

class SSHChannelDataConsumer extends StreamConsumerBase<SSHChannelData> {
  SSHChannelDataConsumer(super.stream);

  @override
  int getLength(SSHChannelData chunk) {
    return chunk.bytes.length;
  }

  @override
  SSHChannelData getSublistView(SSHChannelData chunk, int start, int end) {
    return SSHChannelData(
      Uint8List.sublistView(chunk.bytes, start, end),
      type: chunk.type,
    );
  }
}

/// A function that can be invoked at most once simultaneously.
class OnceSimultaneously {
  OnceSimultaneously(this._fn);

  final Future Function() _fn;

  var _isRunning = false;

  /// Call the function. If the function is already running, this is a no-op.
  void activate() async {
    if (_isRunning) return;
    _isRunning = true;
    try {
      await _fn();
    } finally {
      _isRunning = false;
    }
  }
}
