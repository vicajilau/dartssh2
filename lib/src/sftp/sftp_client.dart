import 'dart:async';
import 'dart:math';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:meta/meta.dart';
import 'package:dartssh2/src/sftp/sftp_errors.dart';
import 'package:dartssh2/src/sftp/sftp_file_attrs.dart';
import 'package:dartssh2/src/sftp/sftp_file_open_mode.dart';
import 'package:dartssh2/src/sftp/sftp_name.dart';
import 'package:dartssh2/src/sftp/sftp_packet.dart';
import 'package:dartssh2/src/sftp/sftp_packet_ext.dart';
import 'package:dartssh2/src/sftp/sftp_request_id.dart';
import 'package:dartssh2/src/sftp/sftp_statvfs.dart';
import 'package:dartssh2/src/sftp/sftp_stream_io.dart';
import 'package:dartssh2/src/ssh_channel.dart';
import 'package:dartssh2/src/ssh_transport.dart';
import 'package:dartssh2/src/utils/chunk_buffer.dart';
import 'package:dartssh2/src/ssh_message.dart';
import 'package:dartssh2/src/utils/pending_requests.dart';
import 'package:dartssh2/src/utils/terminal_state.dart';

part 'sftp_file.dart';

const _kVersion = 3;
const _kReadChunkSize = 16 * 1024;
const _kReadMaxPendingRequests = 64;
// Short replies below this size are treated as a hiccup rather than as the
// server's real read capacity, so they do not shrink later requests.
// Mirrors `MIN_READ_SIZE` in OpenSSH's `sftp-client.c`.
const _kMinReadSize = 512;
const _kDownloadChunkSize = 64 * 1024;
const _kDownloadMaxPendingRequests = 128;
// Matches SFTP_MAX_MSG_LENGTH in OpenSSH. The four-byte length prefix is not
// included in this limit.
const _kMaxPacketLength = 256 * 1024;

class SftpClient {
  final SSHChannel _channel;

  final SSHPrintHandler? printDebug;

  final SSHPrintHandler? printTrace;

  SftpClient(this._channel, {this.printDebug, this.printTrace}) {
    _handshake.future.ignore();
    _channel.stream.listen(
      _handleData,
      onError: (Object error, StackTrace stackTrace) {
        _closeError(error, stackTrace);
      },
      onDone: () {
        _closeError(SftpAbortError('SFTP channel closed'));
      },
    );
    _startHandshake();
  }

  final _buffer = ChunkBuffer();

  final _handshake = Completer<SftpHandsake>();

  final _terminalState = TerminalState();

  final _requestId = SftpRequestId();

  late final _replyWaiters = PendingRequests<int, SftpResponsePacket>(
    terminalState: _terminalState,
  );

  Future<void>? _closeFuture;

  /// The handshake information received from the server.
  Future<SftpHandsake> get handshake => _handshake.future;

  /// Gets the attributes of the file at [path].
  Future<SftpFileAttrs> stat(String path, {bool followLink = true}) async {
    final reply = followLink ? await _sendStat(path) : await _sendLStat(path);
    if (reply is SftpAttrsPacket) return reply.attrs;
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    throw SftpStatusError.fromStatus(reply);
  }

  /// Sets the attributes of the file at [path].
  Future<void> setStat(String path, SftpFileAttrs attrs) async {
    final reply = await _sendSetStat(path, attrs);
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    SftpStatusError.check(reply);
  }

  /// Opens a file for reading or/and writing.
  Future<SftpFile> open(
    String path, {
    SftpFileOpenMode mode = SftpFileOpenMode.read,
  }) async {
    final reply = await _sendOpen(path, mode, SftpFileAttrs());
    if (reply is SftpHandlePacket) return SftpFile(this, reply.handle);
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    throw SftpStatusError.fromStatus(reply);
  }

  /// Downloads a remote file from [path] into [destination].
  ///
  /// This is a convenience API built on top of [SftpFile.read] and keeps the
  /// existing stream-based APIs fully compatible.
  ///
  /// Returns the total number of bytes written.
  Future<int> download(
    String path,
    StreamSink<List<int>> destination, {
    int? length,
    int offset = 0,
    void Function(int bytesRead)? onProgress,
    int chunkSize = _kDownloadChunkSize,
    int maxPendingRequests = _kDownloadMaxPendingRequests,
    bool closeDestination = false,
  }) async {
    final file = await open(path, mode: SftpFileOpenMode.read);
    try {
      return await file.downloadTo(
        destination,
        length: length,
        offset: offset,
        onProgress: onProgress,
        chunkSize: chunkSize,
        maxPendingRequests: maxPendingRequests,
        closeDestination: closeDestination,
      );
    } finally {
      await file.close();
    }
  }

  /// Reads the items of a directory. Returns an [Stream] of [SftpName] chunks.
  /// Use [listdir] instead of this unless the directory contains a large number
  /// of items.
  Stream<List<SftpName>> readdir(String path) async* {
    final dir = await _opendir(path);
    while (true) {
      final names = await _readdir(dir);
      if (names == null) break;
      yield names;
    }
    await _close(dir);
  }

  /// List the items of a directory. This is a convenience method wrapping
  /// [readdir].
  Future<List<SftpName>> listdir(String path) async {
    final result = <SftpName>[];
    await for (final names in readdir(path)) {
      result.addAll(names);
    }
    return result;
  }

  /// Remove a file whose name is [filename]. This can only be used to remove
  /// files. Use [rmdir] to remove a directory.
  Future<void> remove(String filename) async {
    final reply = await _sendRemove(filename);
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    SftpStatusError.check(reply);
  }

  /// Makes a directory at the given [path].
  Future<void> mkdir(String path, [SftpFileAttrs? attrs]) async {
    final reply = await _sendMakeDir(path, attrs ?? SftpFileAttrs());
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    SftpStatusError.check(reply);
  }

  /// Removes a directory whose name is [dirname]. This can only be used to
  /// remove directories. Use [remove] to remove a file.
  /// This will fail if the directory is not empty.
  Future<void> rmdir(String dirname) async {
    final reply = await _sendRemoveDir(dirname);
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    SftpStatusError.check(reply);
  }

  /// Returns the absolute path of [path].
  Future<String> absolute(String path) async {
    final reply = await _sendRealPath(path);
    if (reply is SftpNamePacket) return reply.names.first.filename;
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    throw SftpStatusError.fromStatus(reply);
  }

  /// Renames a file or directory from [oldPath] to [newPath].
  ///
  /// If the server supports the `posix-rename@openssh.com` SFTP extension
  /// (version "1"), this method uses it to perform an atomic rename with
  /// POSIX semantics (replace destination if it exists). Otherwise, it falls
  /// back to the standard SFTP `SSH_FXP_RENAME` request.
  Future<void> rename(String oldPath, String newPath) async {
    // Prefer OpenSSH's posix-rename extension when available.
    final hs = await handshake;
    final extVersion = hs.extensions['posix-rename@openssh.com'];
    if (extVersion != null) {
      try {
        await _checkExtension('posix-rename@openssh.com', '1');
        final payload =
            SftpPosixRenameRequest(oldPath: oldPath, newPath: newPath);
        final reply = await _sendExtended(payload);
        if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
        SftpStatusError.check(reply);
        return;
      } on SftpExtensionError {
        // Fall through to standard rename if extension unsupported/mismatched.
      }
    }

    final reply = await _sendRename(oldPath, newPath);
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    SftpStatusError.check(reply);
  }

  /// Reads the target of a symbolic link.
  Future<String> readlink(String path) async {
    final reply = await _sendReadLink(path);
    if (reply is SftpNamePacket) return reply.names.first.filename;
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    throw SftpStatusError.fromStatus(reply);
  }

  /// Creates a symbolic link at [targetPath] that points to [linkPath].
  Future<void> link(String linkPath, String targetPath) async {
    final reply = await _sendSymlink(linkPath, targetPath);
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    SftpStatusError.check(reply);
  }

  /// Gets the information about a mounted filesystem. [path] is the pathname of
  /// any file within the mounted filesystem.
  ///
  /// **Note**: This is an extension to the SFTP protocol, supported by most
  /// openssh servers. A [SftpExtensionError] is thrown if the server does not
  /// support this extension.
  ///
  /// See also:
  ///
  /// - [SftpFile.statvfs] which requires an open [SftpFile] instance instead of
  ///   a path.
  Future<SftpStatVfs> statvfs(String path) async {
    await _checkExtension('statvfs@openssh.com', '2');
    final payload = SftpStatVfsRequest(path: path);
    final reply = await _sendExtended(payload);
    if (reply is SftpStatusPacket) throw SftpStatusError.fromStatus(reply);
    if (reply is! SftpExtendedReplyPacket) throw SftpError('Unexpected reply');
    final stat = SftpStatVfsReply.decode(reply.payload);
    return SftpStatVfs.fromReply(stat);
  }

  /// Close the sftp session.
  ///
  /// This also closes the underlying SSH channel that the sftp subsystem runs
  /// on. Without this the channel is leaked: every [SSHClient.sftp] call opens
  /// a fresh session channel, so an application that opens an sftp session per
  /// operation would accumulate open channels on the connection until the
  /// server refuses further `CHANNEL_OPEN`s.
  Future<void> close() => _closeFuture ??= _closeClient();

  Future<void> _closeClient() async {
    _closeError(SftpAbortError('SFTP client closed'));
    await _channel.close();
  }

  void _closeError(Object error, [StackTrace? stackTrace]) {
    stackTrace ??= StackTrace.current;
    final didTerminate = _replyWaiters.closeWithError(error, stackTrace);
    if (!didTerminate) return;

    _buffer.clear();
    if (!_handshake.isCompleted) {
      _handshake.completeError(_terminalState.error, _terminalState.stackTrace);
    }
  }

  void _startHandshake() {
    _sendPacket(SftpInitPacket(_kVersion));
  }

  /// Open a directory and return the handle.
  Future<Uint8List> _opendir(String path) async {
    final reply = await _sendOpenDir(path);
    if (reply is SftpHandlePacket) return reply.handle;
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    throw SftpStatusError.fromStatus(reply);
  }

  /// Reads the next bunch of entries from the directory. Returns `null` when
  /// there are no more entries.
  Future<List<SftpName>?> _readdir(Uint8List handle) async {
    final reply = await _sendReadDir(handle);
    if (reply is SftpNamePacket) return reply.names;
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    SftpStatusError.check(reply);
    return null;
  }

  Future<void> _close(Uint8List handle) async {
    final reply = await _sendClose(handle);
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    SftpStatusError.check(reply);
  }

  void _sendPacket(SftpPacket packet) {
    _terminalState.throwIfTerminated();
    final data = packet.encode();
    if (data.length > _kMaxPacketLength) {
      final error = SftpError(
        'Outgoing SFTP packet is too large: ${data.length} bytes '
        '(maximum $_kMaxPacketLength bytes)',
      );
      _closeError(error);
      _channel.destroy();
      throw error;
    }
    printTrace?.call('-> $_channel: $packet');
    final writer = SSHMessageWriter();
    writer.writeUint32(data.length);
    writer.writeBytes(data);
    _channel.addData(writer.takeBytes());
  }

  Future<SftpResponsePacket> _sendRequest(SftpRequestPacket request) async {
    await handshake;
    final reply = _waitReply(request.requestId);
    try {
      _sendPacket(request);
    } catch (error, stackTrace) {
      _replyWaiters.fail(request.requestId, error, stackTrace);
      _closeError(error, stackTrace);
    }
    return await reply;
  }

  Future<SftpResponsePacket> _sendOpen(
    String path,
    SftpFileOpenMode mode,
    SftpFileAttrs attrs,
  ) async {
    final request = SftpOpenPacket(_requestId.next, path, mode.flag, attrs);
    return await _sendRequest(request);
  }

  Future<SftpResponsePacket> _sendClose(Uint8List handle) async {
    final request = SftpClosePacket(_requestId.next, handle);
    return await _sendRequest(request);
  }

  Future<SftpResponsePacket> _sendRead(
    Uint8List handle,
    int offset,
    int length,
  ) async {
    final request = SftpReadPacket(
      requestId: _requestId.next,
      handle: handle,
      offset: offset,
      length: length,
    );
    return await _sendRequest(request);
  }

  Future<SftpResponsePacket> _sendWrite(
    Uint8List handle,
    int offset,
    Uint8List data,
  ) async {
    final request = SftpWritePacket(
      requestId: _requestId.next,
      handle: handle,
      offset: offset,
      data: data,
    );
    return await _sendRequest(request);
  }

  Future<SftpResponsePacket> _sendLStat(String path) async {
    final request = SftpLStatPacket(_requestId.next, path);
    return await _sendRequest(request);
  }

  Future<SftpResponsePacket> _sendFStat(Uint8List handle) async {
    final request = SftpFStatPacket(_requestId.next, handle);
    return await _sendRequest(request);
  }

  Future<SftpResponsePacket> _sendSetStat(
    String path,
    SftpFileAttrs attrs,
  ) async {
    final request = SftpSetStatPacket(_requestId.next, path, attrs);
    return await _sendRequest(request);
  }

  Future<SftpResponsePacket> _sendFSetStat(
    Uint8List handle,
    SftpFileAttrs attrs,
  ) async {
    final request = SftpFSetStatPacket(_requestId.next, handle, attrs);
    return await _sendRequest(request);
  }

  Future<SftpResponsePacket> _sendOpenDir(String path) async {
    final request = SftpOpenDirPacket(_requestId.next, path);
    return await _sendRequest(request);
  }

  Future<SftpResponsePacket> _sendReadDir(Uint8List handle) async {
    final request = SftpReadDirPacket(_requestId.next, handle);
    return await _sendRequest(request);
  }

  Future<SftpResponsePacket> _sendRemove(String filename) async {
    final request = SftpRemovePacket(_requestId.next, filename);
    return await _sendRequest(request);
  }

  Future<SftpResponsePacket> _sendMakeDir(
    String path,
    SftpFileAttrs attrs,
  ) async {
    final request = SftpMkdirPacket(_requestId.next, path, attrs);
    return await _sendRequest(request);
  }

  Future<SftpResponsePacket> _sendRemoveDir(String path) async {
    final request = SftpRmdirPacket(_requestId.next, path);
    return await _sendRequest(request);
  }

  Future<SftpResponsePacket> _sendRealPath(String path) async {
    final request = SftpRealpathPacket(_requestId.next, path);
    return await _sendRequest(request);
  }

  Future<SftpResponsePacket> _sendStat(String path) async {
    final request = SftpStatPacket(_requestId.next, path);
    return await _sendRequest(request);
  }

  Future<SftpResponsePacket> _sendRename(
    String oldPath,
    String newPath,
  ) async {
    final request = SftpRenamePacket(_requestId.next, oldPath, newPath);
    return await _sendRequest(request);
  }

  Future<SftpResponsePacket> _sendReadLink(String path) async {
    final request = SftpReadlinkPacket(_requestId.next, path);
    return await _sendRequest(request);
  }

  Future<SftpResponsePacket> _sendSymlink(
    String linkPath,
    String targetPath,
  ) async {
    final request = SftpSymlinkPacket(_requestId.next, linkPath, targetPath);
    return await _sendRequest(request);
  }

  Future<SftpResponsePacket> _sendExtended(SftpExtendedRequest payload) async {
    final request = SftpExtendedPacket(_requestId.next, payload.encode());
    return await _sendRequest(request);
  }

  void _dispatchReply(SftpResponsePacket packet) {
    _replyWaiters.complete(packet.requestId, packet);
  }

  Future<SftpResponsePacket> _waitReply(int requestId) {
    return _replyWaiters.wait(requestId);
  }

  Future<void> _checkExtension(String name, String version) async {
    final handshake = await this.handshake;
    final extensionVersion = handshake.extensions[name];
    if (extensionVersion == null) {
      throw SftpExtensionUnsupportedError(name);
    }
    if (extensionVersion != version) {
      throw SftpExtensionVersionMismatchError(name, extensionVersion);
    }
  }

  void _handleData(SSHChannelData data) {
    if (_terminalState.isTerminated) return;
    try {
      _buffer.add(data.bytes);
      _handlePackets();
    } catch (error, stackTrace) {
      _closeError(error, stackTrace);
    }
  }

  void _handlePackets() {
    const lengthHeader = 4; // 4 bytes packet length header
    while (_buffer.length >= lengthHeader) {
      final length = _buffer.byteData.getUint32(0);
      if (length > _kMaxPacketLength) {
        _closeError(
          SftpError(
            'Incoming SFTP packet is too large: $length bytes '
            '(maximum $_kMaxPacketLength bytes)',
          ),
        );
        _channel.destroy();
        return;
      }
      if (_buffer.length < lengthHeader + length) break;
      final packet = _buffer.consume(lengthHeader + length);
      final payload = Uint8List.sublistView(packet, lengthHeader);
      _handlePacket(payload);
    }
  }

  void _handlePacket(Uint8List payload) {
    final type = payload[0];
    switch (type) {
      case SftpVersionPacket.packetType:
        return _handleVersionPacket(payload);
      case SftpStatusPacket.packetType:
        return _handleStatusPacket(payload);
      case SftpHandlePacket.packetType:
        return _handleHandlePacket(payload);
      case SftpDataPacket.packetType:
        return _handleDataPacket(payload);
      case SftpNamePacket.packetType:
        return _handleNamePacket(payload);
      case SftpAttrsPacket.packetType:
        return _handleAttrsPacket(payload);
      case SftpExtendedReplyPacket.packetType:
        return _handleExtendedReplyPacket(payload);
      default:
        printDebug?.call('SftpClient._handlePacket: unknown packet: $type');
    }
  }

  void _handleVersionPacket(Uint8List payload) {
    if (_handshake.isCompleted) {
      _closeError(SftpError('Unexpected version packet'));
      return;
    }

    final packet = SftpVersionPacket.decode(payload);
    printTrace?.call('<- $_channel: $packet');

    if (packet.version == _kVersion) {
      final handshake = SftpHandsake(packet.version, packet.extensions);
      return _handshake.complete(handshake);
    }

    _closeError(SftpError('Version mismatch: ${packet.version}'));
  }

  void _handleStatusPacket(Uint8List payload) {
    final packet = SftpStatusPacket.decode(payload);
    printTrace?.call('<- $_channel: $packet');
    _dispatchReply(packet);
  }

  void _handleHandlePacket(Uint8List payload) {
    final packet = SftpHandlePacket.decode(payload);
    printTrace?.call('<- $_channel: $packet');
    _dispatchReply(packet);
  }

  void _handleNamePacket(Uint8List payload) {
    final packet = SftpNamePacket.decode(payload);
    printTrace?.call('<- $_channel: $packet');
    _dispatchReply(packet);
  }

  void _handleDataPacket(Uint8List payload) {
    final packet = SftpDataPacket.decode(payload);
    printTrace?.call('<- $_channel: len=${packet.data.length}');
    _dispatchReply(packet);
  }

  void _handleAttrsPacket(Uint8List payload) {
    final packet = SftpAttrsPacket.decode(payload);
    printTrace?.call('<- $_channel: $packet');
    _dispatchReply(packet);
  }

  void _handleExtendedReplyPacket(Uint8List payload) {
    final packet = SftpExtendedReplyPacket.decode(payload);
    printTrace?.call('<- $_channel: $packet');
    _dispatchReply(packet);
  }
}
