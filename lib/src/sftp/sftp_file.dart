part of 'sftp_client.dart';

/// A large sentinel length used by [SftpFile.read] when the file's reported
/// size cannot be trusted as a real byte count (see the comment where it's
/// used). Reads keep pipelining up to this many bytes, but in practice the
/// loop always terminates earlier via the server's SSH_FX_EOF status.
///
/// Written as a decimal literal on purpose. `1 << 40` folds to `0` under
/// dart2js, whose shifts are 32-bit, which would send every virtual file
/// straight back down the `length == 0` early return this constant exists to
/// avoid.
const _kUnboundedReadLength = 1099511627776; // 1 TiB

/// Represents an opened file handle on the remote SFTP server.
class SftpFile {
  final Uint8List _handle;

  final SftpClient _client;

  /// Creates an [SftpFile] representing an open handle on the remote server.
  SftpFile(this._client, this._handle);

  var _isClosed = false;

  /// Whether this file handle has been closed.
  bool get isClosed => _isClosed;

  /// Closes the file handle on the remote SFTP server.
  Future<void> close() async {
    if (_isClosed) return;
    _isClosed = true;
    await _client._close(_handle);
  }

  /// Retrieves metadata and attributes for this open file handle.
  Future<SftpFileAttrs> stat() async {
    _mustNotBeClosed();
    final reply = await _client._sendFStat(_handle);
    if (reply is SftpAttrsPacket) return reply.attrs;
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    throw SftpStatusError.fromStatus(reply);
  }

  /// Updates metadata and attributes for this open file handle.
  Future<void> setStat(SftpFileAttrs attrs) async {
    _mustNotBeClosed();
    final reply = await _client._sendFSetStat(_handle, attrs);
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    SftpStatusError.check(reply);
  }

  /// Reads at most [length] bytes from the file starting at [offset]. If
  /// [length] is null, reads until end of file. Returns a [Stream] of chunks
  /// ordered by file offset, even if the server replies out of order.
  /// [onProgress] is called with the total number of bytes already read.
  /// Use [readBytes] if you want a single Uint8List.
  Stream<Uint8List> read({
    int? length,
    int offset = 0,
    void Function(int bytesRead)? onProgress,
    int chunkSize = _kReadChunkSize,
    int maxPendingRequests = _kReadMaxPendingRequests,
  }) async* {
    _mustNotBeClosed();
    if (chunkSize <= 0) {
      throw ArgumentError.value(chunkSize, 'chunkSize', 'must be positive');
    }
    if (maxPendingRequests <= 0) {
      throw ArgumentError.value(
        maxPendingRequests,
        'maxPendingRequests',
        'must be positive',
      );
    }

    // Get the file size if not specified.
    if (length == null) {
      final fileStat = await stat();
      final fileSize = fileStat.size;

      if (fileSize == null) {
        throw SftpError('Can not get file size');
      }

      length = fileSize - offset;

      // Some filesystems report a size of 0 for files that actually
      // contain data (e.g. Linux /proc entries, character/device files).
      // SFTP signals end-of-file via the SSH_FX_EOF status code, not via
      // the reported size, so don't trust a stat()-derived size of 0 as
      // "nothing to read". Fall back to reading until the server tells us
      // we've hit EOF. A genuinely empty file still terminates promptly:
      // the very first read request comes back as EOF immediately. This
      // only applies when we computed `length` ourselves - a caller who
      // explicitly passes `length: 0` still gets an empty stream below.
      if (length == 0) {
        length = _kUnboundedReadLength;
        // The read-ahead pipelining below assumes `length` reflects the
        // real amount of remaining data, and will happily keep opening
        // more concurrent requests as long as `reservedOffset` is short of
        // `endOffset`. With a sentinel `endOffset` that's effectively
        // unbounded, so force strictly sequential requests here - we don't
        // know where the real EOF is, and we'd rather send one request at
        // a time than fan out up to [maxPendingRequests] speculative reads
        // into a file that may only be a few bytes long.
        maxPendingRequests = 1;
      }
    }

    if (length == 0) return;

    if (length < 0) {
      throw SftpError('Length must be positive: $length');
    }

    final endOffset = offset + length;
    final completedReads = <int, Uint8List?>{};
    var reservedOffset = offset;
    var bytesRead = 0;
    var nextOutputOffset = offset;
    var pendingReadCount = 0;
    var activeReadLimit = 1;
    var effectiveChunkSize = chunkSize;
    var stopScheduling = false;
    var outputEnded = false;
    Object? pendingError;
    StackTrace? pendingStackTrace;
    Completer<void>? completionSignal;

    void notifyReadComplete() {
      final signal = completionSignal;
      if (signal != null && !signal.isCompleted) {
        signal.complete();
      }
    }

    Future<void> waitForReadComplete() {
      final signal = completionSignal = Completer<void>();
      return signal.future.whenComplete(() {
        if (identical(completionSignal, signal)) {
          completionSignal = null;
        }
      });
    }

    void recordError(Object error, StackTrace stackTrace) {
      if (pendingError != null) return;
      pendingError = error;
      pendingStackTrace = stackTrace;
      stopScheduling = true;
    }

    void issueRead(int startOffset, int requestLength) {
      pendingReadCount++;
      readChunk(requestLength, startOffset).then(
        (chunk) {
          pendingReadCount--;

          if (pendingError != null) {
            notifyReadComplete();
            return;
          }

          if (chunk == null) {
            stopScheduling = true;
            completedReads[startOffset] = null;
            notifyReadComplete();
            return;
          }

          if (chunk.length > requestLength) {
            recordError(
              SftpError(
                'Received ${chunk.length} bytes for a $requestLength-byte read',
              ),
              StackTrace.current,
            );
            notifyReadComplete();
            return;
          }

          if (chunk.isEmpty) {
            recordError(
              SftpError('Unexpected empty data chunk before EOF'),
              StackTrace.current,
            );
            notifyReadComplete();
            return;
          }

          activeReadLimit = min(maxPendingRequests, activeReadLimit + 1);
          completedReads[startOffset] = chunk;

          if (chunk.length < requestLength) {
            // OpenSSH clamps the request size down to a short reply, with a
            // 512 byte floor (`MIN_READ_SIZE` in `sftp-client.c`). We clamp
            // the same way, but only when the reply is large enough to look
            // like the server's real capacity. Clamping to the floor instead
            // would let a single tiny reply pin every later request at 512
            // bytes for the rest of the transfer, which costs far more here
            // than it does in OpenSSH: this pipeline defaults to 64 KB reads
            // with up to 128 of them in flight.
            if (chunk.length >= _kMinReadSize) {
              effectiveChunkSize = min(effectiveChunkSize, chunk.length);
            }
            issueRead(
              startOffset + chunk.length,
              requestLength - chunk.length,
            );
          }

          notifyReadComplete();
        },
        onError: (Object error, StackTrace stackTrace) {
          pendingReadCount--;
          recordError(error, stackTrace);
          notifyReadComplete();
        },
      );
    }

    void scheduleReads() {
      while (!stopScheduling &&
          reservedOffset < endOffset &&
          pendingReadCount < activeReadLimit &&
          completedReads.length < maxPendingRequests) {
        final startOffset = reservedOffset;
        final requestLength =
            min(effectiveChunkSize, endOffset - reservedOffset);
        issueRead(startOffset, requestLength);
        reservedOffset += requestLength;
      }
    }

    scheduleReads();

    while (bytesRead < length) {
      if (pendingError != null) {
        Error.throwWithStackTrace(pendingError!, pendingStackTrace!);
      }

      if (!outputEnded && completedReads.containsKey(nextOutputOffset)) {
        final chunk = completedReads.remove(nextOutputOffset);
        if (chunk == null) {
          outputEnded = true;
        } else {
          nextOutputOffset += chunk.length;
          bytesRead += chunk.length;
          scheduleReads();

          yield chunk;
          onProgress?.call(bytesRead);
          continue;
        }
      }

      scheduleReads();
      if (outputEnded) {
        if (pendingReadCount == 0) break;
      } else if (pendingReadCount == 0) {
        break;
      }
      await waitForReadComplete();
    }
  }

  /// Downloads this file into [destination].
  ///
  /// Returns the total number of bytes written.
  Future<int> downloadTo(
    StreamSink<List<int>> destination, {
    int? length,
    int offset = 0,
    void Function(int bytesRead)? onProgress,
    int chunkSize = _kDownloadChunkSize,
    int maxPendingRequests = _kDownloadMaxPendingRequests,
    bool closeDestination = false,
  }) async {
    _mustNotBeClosed();
    var bytesRead = 0;

    try {
      await destination.addStream(
        read(
          length: length,
          offset: offset,
          onProgress: (value) {
            bytesRead = value;
            onProgress?.call(value);
          },
          chunkSize: chunkSize,
          maxPendingRequests: maxPendingRequests,
        ),
      );
    } finally {
      if (closeDestination) {
        await destination.close();
      }
    }

    return bytesRead;
  }

  /// Reads at most [length] bytes from the file starting at [offset]. If
  /// [length] is null, reads until end of the file.
  /// Use [read] if you want to stream large file in chunks.
  Future<Uint8List> readBytes({int? length, int offset = 0}) async {
    final buffer = BytesBuilder(copy: false);
    await for (final chunk in read(length: length, offset: offset)) {
      buffer.add(chunk);
    }
    return buffer.takeBytes();
  }

  /// Writes [stream] to the file starting at [offset].
  ///
  /// Returns a [SftpFileWriter] that can be used to control the write
  /// operation or wait for it to complete. [chunkSize] controls individual
  /// WRITE packet sizes and [maxPendingRequests] bounds the number waiting for
  /// acknowledgement.
  SftpFileWriter write(
    Stream<Uint8List> stream, {
    int offset = 0,
    void Function(int total)? onProgress,
    int chunkSize = defaultChunkSize,
    int maxPendingRequests = defaultMaxPendingRequests,
  }) {
    return SftpFileWriter(
      this,
      stream,
      offset,
      onProgress,
      chunkSize: chunkSize,
      maxPendingRequests: maxPendingRequests,
    );
  }

  /// Writes [data] to the file starting at [offset].
  ///
  /// At most [maxPendingRequests] writes are sent without an acknowledgement.
  /// If a write fails, no new requests are sent and all requests already in
  /// flight are drained before the first error is reported.
  Future<void> writeBytes(
    Uint8List data, {
    int offset = 0,
    int chunkSize = defaultChunkSize,
    int maxPendingRequests = defaultMaxPendingRequests,
  }) async {
    _mustNotBeClosed();
    if (offset < 0) {
      throw ArgumentError.value(offset, 'offset', 'must not be negative');
    }
    if (chunkSize <= 0) {
      throw ArgumentError.value(chunkSize, 'chunkSize', 'must be positive');
    }
    if (maxPendingRequests <= 0) {
      throw ArgumentError.value(
        maxPendingRequests,
        'maxPendingRequests',
        'must be positive',
      );
    }

    var bytesScheduled = 0;
    var nextWriteId = 0;
    final pending = <int, Future<_WriteCompletion>>{};
    Object? firstError;
    StackTrace? firstErrorStackTrace;

    void scheduleWrite() {
      final writeId = nextWriteId++;
      final length = min(chunkSize, data.length - bytesScheduled);
      final chunk = Uint8List.sublistView(
        data,
        bytesScheduled,
        bytesScheduled + length,
      );
      final writeOffset = offset + bytesScheduled;
      bytesScheduled += length;

      pending[writeId] = _writeChunk(chunk, offset: writeOffset).then(
        (_) => _WriteCompletion(writeId),
        onError: (Object error, StackTrace stackTrace) {
          firstError ??= error;
          firstErrorStackTrace ??= stackTrace;
          return _WriteCompletion(writeId);
        },
      );
    }

    while (bytesScheduled < data.length && firstError == null) {
      while (
          bytesScheduled < data.length && pending.length < maxPendingRequests) {
        scheduleWrite();
      }

      final completed = await Future.any(pending.values);
      pending.remove(completed.id);
    }

    while (pending.isNotEmpty) {
      final completed = await Future.any(pending.values);
      pending.remove(completed.id);
    }

    if (firstError != null) {
      Error.throwWithStackTrace(firstError!, firstErrorStackTrace!);
    }
  }

  /// Gets filesystem statistics that this file is on.
  ///
  /// **Note**: This is an extension to the SFTP protocol, supported by most
  /// openssh servers. A [SftpExtensionError] is thrown if the server does not
  /// support this extension.
  ///
  /// See also:
  ///
  /// * [SftpClient.statvfs] which takes a path instead of a file handle as
  ///   argument.
  Future<SftpStatVfs> statvfs() async {
    _mustNotBeClosed();
    await _client._checkExtension('fstatvfs@openssh.com', '2');
    final payload = SftpFstatVfsRequest(handle: _handle);
    final reply = await _client._sendExtended(payload);
    if (reply is SftpStatusPacket) throw SftpStatusError.fromStatus(reply);
    if (reply is! SftpExtendedReplyPacket) throw SftpError('Unexpected reply');
    final stat = SftpStatVfsReply.decode(reply.payload);
    return SftpStatVfs.fromReply(stat);
  }

  Future<void> _writeChunk(Uint8List data, {int offset = 0}) async {
    // print('_writeChunk: offset=$offset');
    _mustNotBeClosed();
    final reply = await _client._sendWrite(_handle, offset, data);
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    SftpStatusError.check(reply);
  }

  /// Reads one chunk from the remote file.
  ///
  /// The single seam [SftpFileDownload.downloadToRandomAccess] needs. It lives
  /// in its own library so that naming `dart:io`'s [RandomAccessFile] does not
  /// pull `dart:io` into this one, which is what kept pub.dev from listing the
  /// package as available on the web.
  @internal
  Future<Uint8List?> readChunk(int length, [int offset = 0]) async {
    _mustNotBeClosed();
    final reply = await _client._sendRead(_handle, offset, length);
    if (reply is SftpDataPacket) return reply.data;
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    SftpStatusError.check(reply);
    return null;
  }

  void _mustNotBeClosed() {
    if (isClosed) throw SftpError('File is closed');
  }

  @override
  String toString() => 'SftpFile(0x${hex.encode(_handle)})';
}

/// Handshake information received from the SFTP server.
class SftpHandsake {
  /// Negotiated SFTP protocol version.
  final int version;

  /// Map of protocol extension names to version strings supported by server.
  final Map<String, String> extensions;

  /// Creates a container for SFTP handshake details.
  SftpHandsake(this.version, this.extensions);

  @override
  String toString() => 'SftpHandsake($version, $extensions)';
}

/// Tracks a pending SFTP read completion for [SftpFile.downloadToRandomAccess].
class _WriteCompletion {
  _WriteCompletion(this.id);

  final int id;
}
