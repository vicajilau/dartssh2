import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:dartssh2/src/sftp/sftp_client.dart';
import 'package:dartssh2/src/sftp/sftp_errors.dart';

/// Mirrors the defaults the SFTP library uses for [SftpFile.downloadTo]. They
/// are private there, and duplicating two numbers is cheaper than widening the
/// internal surface further.
const _kDownloadChunkSize = 64 * 1024;
const _kDownloadMaxPendingRequests = 128;

/// See [SftpFile.read]. Kept in step with the same constant there.
const _kUnboundedReadLength = 1099511627776; // 1 TiB

/// [downloadToRandomAccess] lives here rather than on [SftpFile] itself
/// because it is the only thing in this package that names a `dart:io` type,
/// and naming one from the SFTP library was enough for pub.dev to classify the
/// whole package as unavailable on the web, even though everything else
/// compiles and runs there.
///
/// It reaches [SftpFile] through [SftpFile.readChunk] and [SftpFile.isClosed],
/// both of which are public, so nothing about the call site changes: the same
/// `package:dartssh2/dartssh2.dart` import brings this in wherever `dart:io`
/// exists.
extension SftpFileDownload on SftpFile {
  /// Downloads this file into a random-access local file.
  ///
  /// Unlike [read] and [downloadTo], this method does not require SFTP read
  /// replies to be yielded in offset order. Replies are written to
  /// [destination] at the same offset, allowing pipelined reads to make
  /// progress even when later offsets complete before earlier ones.
  ///
  /// Returns the total number of bytes written.
  Future<int> downloadToRandomAccess(
    RandomAccessFile destination, {
    int? length,
    int offset = 0,
    void Function(int bytesRead)? onProgress,
    int chunkSize = _kDownloadChunkSize,
    int maxPendingRequests = _kDownloadMaxPendingRequests,
  }) async {
    if (isClosed) throw SftpError('File is closed');
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

    // Whether `length` reflects a real, trustworthy byte count. It starts
    // true (an explicit `length` from the caller is always trusted) and is
    // only flipped below when we have to fall back to the stat()-size-0
    // sentinel. It gates the truncation check at the end of this method -
    // see the comment there for why that check can't just compare against
    // the (possibly sentinel) `length` value directly.
    var lengthIsKnown = true;

    if (length == null) {
      final fileSize = (await stat()).size;
      if (fileSize == null) {
        throw SftpError('Can not get file size');
      }
      length = fileSize - offset;

      // Some filesystems report a size of 0 for files that actually contain
      // data (e.g. Linux /proc entries, character/device files). SFTP
      // signals end-of-file via the SSH_FX_EOF status code, not via the
      // reported size, so don't trust a stat()-derived size of 0 as
      // "nothing to download" - see the matching comment in [read] for the
      // full reasoning. Fall back to downloading until the server tells us
      // we've hit EOF instead. This only applies when we computed `length`
      // ourselves; a caller who explicitly passes `length: 0` still gets an
      // empty, zero-byte download below.
      if (length == 0) {
        length = _kUnboundedReadLength;
        lengthIsKnown = false;
        // See [read]: with the real end unknown, the reservation logic
        // below can't tell when to stop fanning out speculative reads, so
        // force strictly sequential requests instead of fanning out up to
        // [maxPendingRequests] of them into a file that may only be a few
        // bytes long. Because writes here go to their own offset (not
        // gated on in-order arrival like [read]), concurrency wouldn't be
        // *incorrect* - just wasteful for the common case this exists for.
        maxPendingRequests = 1;
      }
    }

    if (length == 0) return 0;
    if (length < 0) {
      throw SftpError('Length must be positive: $length');
    }

    final endOffset = offset + length;
    final completionQueue = <_ReadCompletion>[];
    var reservedOffset = offset;
    var bytesWritten = 0;
    var pendingReadCount = 0;
    var activeReadLimit = 1;
    var effectiveChunkSize = chunkSize;
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
      if (completionQueue.isNotEmpty || pendingError != null) {
        return Future.value();
      }
      final signal = completionSignal = Completer<void>();
      return signal.future.whenComplete(() {
        if (identical(completionSignal, signal)) {
          completionSignal = null;
        }
      });
    }

    void issueRead(int startOffset, int requestLength) {
      pendingReadCount++;
      readChunk(requestLength, startOffset).then(
        (chunk) {
          pendingReadCount--;
          if (chunk != null && chunk.isNotEmpty) {
            activeReadLimit = min(maxPendingRequests, activeReadLimit + 1);
          }
          completionQueue.add(_ReadCompletion(startOffset, chunk));
          if (chunk != null &&
              chunk.isNotEmpty &&
              chunk.length < requestLength &&
              startOffset + chunk.length < endOffset) {
            effectiveChunkSize = max(1, min(effectiveChunkSize, chunk.length));
            issueRead(
              startOffset + chunk.length,
              min(
                requestLength - chunk.length,
                endOffset - startOffset - chunk.length,
              ),
            );
          }
          notifyReadComplete();
        },
        onError: (Object error, StackTrace stackTrace) {
          pendingReadCount--;
          pendingError = error;
          pendingStackTrace = stackTrace;
          notifyReadComplete();
        },
      );
    }

    void scheduleReads() {
      while (reservedOffset < endOffset && pendingReadCount < activeReadLimit) {
        final startOffset = reservedOffset;
        final requestLength =
            min(effectiveChunkSize, endOffset - reservedOffset);
        issueRead(startOffset, requestLength);
        reservedOffset += requestLength;
      }
    }

    scheduleReads();

    while (bytesWritten < length) {
      if (pendingError != null) {
        Error.throwWithStackTrace(pendingError!, pendingStackTrace!);
      }

      if (completionQueue.isEmpty) {
        if (pendingReadCount == 0) break;
        await waitForReadComplete();
        continue;
      }

      final completion = completionQueue.removeAt(0);
      final startOffset = completion.startOffset;
      final chunk = completion.chunk;
      if (chunk == null) break;
      if (chunk.isEmpty) {
        throw SftpError('Unexpected empty data chunk before EOF');
      }

      final remaining = length - (startOffset - offset);
      final outputChunk = chunk.length <= remaining
          ? chunk
          : Uint8List.sublistView(chunk, 0, remaining);
      await destination.setPosition(startOffset);
      await destination.writeFrom(outputChunk);

      bytesWritten += outputChunk.length;
      onProgress?.call(bytesWritten);
      scheduleReads();
    }

    // Only enforce the truncation check when `length` is a real target byte
    // count. When it's the unbounded sentinel (stat() reported size 0 but
    // EOF is what actually ended the loop above), `bytesWritten` will almost
    // never equal the sentinel and this would misfire on every such
    // download, including genuinely-complete ones and genuinely-empty ones.
    if (lengthIsKnown && bytesWritten != length) {
      throw SftpError(
        'Incomplete download: received $bytesWritten of $length bytes',
      );
    }

    return bytesWritten;
  }
}

class _ReadCompletion {
  _ReadCompletion(this.startOffset, this.chunk);

  final int startOffset;
  final Uint8List? chunk;
}
