@TestOn('vm')
library;

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:dartssh2/src/message/msg_channel.dart';
import 'package:dartssh2/src/sftp/sftp_client.dart';
import 'package:dartssh2/src/sftp/sftp_file_io.dart';
import 'package:dartssh2/src/sftp/sftp_errors.dart';
import 'package:dartssh2/src/sftp/sftp_file_attrs.dart';
import 'package:dartssh2/src/sftp/sftp_packet.dart';
import 'package:dartssh2/src/sftp/sftp_status_code.dart';
import 'package:dartssh2/src/ssh_channel.dart';
import 'package:dartssh2/src/ssh_message.dart';
import 'package:test/test.dart';

const _openSshMaxSftpPacketLength = 256 * 1024;

void main() {
  group('SftpClient protocol', () {
    test('handshake completes with version packet', () async {
      final harness = _SftpHarness();
      final initPayload = await harness.nextOutgoingPacket();
      final init = SftpInitPacket.decode(initPayload);
      expect(init.version, 3);

      harness.sendResponsePacket(
        SftpVersionPacket(3, {'fstatvfs@openssh.com': '2'}),
      );

      final handshake = await harness.client.handshake;
      expect(handshake.version, 3);
      expect(handshake.extensions['fstatvfs@openssh.com'], '2');

      harness.dispose();
    });

    test('accepts an incoming packet at the OpenSSH size limit', () async {
      final harness = _SftpHarness();
      await harness.nextOutgoingPacket();

      final payload = Uint8List(_openSshMaxSftpPacketLength);
      payload[0] = 0xff; // Unknown packets are ignored by the client.
      harness.sendResponsePayload(payload);
      harness.sendResponsePacket(SftpVersionPacket(3));

      await expectLater(harness.client.handshake, completes);
      harness.dispose();
    });

    test('rejects an oversized incoming packet from its length header',
        () async {
      final harness = _SftpHarness();
      await harness.nextOutgoingPacket();
      harness.sendResponsePacket(SftpVersionPacket(3));
      await harness.client.handshake;

      final openFuture = harness.client.open('/tmp/file');
      await harness.nextOutgoingPacket();
      final openExpectation = expectLater(
        openFuture,
        throwsA(
          isA<SftpError>().having(
            (error) => error.message,
            'message',
            contains('${_openSshMaxSftpPacketLength + 1} bytes'),
          ),
        ),
      );

      harness.sendResponseLength(_openSshMaxSftpPacketLength + 1);

      await openExpectation;
      await expectLater(harness.channelDone, completes);
      harness.dispose();
    });

    test('rejects an outgoing packet over the OpenSSH size limit', () async {
      final channel = _SynchronousResponseChannel();
      final client = SftpClient(channel);
      channel.sendResponsePacket(SftpVersionPacket(3));
      await client.handshake;
      final packetsBeforeRequest = channel.outboundPacketCount;
      final oversizedPathBytes = Uint8List(_openSshMaxSftpPacketLength)
        ..fillRange(0, _openSshMaxSftpPacketLength, 0x78);
      final oversizedPath = String.fromCharCodes(oversizedPathBytes);

      await expectLater(
        client.stat(oversizedPath),
        throwsA(
          isA<SftpError>().having(
            (error) => error.message,
            'message',
            contains('Outgoing SFTP packet is too large'),
          ),
        ),
      );
      expect(channel.outboundPacketCount, packetsBeforeRequest);
      await client.close();
    });

    test('stat uses lstat when followLink is false', () async {
      final harness = _SftpHarness();
      await harness.nextOutgoingPacket();
      harness.sendResponsePacket(SftpVersionPacket(3));
      await harness.client.handshake;

      final statFuture = harness.client.stat('/tmp/file', followLink: false);
      final packet = await harness.nextOutgoingPacket();
      final lstat = SftpLStatPacket.decode(packet);

      harness.sendResponsePacket(
        SftpAttrsPacket(
          lstat.requestId,
          SftpFileAttrs(size: 55, mode: const SftpFileMode.value(1 << 15)),
        ),
      );

      final attrs = await statFuture;
      expect(attrs.size, 55);
      expect(attrs.isFile, isTrue);

      harness.dispose();
    });

    test('stat throws SftpStatusError on failure status', () async {
      final harness = _SftpHarness();
      await harness.nextOutgoingPacket();
      harness.sendResponsePacket(SftpVersionPacket(3));
      await harness.client.handshake;

      final statFuture = harness.client.stat('/tmp/file');
      final packet = await harness.nextOutgoingPacket();
      final stat = SftpStatPacket.decode(packet);

      harness.sendResponsePacket(
        SftpStatusPacket(
          requestId: stat.requestId,
          code: SftpStatusCode.permissionDenied,
          message: 'denied',
        ),
      );

      await expectLater(
        statFuture,
        throwsA(
          isA<SftpStatusError>()
              .having((e) => e.code, 'code', SftpStatusCode.permissionDenied),
        ),
      );

      harness.dispose();
    });

    test('close aborts pending requests', () async {
      final harness = _SftpHarness();
      await harness.nextOutgoingPacket();
      harness.sendResponsePacket(SftpVersionPacket(3));
      await harness.client.handshake;

      final openFuture = harness.client.open('/tmp/f');
      await harness.nextOutgoingPacket();

      unawaited(harness.client.close());

      await expectLater(openFuture, throwsA(isA<SftpAbortError>()));
      harness.dispose();
    });

    test('remote channel close aborts the handshake', () async {
      final harness = _SftpHarness();
      await harness.nextOutgoingPacket();
      final handshakeExpectation = expectLater(
        harness.client.handshake,
        throwsA(isA<SftpAbortError>()),
      );

      harness.closeRemote();

      await handshakeExpectation;
      harness.dispose();
    });

    test('remote channel close aborts pending requests', () async {
      final harness = _SftpHarness();
      await harness.nextOutgoingPacket();
      harness.sendResponsePacket(SftpVersionPacket(3));
      await harness.client.handshake;

      final openFuture = harness.client.open('/tmp/f');
      await harness.nextOutgoingPacket();
      final openExpectation = expectLater(
        openFuture,
        throwsA(isA<SftpAbortError>()),
      );

      harness.closeRemote();

      await openExpectation;
      harness.dispose();
    });

    test('stream error and done terminate the client only once', () async {
      final channel = _SynchronousResponseChannel();
      final client = SftpClient(channel);
      final error = StateError('stream failed');
      final handshakeExpectation = expectLater(
        client.handshake,
        throwsA(same(error)),
      );

      channel.fail(error);
      await channel.finish();

      await handshakeExpectation;
      await expectLater(client.close(), completes);
      await expectLater(client.close(), completes);
    });

    test('requests after stream termination fail before sending a packet',
        () async {
      final channel = _SynchronousResponseChannel();
      final client = SftpClient(channel);
      channel.sendResponsePacket(SftpVersionPacket(3));
      await client.handshake;

      await channel.finish();
      await Future<void>.delayed(Duration.zero);
      final packetsBeforeRequest = channel.outboundPacketCount;

      await expectLater(
        client.stat('/tmp/f'),
        throwsA(isA<SftpAbortError>()),
      );
      expect(channel.outboundPacketCount, packetsBeforeRequest);
      await client.close();
    });

    test('close closes the underlying channel', () async {
      final harness = _SftpHarness();
      await harness.nextOutgoingPacket();
      harness.sendResponsePacket(SftpVersionPacket(3));
      await harness.client.handshake;

      final closeFuture = harness.client.close();
      // The server acks the channel close, letting the teardown complete.
      harness.closeRemote();
      await closeFuture;

      await expectLater(harness.channelDone, completes);
      harness.dispose();
    });

    test('request waiter is registered before packet is sent', () async {
      final channel = _SynchronousResponseChannel();
      final client = SftpClient(channel);

      channel.sendResponsePacket(SftpVersionPacket(3));
      await client.handshake;

      channel.respondDuringAddData((payload) {
        final stat = SftpStatPacket.decode(payload);
        return SftpAttrsPacket(
          stat.requestId,
          SftpFileAttrs(size: 9, mode: const SftpFileMode.value(1 << 15)),
        );
      });

      final attrs = await client.stat('/tmp/file').timeout(
            const Duration(seconds: 1),
          );
      expect(attrs.size, 9);

      await client.close();
    });

    test('read ramps and replenishes its pipeline for out-of-order replies',
        () async {
      final harness = _SftpHarness();
      await harness.nextOutgoingPacket();
      harness.sendResponsePacket(SftpVersionPacket(3));
      await harness.client.handshake;

      final sink = _CollectingSink();
      final downloadFuture = harness.client.download(
        '/tmp/file',
        sink,
        length: 16,
        chunkSize: 4,
        maxPendingRequests: 2,
      );

      final open = SftpOpenPacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpHandlePacket(open.requestId, Uint8List.fromList([1, 2, 3])),
      );

      final read1 = SftpReadPacket.decode(await harness.nextOutgoingPacket());
      expect(read1.offset, 0);

      final nextReads = harness.nextOutgoingPackets(2);
      harness.sendResponsePacket(
        SftpDataPacket(read1.requestId, Uint8List.fromList('ABCD'.codeUnits)),
      );

      final reads = (await nextReads).map(SftpReadPacket.decode).toList();
      final read2 = reads[0];
      final read3 = reads[1];
      expect(read2.offset, 4);
      expect(read3.offset, 8);

      final read4Future = harness.nextOutgoingPacket();
      harness.sendResponsePacket(
        SftpDataPacket(read3.requestId, Uint8List.fromList('IJKL'.codeUnits)),
      );
      final read4 = SftpReadPacket.decode(await read4Future);
      expect(read4.offset, 12);

      harness.sendResponsePacket(
        SftpDataPacket(read4.requestId, Uint8List.fromList('MNOP'.codeUnits)),
      );
      harness.sendResponsePacket(
        SftpDataPacket(read2.requestId, Uint8List.fromList('EFGH'.codeUnits)),
      );

      final close = SftpClosePacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpStatusPacket(
          requestId: close.requestId,
          code: SftpStatusCode.ok,
          message: 'ok',
        ),
      );

      final bytes = await downloadFuture;
      expect(bytes, 16);
      expect(sink.bytes, Uint8List.fromList('ABCDEFGHIJKLMNOP'.codeUnits));

      harness.dispose();
    });

    test('a one-off tiny reply does not shrink later reads', () async {
      final lengths = await _recordReadLengths(
        totalLength: 8192 * 3,
        chunkSize: 8192,
        firstReplyLength: 1,
      );

      // The suffix is retried, and the reads after it stay at full size
      // instead of being pinned to the 512 byte floor.
      expect(lengths, [8192, 8191, 8192, 8192]);
    });

    // These two pin down how many round trips a download costs. The 512 byte
    // collapse fixed in 3.0.2 was found by hand: every read after a single
    // short reply shrank to the floor and never recovered, which is invisible
    // to a test that only checks the bytes that come out.
    test('a clean download costs exactly one read per chunk', () async {
      final lengths = await _recordReadLengths(
        totalLength: 1024 * 1024,
        chunkSize: 64 * 1024,
      );

      expect(lengths, hasLength(16));
      expect(lengths.every((length) => length == 64 * 1024), isTrue);
    });

    test('one tiny short reply costs exactly one extra read', () async {
      final lengths = await _recordReadLengths(
        totalLength: 1024 * 1024,
        chunkSize: 64 * 1024,
        firstReplyLength: 1,
      );

      // 16 chunks plus a single retry for the byte that was missed.
      expect(lengths, hasLength(17));
      expect(lengths[1], 64 * 1024 - 1);
      expect(lengths.skip(2).every((length) => length == 64 * 1024), isTrue);
    });

    test('a large short reply clamps later reads, as OpenSSH does', () async {
      final lengths = await _recordReadLengths(
        totalLength: 8192 * 3,
        chunkSize: 8192,
        firstReplyLength: 4096,
      );

      // A reply this size reads as the server's real capacity, so the client
      // settles there and stops asking for more than the server will give.
      expect(lengths, [8192, 4096, 4096, 4096, 4096, 4096]);
    });

    test('read retries the missing suffix after a short data packet', () async {
      final harness = _SftpHarness();
      await harness.nextOutgoingPacket();
      harness.sendResponsePacket(SftpVersionPacket(3));
      await harness.client.handshake;

      final sink = _CollectingSink();
      final downloadFuture = harness.client.download(
        '/tmp/file',
        sink,
        length: 1536,
        chunkSize: 1024,
        maxPendingRequests: 2,
      );

      final open = SftpOpenPacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpHandlePacket(open.requestId, Uint8List.fromList([1, 2, 3])),
      );

      final read1 = SftpReadPacket.decode(await harness.nextOutgoingPacket());
      expect(read1.offset, 0);
      expect(read1.length, 1024);

      final nextReads = harness.nextOutgoingPackets(2);
      harness.sendResponsePacket(
        SftpDataPacket(read1.requestId, Uint8List.fromList([1])),
      );

      final reads = (await nextReads).map(SftpReadPacket.decode).toList();
      final retry = reads[0];
      final read2 = reads[1];
      expect(retry.offset, 1);
      expect(retry.length, 1023);
      expect(read2.offset, 1024);
      expect(read2.length, 512);

      harness.sendResponsePacket(
        SftpDataPacket(
          read2.requestId,
          Uint8List.fromList(List<int>.filled(512, 3)),
        ),
      );
      harness.sendResponsePacket(
        SftpDataPacket(
          retry.requestId,
          Uint8List.fromList(List<int>.filled(1023, 2)),
        ),
      );

      final close = SftpClosePacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpStatusPacket(
          requestId: close.requestId,
          code: SftpStatusCode.ok,
          message: 'ok',
        ),
      );

      final bytes = await downloadFuture;
      expect(bytes, 1536);
      expect(
        sink.bytes,
        Uint8List.fromList([
          1,
          ...List<int>.filled(1023, 2),
          ...List<int>.filled(512, 3),
        ]),
      );

      harness.dispose();
    });

    test('read rejects invalid pipeline settings', () async {
      final harness = _SftpHarness();
      await harness.nextOutgoingPacket();
      harness.sendResponsePacket(SftpVersionPacket(3));
      await harness.client.handshake;

      final fileFuture = harness.client.open('/tmp/file');
      final open = SftpOpenPacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpHandlePacket(open.requestId, Uint8List.fromList([1, 2, 3])),
      );
      final file = await fileFuture;

      await expectLater(
        file.read(chunkSize: 0).toList(),
        throwsA(isA<ArgumentError>()),
      );
      await expectLater(
        file.read(maxPendingRequests: 0).toList(),
        throwsA(isA<ArgumentError>()),
      );

      final closeFuture = file.close();
      final close = SftpClosePacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpStatusPacket(
          requestId: close.requestId,
          code: SftpStatusCode.ok,
          message: 'ok',
        ),
      );
      await closeFuture;
      harness.dispose();
    });

    test('downloadTo can close destination sink', () async {
      final harness = _SftpHarness();
      await harness.nextOutgoingPacket();
      harness.sendResponsePacket(SftpVersionPacket(3));
      await harness.client.handshake;

      final fileFuture = harness.client.open('/tmp/file');
      final open = SftpOpenPacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpHandlePacket(open.requestId, Uint8List.fromList([1, 2, 3])),
      );
      final file = await fileFuture;

      final sink = _CollectingSink();
      final downloadFuture = file.downloadTo(
        sink,
        length: 4,
        chunkSize: 4,
        maxPendingRequests: 1,
        closeDestination: true,
      );

      final read = SftpReadPacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpDataPacket(read.requestId, Uint8List.fromList('ABCD'.codeUnits)),
      );

      final bytes = await downloadFuture;
      expect(bytes, 4);
      expect(sink.bytes, Uint8List.fromList('ABCD'.codeUnits));
      expect(sink.isClosed, isTrue);

      final closeFuture = file.close();
      final close = SftpClosePacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpStatusPacket(
          requestId: close.requestId,
          code: SftpStatusCode.ok,
          message: 'ok',
        ),
      );
      await closeFuture;
      harness.dispose();
    });

    test('downloadTo reports progress callback', () async {
      final harness = _SftpHarness();
      await harness.nextOutgoingPacket();
      harness.sendResponsePacket(SftpVersionPacket(3));
      await harness.client.handshake;

      final fileFuture = harness.client.open('/tmp/file');
      final open = SftpOpenPacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpHandlePacket(open.requestId, Uint8List.fromList([1, 2, 3])),
      );
      final file = await fileFuture;

      var progress = -1;
      final sink = _CollectingSink();
      final downloadFuture = file.downloadTo(
        sink,
        length: 4,
        chunkSize: 4,
        maxPendingRequests: 1,
        onProgress: (value) => progress = value,
      );

      final read = SftpReadPacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpDataPacket(read.requestId, Uint8List.fromList('ABCD'.codeUnits)),
      );

      final bytes = await downloadFuture;
      expect(bytes, 4);
      expect(progress, 4);

      final closeFuture = file.close();
      final close = SftpClosePacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpStatusPacket(
          requestId: close.requestId,
          code: SftpStatusCode.ok,
          message: 'ok',
        ),
      );
      await closeFuture;
      harness.dispose();
    });

    test('download infers length from stat when not provided', () async {
      final harness = _SftpHarness();
      await harness.nextOutgoingPacket();
      harness.sendResponsePacket(SftpVersionPacket(3));
      await harness.client.handshake;

      final sink = _CollectingSink();
      final downloadFuture = harness.client.download('/tmp/file', sink);

      final open = SftpOpenPacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpHandlePacket(open.requestId, Uint8List.fromList([1, 2, 3])),
      );

      final fstat = SftpFStatPacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpAttrsPacket(
          fstat.requestId,
          SftpFileAttrs(size: 4, mode: const SftpFileMode.value(1 << 15)),
        ),
      );

      final read = SftpReadPacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpDataPacket(read.requestId, Uint8List.fromList('WXYZ'.codeUnits)),
      );

      final close = SftpClosePacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpStatusPacket(
          requestId: close.requestId,
          code: SftpStatusCode.ok,
          message: 'ok',
        ),
      );

      final bytes = await downloadFuture;
      expect(bytes, 4);
      expect(sink.bytes, Uint8List.fromList('WXYZ'.codeUnits));
      harness.dispose();
    });

    test('write() returns writer and writes streamed data', () async {
      final harness = _SftpHarness();
      await harness.nextOutgoingPacket();
      harness.sendResponsePacket(SftpVersionPacket(3));
      await harness.client.handshake;

      final fileFuture = harness.client.open('/tmp/file');
      final open = SftpOpenPacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpHandlePacket(open.requestId, Uint8List.fromList([1, 2, 3])),
      );
      final file = await fileFuture;

      final writer = file.write(
        Stream.value(Uint8List.fromList('ABCD'.codeUnits)),
      );

      final write = SftpWritePacket.decode(await harness.nextOutgoingPacket());
      expect(write.offset, 0);
      expect(write.data, Uint8List.fromList('ABCD'.codeUnits));

      harness.sendResponsePacket(
        SftpStatusPacket(
          requestId: write.requestId,
          code: SftpStatusCode.ok,
          message: 'ok',
        ),
      );

      await writer.done;
      expect(writer.progress, 4);

      final closeFuture = file.close();
      final close = SftpClosePacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpStatusPacket(
          requestId: close.requestId,
          code: SftpStatusCode.ok,
          message: 'ok',
        ),
      );
      await closeFuture;
      harness.dispose();
    });

    test('rename uses posix-rename extension when advertised', () async {
      final harness = _SftpHarness();
      await harness.nextOutgoingPacket();
      harness.sendResponsePacket(
        SftpVersionPacket(3, {'posix-rename@openssh.com': '1'}),
      );
      await harness.client.handshake;

      final renameFuture = harness.client.rename('/tmp/a', '/tmp/b');
      final packet = await harness.nextOutgoingPacket();
      final extended = SftpExtendedPacket.decode(packet);

      harness.sendResponsePacket(
        SftpStatusPacket(
          requestId: extended.requestId,
          code: SftpStatusCode.ok,
          message: 'ok',
        ),
      );

      await renameFuture;
      harness.dispose();
    });

    test('rename falls back to SSH_FXP_RENAME without extension', () async {
      final harness = _SftpHarness();
      await harness.nextOutgoingPacket();
      harness.sendResponsePacket(SftpVersionPacket(3));
      await harness.client.handshake;

      final renameFuture = harness.client.rename('/tmp/a', '/tmp/b');
      final packet = await harness.nextOutgoingPacket();
      final rename = SftpRenamePacket.decode(packet);
      expect(rename.oldPath, '/tmp/a');
      expect(rename.newPath, '/tmp/b');

      harness.sendResponsePacket(
        SftpStatusPacket(
          requestId: rename.requestId,
          code: SftpStatusCode.ok,
          message: 'ok',
        ),
      );

      await renameFuture;
      harness.dispose();
    });

    test('downloadToRandomAccess writes out-of-order chunks at offset',
        () async {
      final harness = _SftpHarness();
      await harness.nextOutgoingPacket();
      harness.sendResponsePacket(SftpVersionPacket(3));
      await harness.client.handshake;

      final fileFuture = harness.client.open('/tmp/file');
      final open = SftpOpenPacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpHandlePacket(open.requestId, Uint8List.fromList([1, 2, 3])),
      );
      final file = await fileFuture;

      final tempDir = await Directory.systemTemp.createTemp('sftp_ra_test');
      final tempFile = File('${tempDir.path}/ra.bin');
      final raf = await tempFile.open(mode: FileMode.write);

      final downloadFuture = file.downloadToRandomAccess(
        raf,
        length: 12,
        chunkSize: 4,
        maxPendingRequests: 2,
      );

      // activeReadLimit starts at 1, so only read1 is issued initially.
      final read1 = SftpReadPacket.decode(await harness.nextOutgoingPacket());
      expect(read1.offset, 0);
      // Replying to read1 bumps activeReadLimit to 2, which schedules read2
      // and read3 together (both fit within the limit now).
      harness.sendResponsePacket(
        SftpDataPacket(read1.requestId, Uint8List.fromList('ABCD'.codeUnits)),
      );
      final read2 = SftpReadPacket.decode(await harness.nextOutgoingPacket());
      final read3 = SftpReadPacket.decode(await harness.nextOutgoingPacket());
      expect(read2.offset, 4);
      expect(read3.offset, 8);

      // Reply out of order: read3 before read2. downloadToRandomAccess must
      // write each chunk at its own offset regardless of arrival order.
      harness.sendResponsePacket(
        SftpDataPacket(read3.requestId, Uint8List.fromList('IJKL'.codeUnits)),
      );
      harness.sendResponsePacket(
        SftpDataPacket(read2.requestId, Uint8List.fromList('EFGH'.codeUnits)),
      );

      final bytes = await downloadFuture;
      expect(bytes, 12);

      final closeFuture = file.close();
      final close = SftpClosePacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpStatusPacket(
          requestId: close.requestId,
          code: SftpStatusCode.ok,
          message: 'ok',
        ),
      );
      await closeFuture;

      await raf.close();

      final contents = await tempFile.readAsBytes();
      expect(contents, Uint8List.fromList('ABCDEFGHIJKL'.codeUnits));

      await tempDir.delete(recursive: true);
      harness.dispose();
    });

    test(
        'downloadToRandomAccess falls back to EOF-driven reads for virtual '
        'files that report stat size 0 but actually contain data', () async {
      final harness = _SftpHarness();
      await harness.nextOutgoingPacket();
      harness.sendResponsePacket(SftpVersionPacket(3));
      await harness.client.handshake;

      final fileFuture = harness.client.open('/proc/virtual');
      final open = SftpOpenPacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpHandlePacket(open.requestId, Uint8List.fromList([1])),
      );
      final file = await fileFuture;

      final tempDir =
          await Directory.systemTemp.createTemp('sftp_ra_virtual_test');
      final tempFile = File('${tempDir.path}/virtual.bin');
      final raf = await tempFile.open(mode: FileMode.write);

      // No explicit `length`, so downloadToRandomAccess must stat() first.
      final downloadFuture = file.downloadToRandomAccess(raf);

      final statPacket = await harness.nextOutgoingPacket();
      final fstat = SftpFStatPacket.decode(statPacket);
      harness.sendResponsePacket(
        SftpAttrsPacket(fstat.requestId, SftpFileAttrs(size: 0)),
      );

      // A real read request must still be issued even though stat()
      // reported size 0 - EOF is what actually terminates the download.
      final readPacket = await harness.nextOutgoingPacket();
      final read = SftpReadPacket.decode(readPacket);
      harness.sendResponsePacket(
        SftpDataPacket(read.requestId, Uint8List.fromList([1, 2, 3, 4])),
      );

      // The short reply triggers a follow-up read to fill out the original
      // (sentinel-sized) request; respond to it with EOF.
      final followUpPacket = await harness.nextOutgoingPacket();
      final followUpRead = SftpReadPacket.decode(followUpPacket);
      harness.sendResponsePacket(
        SftpStatusPacket(
          requestId: followUpRead.requestId,
          code: SftpStatusCode.eof,
          message: '',
        ),
      );

      final bytesWritten = await downloadFuture;
      expect(bytesWritten, 4);

      await raf.close();
      final contents = await tempFile.readAsBytes();
      expect(contents, Uint8List.fromList([1, 2, 3, 4]));

      await tempDir.delete(recursive: true);
      harness.dispose();
    });

    test(
        'downloadToRandomAccess on a genuinely empty file (stat size 0) '
        'completes with zero bytes and no error', () async {
      final harness = _SftpHarness();
      await harness.nextOutgoingPacket();
      harness.sendResponsePacket(SftpVersionPacket(3));
      await harness.client.handshake;

      final fileFuture = harness.client.open('/tmp/empty');
      final open = SftpOpenPacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpHandlePacket(open.requestId, Uint8List.fromList([1])),
      );
      final file = await fileFuture;

      final tempDir =
          await Directory.systemTemp.createTemp('sftp_ra_empty_test');
      final tempFile = File('${tempDir.path}/empty.bin');
      final raf = await tempFile.open(mode: FileMode.write);

      final downloadFuture = file.downloadToRandomAccess(raf);

      final statPacket = await harness.nextOutgoingPacket();
      final fstat = SftpFStatPacket.decode(statPacket);
      harness.sendResponsePacket(
        SftpAttrsPacket(fstat.requestId, SftpFileAttrs(size: 0)),
      );

      // The very first read request comes back as EOF immediately, since
      // the file is genuinely empty.
      final readPacket = await harness.nextOutgoingPacket();
      final read = SftpReadPacket.decode(readPacket);
      harness.sendResponsePacket(
        SftpStatusPacket(
          requestId: read.requestId,
          code: SftpStatusCode.eof,
          message: '',
        ),
      );

      final bytesWritten = await downloadFuture;
      expect(bytesWritten, 0);

      await raf.close();
      final contents = await tempFile.readAsBytes();
      expect(contents, isEmpty);

      await tempDir.delete(recursive: true);
      harness.dispose();
    });

    test(
        'downloadToRandomAccess still raises on a genuine short read '
        'against a known length', () async {
      final harness = _SftpHarness();
      await harness.nextOutgoingPacket();
      harness.sendResponsePacket(SftpVersionPacket(3));
      await harness.client.handshake;

      final fileFuture = harness.client.open('/tmp/short');
      final open = SftpOpenPacket.decode(await harness.nextOutgoingPacket());
      harness.sendResponsePacket(
        SftpHandlePacket(open.requestId, Uint8List.fromList([1])),
      );
      final file = await fileFuture;

      final tempDir =
          await Directory.systemTemp.createTemp('sftp_ra_short_test');
      final tempFile = File('${tempDir.path}/short.bin');
      final raf = await tempFile.open(mode: FileMode.write);

      // An explicit, known length of 10 bytes.
      final downloadFuture = file.downloadToRandomAccess(raf, length: 10);

      final read = SftpReadPacket.decode(await harness.nextOutgoingPacket());
      expect(read.length, 10);
      harness.sendResponsePacket(
        SftpDataPacket(read.requestId, Uint8List.fromList([1, 2, 3, 4])),
      );

      // The short 4-byte reply triggers a follow-up read for the remaining
      // 6 bytes; the server unexpectedly reports EOF instead of supplying
      // them. Since the target length was known up front, this must still
      // be treated as a truncated download, not a virtual/unbounded file.
      final followUp =
          SftpReadPacket.decode(await harness.nextOutgoingPacket());
      expect(followUp.offset, 4);
      harness.sendResponsePacket(
        SftpStatusPacket(
          requestId: followUp.requestId,
          code: SftpStatusCode.eof,
          message: '',
        ),
      );

      await expectLater(
        downloadFuture,
        throwsA(isA<SftpError>().having(
          (e) => e.message,
          'message',
          contains('Incomplete download'),
        )),
      );

      await raf.close();
      await tempDir.delete(recursive: true);
      harness.dispose();
    });
  });
}

class _CollectingSink implements StreamSink<List<int>> {
  final BytesBuilder _builder = BytesBuilder(copy: false);
  final Completer<void> _done = Completer<void>();
  var _isClosed = false;

  Uint8List get bytes => _builder.toBytes();

  bool get isClosed => _isClosed;

  @override
  void add(List<int> event) {
    _builder.add(event);
  }

  @override
  void addError(Object error, [StackTrace? stackTrace]) {}

  @override
  Future<void> addStream(Stream<List<int>> stream) async {
    await for (final chunk in stream) {
      add(chunk);
    }
  }

  @override
  Future<void> close() async {
    _isClosed = true;
    if (!_done.isCompleted) {
      _done.complete();
    }
  }

  @override
  Future<void> get done => _done.future;
}

/// Downloads [totalLength] bytes, answering the first read with only
/// [firstReplyLength] bytes and filling every read after it, and returns the
/// length the client asked for on each read request.
Future<List<int>> _recordReadLengths({
  required int totalLength,
  required int chunkSize,
  int? firstReplyLength,
}) async {
  final harness = _SftpHarness();
  await harness.nextOutgoingPacket();
  harness.sendResponsePacket(SftpVersionPacket(3));
  await harness.client.handshake;

  final sink = _CollectingSink();
  final downloadFuture = harness.client.download(
    '/tmp/file',
    sink,
    length: totalLength,
    chunkSize: chunkSize,
    maxPendingRequests: 1,
  );

  final open = SftpOpenPacket.decode(await harness.nextOutgoingPacket());
  harness.sendResponsePacket(
    SftpHandlePacket(open.requestId, Uint8List.fromList([1, 2, 3])),
  );

  final requestedLengths = <int>[];
  var delivered = 0;

  while (delivered < totalLength) {
    final packet = await harness.nextOutgoingPacket();
    if (packet[0] != SftpReadPacket.packetType) break;

    final read = SftpReadPacket.decode(packet);
    requestedLengths.add(read.length);

    final replyLength = requestedLengths.length == 1
        ? (firstReplyLength ?? read.length)
        : read.length;
    delivered += replyLength;

    harness.sendResponsePacket(
      SftpDataPacket(
        read.requestId,
        Uint8List.fromList(List<int>.filled(replyLength, 7)),
      ),
    );
  }

  final close = SftpClosePacket.decode(await harness.nextOutgoingPacket());
  harness.sendResponsePacket(
    SftpStatusPacket(
      requestId: close.requestId,
      code: SftpStatusCode.ok,
      message: 'ok',
    ),
  );

  expect(await downloadFuture, totalLength);
  expect(sink.bytes, hasLength(totalLength));

  harness.dispose();
  return requestedLengths;
}

class _SftpHarness {
  _SftpHarness() {
    _controller = SSHChannelController(
      localId: 1,
      localMaximumPacketSize: 1024 * 1024,
      localInitialWindowSize: 1024 * 1024,
      remoteId: 2,
      remoteMaximumPacketSize: 1024 * 1024,
      remoteInitialWindowSize: 1024 * 1024,
      sendMessage: _handleOutboundMessage,
    );
    client = SftpClient(_controller.channel);
  }

  late final SSHChannelController _controller;
  late final SftpClient client;

  final _outgoing = StreamController<Uint8List>.broadcast();
  var _disposed = false;

  void _handleOutboundMessage(SSHMessage message) {
    if (message is! SSH_Message_Channel_Data) return;
    final reader = SSHMessageReader(message.data);
    final length = reader.readUint32();
    final payload = reader.readBytes(length);
    _outgoing.add(payload);
  }

  Future<Uint8List> nextOutgoingPacket() => _outgoing.stream.first;

  Future<List<Uint8List>> nextOutgoingPackets(int count) =>
      _outgoing.stream.take(count).toList();

  Future<void> get channelDone => _controller.channel.done;

  void closeRemote() {
    _controller.handleMessage(
      SSH_Message_Channel_Close(recipientChannel: _controller.localId),
    );
  }

  void sendResponsePacket(SftpPacket packet) {
    sendResponsePayload(packet.encode());
  }

  void sendResponsePayload(Uint8List payload) {
    final writer = SSHMessageWriter();
    writer.writeUint32(payload.length);
    writer.writeBytes(payload);

    _sendResponseData(writer.takeBytes());
  }

  void sendResponseLength(int length) {
    final writer = SSHMessageWriter();
    writer.writeUint32(length);
    _sendResponseData(writer.takeBytes());
  }

  void _sendResponseData(Uint8List data) {
    _controller.handleMessage(
      SSH_Message_Channel_Data(
        recipientChannel: _controller.localId,
        data: data,
      ),
    );
  }

  void dispose() {
    if (_disposed) return;
    _disposed = true;

    unawaited(client.close());
    _controller.destroy();
    _outgoing.close();
  }
}

class _SynchronousResponseChannel extends SSHChannel {
  _SynchronousResponseChannel()
      : super(
          SSHChannelController(
            localId: 1,
            localMaximumPacketSize: 1024 * 1024,
            localInitialWindowSize: 1024 * 1024,
            remoteId: 2,
            remoteMaximumPacketSize: 1024 * 1024,
            remoteInitialWindowSize: 0,
            sendMessage: (_) {},
          ),
        );

  final _incoming = StreamController<SSHChannelData>(sync: true);
  SftpPacket Function(Uint8List payload)? _outboundResponder;
  var outboundPacketCount = 0;

  @override
  Stream<SSHChannelData> get stream => _incoming.stream;

  @override
  void addData(Uint8List data, {int? type}) {
    outboundPacketCount++;
    final reader = SSHMessageReader(data);
    final length = reader.readUint32();
    final payload = reader.readBytes(length);
    final response = _outboundResponder?.call(payload);
    if (response != null) {
      sendResponsePacket(response);
    }
  }

  void respondDuringAddData(
    SftpPacket Function(Uint8List payload) responder,
  ) {
    _outboundResponder = responder;
  }

  void sendResponsePacket(SftpPacket packet) {
    final payload = packet.encode();
    final writer = SSHMessageWriter();
    writer.writeUint32(payload.length);
    writer.writeBytes(payload);
    _incoming.add(SSHChannelData(writer.takeBytes()));
  }

  void fail(Object error, [StackTrace? stackTrace]) {
    _incoming.addError(error, stackTrace ?? StackTrace.current);
  }

  Future<void> finish() => _incoming.close();

  @override
  Future<void> close() => _incoming.close();
}
