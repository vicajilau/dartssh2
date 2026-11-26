// The ChaCha20-Poly1305 tests that encrypt or decrypt a packet run on the VM
// only: PointyCastle's Poly1305 needs full-width 64-bit integers, which a
// browser does not have (see "Web support" in the README). Everything else
// here, AES-GCM included, also runs in the browser.

import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/ssh_transport.dart';
import 'package:dartssh2/src/message/msg_kex.dart';
import 'package:dartssh2/src/ssh_packet.dart';
import 'package:dartssh2/src/utils/openssh_chacha20_poly1305.dart';
import 'package:test/test.dart';

void main() {
  group('SSHTransport AEAD', () {
    test('exchanges fragmented OpenSSH ChaCha20-Poly1305 packets', testOn: 'vm',
        () async {
      final key = Uint8List.fromList(List<int>.generate(64, (i) => i));
      final payload = Uint8List.fromList(
        List<int>.generate(37, (i) => (i * 17) & 0xff),
      );

      final senderSocket = _CaptureSSHSocket();
      final sender = SSHTransport(
        senderSocket,
        algorithms: const SSHAlgorithms(
          cipher: [SSHCipherType.chacha20poly1305],
        ),
      );
      transportTestHooks(sender).clientCipherType =
          SSHCipherType.chacha20poly1305;
      transportTestHooks(sender).localCipherType =
          SSHCipherType.chacha20poly1305;
      transportTestHooks(sender).localChaChaCipher =
          OpenSSHChaCha20Poly1305(key);
      transportTestHooks(sender).kexInProgress = false;
      transportTestHooks(sender).localPacketSN.value = 7;

      sender.sendPacket(payload);
      final encryptedPacket = senderSocket.packets.last;

      final receiverSocket = _CaptureSSHSocket();
      final receivedPacket = Completer<Uint8List>();
      final receiver = SSHTransport(
        receiverSocket,
        algorithms: const SSHAlgorithms(
          cipher: [SSHCipherType.chacha20poly1305],
        ),
        onMessage: (packet) {
          if (!receivedPacket.isCompleted) {
            receivedPacket.complete(packet);
          }
          return true;
        },
      );
      transportTestHooks(receiver).remoteVersion = 'SSH-2.0-test';
      transportTestHooks(receiver).serverCipherType =
          SSHCipherType.chacha20poly1305;
      transportTestHooks(receiver).remoteCipherType =
          SSHCipherType.chacha20poly1305;
      transportTestHooks(receiver).remoteChaChaCipher =
          OpenSSHChaCha20Poly1305(key);
      // The receiver must be past key exchange, otherwise the packet is
      // treated as an unexpected message during kex and never delivered.
      transportTestHooks(receiver).kexInProgress = false;
      transportTestHooks(receiver).remotePacketSN.value = 7;

      receiverSocket.addIncomingBytes(
        Uint8List.sublistView(encryptedPacket, 0, 4),
      );
      await Future<void>.delayed(Duration.zero);
      expect(receivedPacket.isCompleted, isFalse);

      receiverSocket.addIncomingBytes(
        Uint8List.sublistView(encryptedPacket, 4),
      );
      expect(
        await receivedPacket.future.timeout(const Duration(seconds: 2)),
        payload,
      );

      sender.close();
      receiver.close();
    });

    test('keeps active ChaCha keys until NEWKEYS takes effect', testOn: 'vm',
        () {
      final key = Uint8List.fromList(List<int>.generate(64, (i) => i));
      final cipher = OpenSSHChaCha20Poly1305(key);
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      // A rekey has selected AES-GCM, but outbound packets up to and including
      // NEWKEYS must still use the currently active ChaCha keys.
      transportTestHooks(transport).clientCipherType = SSHCipherType.aes128gcm;
      transportTestHooks(transport).localCipherType =
          SSHCipherType.chacha20poly1305;
      transportTestHooks(transport).localChaChaCipher = cipher;
      transportTestHooks(transport).kexInProgress = true;
      transportTestHooks(transport).localPacketSN.value = 9;

      final payload = Uint8List.fromList([SSH_Message_NewKeys.messageId]);
      transport.sendPacket(payload);

      final encrypted = socket.packets.last;
      final packet = cipher.decryptPacket(encrypted, 9);
      final packetLength = SSHPacket.readPacketLength(packet);
      final paddingLength = SSHPacket.readPaddingLength(packet);
      expect(
        Uint8List.sublistView(packet, 5, 4 + packetLength - paddingLength),
        payload,
      );

      // The inbound direction likewise keeps using its active cipher while a
      // different negotiated cipher waits for the peer's NEWKEYS packet.
      final receiverSocket = _CaptureSSHSocket();
      final receiver = SSHTransport(receiverSocket);
      transportTestHooks(receiver).serverCipherType = SSHCipherType.aes128gcm;
      transportTestHooks(receiver).remoteCipherType =
          SSHCipherType.chacha20poly1305;
      transportTestHooks(receiver).remoteChaChaCipher = cipher;
      transportTestHooks(receiver).remotePacketSN.value = 9;
      final dynamic buffer = transportTestHooks(receiver).buffer;
      buffer.add(encrypted);

      final received = transportTestHooks(receiver).consumeChaChaPacket();
      expect(received, payload);

      transport.close();
      receiver.close();
    });

    test('rejects misaligned OpenSSH ChaCha20-Poly1305 packets', testOn: 'vm',
        () {
      final key = Uint8List(64);
      final cipher = OpenSSHChaCha20Poly1305(key);
      final packet = Uint8List(4 + 15);
      ByteData.sublistView(packet, 0, 4).setUint32(0, 15);
      packet[4] = 4;

      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);
      transportTestHooks(transport).serverCipherType =
          SSHCipherType.chacha20poly1305;
      transportTestHooks(transport).remoteCipherType =
          SSHCipherType.chacha20poly1305;
      transportTestHooks(transport).remoteChaChaCipher = cipher;
      final dynamic buffer = transportTestHooks(transport).buffer;
      buffer.add(cipher.encryptPacket(packet, 0));

      expect(
        () => transportTestHooks(transport).consumeChaChaPacket(),
        throwsA(
          isA<SSHPacketError>().having(
            (error) => error.toString(),
            'message',
            contains('Invalid packet alignment'),
          ),
        ),
      );

      transport.close();
    });

    test('rekey replaces ChaCha contexts and switching clears them', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      transportTestHooks(transport).kexType = SSHKexType.x25519;
      transportTestHooks(transport).sharedSecret = BigInt.from(21);
      transportTestHooks(transport).exchangeHash =
          Uint8List.fromList(List<int>.filled(32, 22));
      transportTestHooks(transport).sessionId =
          Uint8List.fromList(List<int>.filled(32, 23));
      transportTestHooks(transport).clientCipherType =
          SSHCipherType.chacha20poly1305;

      transportTestHooks(transport).applyLocalKeys();
      final first = transportTestHooks(transport).localChaChaCipher;
      expect(first, isNotNull);
      expect(
        transportTestHooks(transport).localCipherType,
        SSHCipherType.chacha20poly1305,
      );
      expect(transportTestHooks(transport).localMacType, isNull);
      expect(transportTestHooks(transport).localCipherKey, isNull);
      expect(transportTestHooks(transport).localIV, isNull);

      transportTestHooks(transport).sharedSecret = BigInt.from(24);
      transportTestHooks(transport).applyLocalKeys();
      final second = transportTestHooks(transport).localChaChaCipher;
      expect(second, isNotNull);
      expect(identical(second, first), isFalse);

      transportTestHooks(transport).clientCipherType = SSHCipherType.aes128ctr;
      transportTestHooks(transport).clientMacType = SSHMacType.hmacSha256;
      transportTestHooks(transport).applyLocalKeys();
      expect(
        transportTestHooks(transport).localChaChaCipher,
        isNull,
      );
      expect(
        transportTestHooks(transport).localCipherType,
        SSHCipherType.aes128ctr,
      );
      expect(
        transportTestHooks(transport).localMacType,
        SSHMacType.hmacSha256,
      );
      expect(transportTestHooks(transport).encryptCipher, isNotNull);

      transport.close();
    });

    test('remote rekey replaces the ChaCha context', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      transportTestHooks(transport).kexType = SSHKexType.x25519;
      transportTestHooks(transport).sharedSecret = BigInt.from(31);
      transportTestHooks(transport).exchangeHash =
          Uint8List.fromList(List<int>.filled(32, 32));
      transportTestHooks(transport).sessionId =
          Uint8List.fromList(List<int>.filled(32, 33));
      transportTestHooks(transport).serverCipherType =
          SSHCipherType.chacha20poly1305;

      transportTestHooks(transport).applyRemoteKeys();
      final first = transportTestHooks(transport).remoteChaChaCipher;
      expect(first, isNotNull);

      transportTestHooks(transport).sharedSecret = BigInt.from(34);
      transportTestHooks(transport).applyRemoteKeys();
      final second = transportTestHooks(transport).remoteChaChaCipher;
      expect(second, isNotNull);
      expect(identical(second, first), isFalse);
      expect(
        transportTestHooks(transport).remoteCipherType,
        SSHCipherType.chacha20poly1305,
      );
      expect(transportTestHooks(transport).remoteMacType, isNull);
      expect(transportTestHooks(transport).remoteCipherKey, isNull);
      expect(transportTestHooks(transport).remoteIV, isNull);

      transportTestHooks(transport).serverCipherType = SSHCipherType.aes128ctr;
      transportTestHooks(transport).serverMacType = SSHMacType.hmacSha256;
      transportTestHooks(transport).applyRemoteKeys();
      expect(
        transportTestHooks(transport).remoteChaChaCipher,
        isNull,
      );
      expect(
        transportTestHooks(transport).remoteCipherType,
        SSHCipherType.aes128ctr,
      );
      expect(
        transportTestHooks(transport).remoteMacType,
        SSHMacType.hmacSha256,
      );
      expect(transportTestHooks(transport).decryptCipher, isNotNull);

      transport.close();
    });

    test('exchanges packets with AES-GCM', () async {
      for (final cipherType in [
        SSHCipherType.aes128gcm,
        SSHCipherType.aes256gcm
      ]) {
        final key = Uint8List(cipherType.keySize);
        final iv = Uint8List(cipherType.ivSize);
        for (var i = 0; i < key.length; i++) {
          key[i] = i;
        }
        for (var i = 0; i < iv.length; i++) {
          iv[i] = i + 16;
        }

        for (final payloadLength in [1, 5, 6, 10, 11, 15, 16, 20, 31, 32]) {
          final senderSocket = _CaptureSSHSocket();
          final sender = SSHTransport(
            senderSocket,
            algorithms: SSHAlgorithms(
              cipher: [cipherType],
            ),
          );

          transportTestHooks(sender).clientCipherType = cipherType;
          transportTestHooks(sender).localCipherType = cipherType;
          transportTestHooks(sender).localCipherKey = key;
          transportTestHooks(sender).localIV = iv;
          transportTestHooks(sender).kexInProgress = false;
          transportTestHooks(sender).localPacketSN.value = 0;

          final payload = Uint8List.fromList(
            List.generate(payloadLength, (index) => index % 256),
          );
          sender.sendPacket(payload);

          final encryptedPacket = senderSocket.packets.last;

          final receiverSocket = _CaptureSSHSocket();
          final receivedPacket = Completer<Uint8List>();
          final receiver = SSHTransport(
            receiverSocket,
            algorithms: SSHAlgorithms(
              cipher: [cipherType],
            ),
            onMessage: (packet) {
              if (!receivedPacket.isCompleted) {
                receivedPacket.complete(packet);
              }
              return true;
            },
          );

          transportTestHooks(receiver).remoteVersion = 'SSH-2.0-test';
          transportTestHooks(receiver).serverCipherType = cipherType;
          transportTestHooks(receiver).remoteCipherType = cipherType;
          transportTestHooks(receiver).remoteCipherKey = key;
          transportTestHooks(receiver).remoteIV = iv;
          transportTestHooks(receiver).kexInProgress = false;
          transportTestHooks(receiver).remotePacketSN.value = 0;

          receiverSocket.addIncomingBytes(encryptedPacket);

          final received =
              await receivedPacket.future.timeout(const Duration(seconds: 2));
          expect(received, payload);

          sender.close();
          receiver.close();
        }
      }
    });

    test('reports AEAD authentication failure when packet is tampered',
        () async {
      for (final cipherType in [
        SSHCipherType.aes128gcm,
        SSHCipherType.aes256gcm
      ]) {
        final key = Uint8List(cipherType.keySize);
        final iv = Uint8List(cipherType.ivSize);
        for (var i = 0; i < key.length; i++) {
          key[i] = i;
        }
        for (var i = 0; i < iv.length; i++) {
          iv[i] = i + 16;
        }

        final senderSocket = _CaptureSSHSocket();
        final sender = SSHTransport(
          senderSocket,
          algorithms: SSHAlgorithms(
            cipher: [cipherType],
          ),
        );

        transportTestHooks(sender).clientCipherType = cipherType;
        transportTestHooks(sender).localCipherType = cipherType;
        transportTestHooks(sender).localCipherKey = key;
        transportTestHooks(sender).localIV = iv;
        transportTestHooks(sender).kexInProgress = false;
        transportTestHooks(sender).localPacketSN.value = 0;

        sender.sendPacket(Uint8List.fromList([251, 9, 8, 7]));
        final tampered = Uint8List.fromList(senderSocket.packets.last);
        tampered[tampered.length - 1] ^= 0x01;

        final receiverSocket = _CaptureSSHSocket();
        final receiver = SSHTransport(
          receiverSocket,
          algorithms: SSHAlgorithms(
            cipher: [cipherType],
          ),
        );

        transportTestHooks(receiver).remoteVersion = 'SSH-2.0-test';
        transportTestHooks(receiver).serverCipherType = cipherType;
        transportTestHooks(receiver).remoteCipherType = cipherType;
        transportTestHooks(receiver).remoteCipherKey = key;
        transportTestHooks(receiver).remoteIV = iv;
        transportTestHooks(receiver).remotePacketSN.value = 0;

        receiverSocket.addIncomingBytes(tampered);

        await expectLater(
          receiver.done,
          throwsA(
            predicate(
              (error) =>
                  error is SSHPacketError &&
                  error.toString().contains('AEAD authentication failed'),
            ),
          ),
        );

        sender.close();
        receiver.close();
      }
    });

    test('validates AEAD nonce IV length', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      expect(
        () => transportTestHooks(transport).nonceForSequence(Uint8List(8), 0),
        throwsA(isA<ArgumentError>()),
      );

      transport.close();
    });

    test('consumeAeadPacket returns null for incomplete inputs', () {
      for (final cipherType in [
        SSHCipherType.aes128gcm,
        SSHCipherType.aes256gcm
      ]) {
        final socket = _CaptureSSHSocket();
        final transport = SSHTransport(socket);

        transportTestHooks(transport).remoteVersion = 'SSH-2.0-test';
        transportTestHooks(transport).serverCipherType = cipherType;
        transportTestHooks(transport).remoteCipherKey =
            Uint8List(cipherType.keySize);
        transportTestHooks(transport).remoteIV = Uint8List(cipherType.ivSize);
        transportTestHooks(transport).remotePacketSN.value = 0;

        final resultNoHeader =
            transportTestHooks(transport).consumeAeadPacket(cipherType);
        expect(resultNoHeader, isNull);

        final dynamic buffer = transportTestHooks(transport).buffer;
        buffer.add(Uint8List.fromList([0, 0, 0, 20, 1, 2, 3]));

        final resultPartial =
            transportTestHooks(transport).consumeAeadPacket(cipherType);
        expect(resultPartial, isNull);

        transport.close();
      }
    });

    test('applyLocalKeys keeps AEAD mode without cipher/mac instances', () {
      for (final cipherType in [
        SSHCipherType.aes128gcm,
        SSHCipherType.aes256gcm
      ]) {
        final socket = _CaptureSSHSocket();
        final transport = SSHTransport(socket);

        transportTestHooks(transport).kexType = SSHKexType.x25519;
        transportTestHooks(transport).sharedSecret = BigInt.from(1);
        transportTestHooks(transport).exchangeHash =
            Uint8List.fromList(List<int>.filled(32, 1));
        transportTestHooks(transport).sessionId =
            Uint8List.fromList(List<int>.filled(32, 2));
        transportTestHooks(transport).clientCipherType = cipherType;

        transportTestHooks(transport).applyLocalKeys();

        final localKey = transportTestHooks(transport).localCipherKey;
        final localIv = transportTestHooks(transport).localIV;
        expect(localKey, isNotNull);
        expect(localKey!.length, cipherType.keySize);
        expect(localIv, isNotNull);
        expect(localIv!.length, cipherType.ivSize);
        expect(transportTestHooks(transport).encryptCipher, isNull);
        expect(transportTestHooks(transport).localMac, isNull);

        transport.close();
      }
    });

    test('applyRemoteKeys keeps AEAD mode without cipher/mac instances', () {
      for (final cipherType in [
        SSHCipherType.aes128gcm,
        SSHCipherType.aes256gcm
      ]) {
        final socket = _CaptureSSHSocket();
        final transport = SSHTransport(socket);

        transportTestHooks(transport).kexType = SSHKexType.x25519;
        transportTestHooks(transport).sharedSecret = BigInt.from(1);
        transportTestHooks(transport).exchangeHash =
            Uint8List.fromList(List<int>.filled(32, 3));
        transportTestHooks(transport).sessionId =
            Uint8List.fromList(List<int>.filled(32, 4));
        transportTestHooks(transport).serverCipherType = cipherType;

        transportTestHooks(transport).applyRemoteKeys();

        final remoteKey = transportTestHooks(transport).remoteCipherKey;
        final remoteIv = transportTestHooks(transport).remoteIV;
        expect(remoteKey, isNotNull);
        expect(remoteKey!.length, cipherType.keySize);
        expect(remoteIv, isNotNull);
        expect(remoteIv!.length, cipherType.ivSize);
        expect(transportTestHooks(transport).decryptCipher, isNull);
        expect(transportTestHooks(transport).remoteMac, isNull);

        transport.close();
      }
    });

    test('applyLocalKeys creates cipher and mac for non-AEAD algorithms', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      transportTestHooks(transport).kexType = SSHKexType.x25519;
      transportTestHooks(transport).sharedSecret = BigInt.from(5);
      transportTestHooks(transport).exchangeHash =
          Uint8List.fromList(List<int>.filled(32, 6));
      transportTestHooks(transport).sessionId =
          Uint8List.fromList(List<int>.filled(32, 7));
      transportTestHooks(transport).clientCipherType = SSHCipherType.aes128ctr;
      transportTestHooks(transport).clientMacType = SSHMacType.hmacSha256;

      transportTestHooks(transport).applyLocalKeys();

      expect(transportTestHooks(transport).encryptCipher, isNotNull);
      expect(transportTestHooks(transport).localMac, isNotNull);

      transport.close();
    });

    test('applyRemoteKeys creates cipher and mac for non-AEAD algorithms', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      transportTestHooks(transport).kexType = SSHKexType.x25519;
      transportTestHooks(transport).sharedSecret = BigInt.from(8);
      transportTestHooks(transport).exchangeHash =
          Uint8List.fromList(List<int>.filled(32, 9));
      transportTestHooks(transport).sessionId =
          Uint8List.fromList(List<int>.filled(32, 10));
      transportTestHooks(transport).serverCipherType = SSHCipherType.aes128ctr;
      transportTestHooks(transport).serverMacType = SSHMacType.hmacSha256;

      transportTestHooks(transport).applyRemoteKeys();

      expect(transportTestHooks(transport).decryptCipher, isNotNull);
      expect(transportTestHooks(transport).remoteMac, isNotNull);

      transport.close();
    });

    test('kexinit allows missing MAC when AEAD cipher is selected', () async {
      for (final cipherType in [
        SSHCipherType.chacha20poly1305,
        SSHCipherType.aes128gcm,
        SSHCipherType.aes256gcm
      ]) {
        final socket = _CaptureSSHSocket();
        final transport = SSHTransport(
          socket,
          algorithms: SSHAlgorithms(
            cipher: [cipherType],
            mac: const [SSHMacType.hmacSha256],
          ),
        );

        transportTestHooks(transport).kexInProgress = true;
        transportTestHooks(transport).sentKexInit = true;

        final payload = SSH_Message_KexInit(
          kexAlgorithms: [SSHKexType.x25519.name],
          serverHostKeyAlgorithms: [SSHHostkeyType.ed25519.name],
          encryptionClientToServer: [cipherType.name],
          encryptionServerToClient: [cipherType.name],
          macClientToServer: const ['missing-mac'],
          macServerToClient: const ['missing-mac'],
          compressionClientToServer: const ['none'],
          compressionServerToClient: const ['none'],
          firstKexPacketFollows: false,
        ).encode();

        final result =
            transportTestHooks(transport).handleMessageKexInit(payload);
        await expectLater(result, completes);

        transport.close();
      }
    });

    test('sendPacket buffers non-kex packets during key exchange', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      transportTestHooks(transport).kexInProgress = true;

      // 94 is outside control/kex message ranges and should be buffered.
      transport.sendPacket(Uint8List.fromList([94, 1, 2]));

      final pending = transportTestHooks(transport).rekeyPendingPackets;
      expect(pending, hasLength(1));
      expect(pending.first, Uint8List.fromList([94, 1, 2]));

      transport.close();
    });

    test('applyLocalKeys throws when cipher type is missing', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      expect(
        () => transportTestHooks(transport).applyLocalKeys(),
        throwsA(isA<StateError>()),
      );

      transport.close();
    });

    test('applyRemoteKeys throws when cipher type is missing', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      expect(
        () => transportTestHooks(transport).applyRemoteKeys(),
        throwsA(isA<StateError>()),
      );

      transport.close();
    });

    test('applyLocalKeys throws when non-AEAD MAC type is missing', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      transportTestHooks(transport).kexType = SSHKexType.x25519;
      transportTestHooks(transport).sharedSecret = BigInt.from(11);
      transportTestHooks(transport).exchangeHash =
          Uint8List.fromList(List<int>.filled(32, 12));
      transportTestHooks(transport).sessionId =
          Uint8List.fromList(List<int>.filled(32, 13));
      transportTestHooks(transport).clientCipherType = SSHCipherType.aes128ctr;

      expect(
        () => transportTestHooks(transport).applyLocalKeys(),
        throwsA(isA<StateError>()),
      );

      transport.close();
    });

    test('applyRemoteKeys throws when non-AEAD MAC type is missing', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      transportTestHooks(transport).kexType = SSHKexType.x25519;
      transportTestHooks(transport).sharedSecret = BigInt.from(14);
      transportTestHooks(transport).exchangeHash =
          Uint8List.fromList(List<int>.filled(32, 15));
      transportTestHooks(transport).sessionId =
          Uint8List.fromList(List<int>.filled(32, 16));
      transportTestHooks(transport).serverCipherType = SSHCipherType.aes128ctr;

      expect(
        () => transportTestHooks(transport).applyRemoteKeys(),
        throwsA(isA<StateError>()),
      );

      transport.close();
    });

    test('kexinit requires client MAC when non-AEAD cipher is selected',
        () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(
        socket,
        algorithms: const SSHAlgorithms(
          cipher: [SSHCipherType.aes128ctr],
          mac: [SSHMacType.hmacSha256],
        ),
      );

      transportTestHooks(transport).kexInProgress = true;
      transportTestHooks(transport).sentKexInit = true;

      final payload = SSH_Message_KexInit(
        kexAlgorithms: [SSHKexType.x25519.name],
        serverHostKeyAlgorithms: [SSHHostkeyType.ed25519.name],
        encryptionClientToServer: [SSHCipherType.aes128ctr.name],
        encryptionServerToClient: [SSHCipherType.aes128ctr.name],
        macClientToServer: const ['missing-mac'],
        macServerToClient: [SSHMacType.hmacSha256.name],
        compressionClientToServer: const ['none'],
        compressionServerToClient: const ['none'],
        firstKexPacketFollows: false,
      ).encode();

      await expectLater(
        transportTestHooks(transport).handleMessageKexInit(payload),
        throwsA(isA<StateError>()),
      );

      transport.close();
    });

    test('kexinit requires server MAC when non-AEAD cipher is selected',
        () async {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(
        socket,
        algorithms: const SSHAlgorithms(
          cipher: [SSHCipherType.aes128ctr],
          mac: [SSHMacType.hmacSha256],
        ),
      );

      transportTestHooks(transport).kexInProgress = true;
      transportTestHooks(transport).sentKexInit = true;

      final payload = SSH_Message_KexInit(
        kexAlgorithms: [SSHKexType.x25519.name],
        serverHostKeyAlgorithms: [SSHHostkeyType.ed25519.name],
        encryptionClientToServer: [SSHCipherType.aes128ctr.name],
        encryptionServerToClient: [SSHCipherType.aes128ctr.name],
        macClientToServer: [SSHMacType.hmacSha256.name],
        macServerToClient: const ['missing-mac'],
        compressionClientToServer: const ['none'],
        compressionServerToClient: const ['none'],
        firstKexPacketFollows: false,
      ).encode();

      await expectLater(
        transportTestHooks(transport).handleMessageKexInit(payload),
        throwsA(isA<StateError>()),
      );

      transport.close();
    });
  });
}

class _CaptureSSHSocket implements SSHSocket {
  final _inputController = StreamController<Uint8List>();
  final _doneCompleter = Completer<void>();
  final packets = <Uint8List>[];

  @override
  Stream<Uint8List> get stream => _inputController.stream;

  @override
  StreamSink<List<int>> get sink => _CaptureSink(packets);

  @override
  Future<void> get done => _doneCompleter.future;

  void addIncomingBytes(Uint8List data) {
    _inputController.add(Uint8List.fromList(data));
  }

  @override
  Future<void> close() async {
    if (!_doneCompleter.isCompleted) {
      _doneCompleter.complete();
    }
    await _inputController.close();
  }

  @override
  void destroy() {
    if (!_doneCompleter.isCompleted) {
      _doneCompleter.complete();
    }
    unawaited(_inputController.close());
  }

  @override
  Future<void> flush() async {}
}

class _CaptureSink implements StreamSink<List<int>> {
  _CaptureSink(this._packets);

  final List<Uint8List> _packets;

  @override
  void add(List<int> data) {
    _packets.add(Uint8List.fromList(data));
  }

  @override
  Future<void> addStream(Stream<List<int>> stream) async {
    await for (final chunk in stream) {
      add(chunk);
    }
  }

  @override
  void addError(Object error, [StackTrace? stackTrace]) {}

  @override
  Future<void> close() async {}

  @override
  Future<void> get done async {}
}
