// Uses dart:mirrors to reach SSHTransport's private methods; dart:mirrors is
// VM-only. The web-runnable AEAD coverage lives in
// ssh_transport_aead_web_test.dart instead.
@TestOn('vm')
library;

import 'dart:async';
// Deprecated in Dart 3.14, still needed here to reach private state.
// ignore: deprecated_member_use
import 'dart:mirrors';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/message/msg_kex.dart';
import 'package:dartssh2/src/ssh_packet.dart';
import 'package:dartssh2/src/utils/openssh_chacha20_poly1305.dart';
import 'package:test/test.dart';

void main() {
  final transportLibrary = reflectClass(SSHTransport).owner as LibraryMirror;
  final packetLibrary = reflectClass(SSHPacketSN).owner as LibraryMirror;
  Symbol privateSymbol(String name) =>
      MirrorSystem.getSymbol(name, transportLibrary);
  Symbol packetPrivateSymbol(String name) =>
      MirrorSystem.getSymbol(name, packetLibrary);
  void setPrivate(SSHTransport transport, String field, Object? value) {
    reflect(transport).setField(privateSymbol(field), value);
  }

  T getPrivate<T>(SSHTransport transport, String field) {
    return reflect(transport).getField(privateSymbol(field)).reflectee as T;
  }

  void setSequenceValue(SSHTransport transport, String field, int value) {
    final sequence =
        reflect(transport).getField(privateSymbol(field)).reflectee;
    reflect(sequence).setField(packetPrivateSymbol('_value'), value);
  }

  group('SSHTransport AEAD', () {
    test('exchanges fragmented OpenSSH ChaCha20-Poly1305 packets', () async {
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
      setPrivate(
        sender,
        '_clientCipherType',
        SSHCipherType.chacha20poly1305,
      );
      setPrivate(
        sender,
        '_localCipherType',
        SSHCipherType.chacha20poly1305,
      );
      setPrivate(
        sender,
        '_localChaChaCipher',
        OpenSSHChaCha20Poly1305(key),
      );
      setPrivate(sender, '_kexInProgress', false);
      setSequenceValue(sender, '_localPacketSN', 7);

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
      setPrivate(receiver, '_remoteVersion', 'SSH-2.0-test');
      setPrivate(
        receiver,
        '_serverCipherType',
        SSHCipherType.chacha20poly1305,
      );
      setPrivate(
        receiver,
        '_remoteCipherType',
        SSHCipherType.chacha20poly1305,
      );
      setPrivate(
        receiver,
        '_remoteChaChaCipher',
        OpenSSHChaCha20Poly1305(key),
      );
      // The receiver must be past key exchange, otherwise the packet is
      // treated as an unexpected message during kex and never delivered.
      setPrivate(receiver, '_kexInProgress', false);
      setSequenceValue(receiver, '_remotePacketSN', 7);

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

    test('keeps active ChaCha keys until NEWKEYS takes effect', () {
      final key = Uint8List.fromList(List<int>.generate(64, (i) => i));
      final cipher = OpenSSHChaCha20Poly1305(key);
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      // A rekey has selected AES-GCM, but outbound packets up to and including
      // NEWKEYS must still use the currently active ChaCha keys.
      setPrivate(
        transport,
        '_clientCipherType',
        SSHCipherType.aes128gcm,
      );
      setPrivate(
        transport,
        '_localCipherType',
        SSHCipherType.chacha20poly1305,
      );
      setPrivate(transport, '_localChaChaCipher', cipher);
      setPrivate(transport, '_kexInProgress', true);
      setSequenceValue(transport, '_localPacketSN', 9);

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
      setPrivate(
        receiver,
        '_serverCipherType',
        SSHCipherType.aes128gcm,
      );
      setPrivate(
        receiver,
        '_remoteCipherType',
        SSHCipherType.chacha20poly1305,
      );
      setPrivate(receiver, '_remoteChaChaCipher', cipher);
      setSequenceValue(receiver, '_remotePacketSN', 9);
      final dynamic buffer = getPrivate<dynamic>(receiver, '_buffer');
      buffer.add(encrypted);

      final received = reflect(receiver)
          .invoke(privateSymbol('_consumeChaChaPacket'), const []).reflectee;
      expect(received, payload);

      transport.close();
      receiver.close();
    });

    test('rejects misaligned OpenSSH ChaCha20-Poly1305 packets', () {
      final key = Uint8List(64);
      final cipher = OpenSSHChaCha20Poly1305(key);
      final packet = Uint8List(4 + 15);
      ByteData.sublistView(packet, 0, 4).setUint32(0, 15);
      packet[4] = 4;

      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);
      setPrivate(
        transport,
        '_serverCipherType',
        SSHCipherType.chacha20poly1305,
      );
      setPrivate(
        transport,
        '_remoteCipherType',
        SSHCipherType.chacha20poly1305,
      );
      setPrivate(transport, '_remoteChaChaCipher', cipher);
      final dynamic buffer = getPrivate<dynamic>(transport, '_buffer');
      buffer.add(cipher.encryptPacket(packet, 0));

      expect(
        () => reflect(transport).invoke(
          privateSymbol('_consumeChaChaPacket'),
          const [],
        ),
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

      setPrivate(transport, '_kexType', SSHKexType.x25519);
      setPrivate(transport, '_sharedSecret', BigInt.from(21));
      setPrivate(
        transport,
        '_exchangeHash',
        Uint8List.fromList(List<int>.filled(32, 22)),
      );
      setPrivate(
        transport,
        '_sessionId',
        Uint8List.fromList(List<int>.filled(32, 23)),
      );
      setPrivate(
        transport,
        '_clientCipherType',
        SSHCipherType.chacha20poly1305,
      );

      reflect(transport).invoke(privateSymbol('_applyLocalKeys'), const []);
      final first = getPrivate<OpenSSHChaCha20Poly1305?>(
        transport,
        '_localChaChaCipher',
      );
      expect(first, isNotNull);
      expect(
        getPrivate<SSHCipherType?>(transport, '_localCipherType'),
        SSHCipherType.chacha20poly1305,
      );
      expect(getPrivate<Object?>(transport, '_localMacType'), isNull);
      expect(getPrivate<Object?>(transport, '_localCipherKey'), isNull);
      expect(getPrivate<Object?>(transport, '_localIV'), isNull);

      setPrivate(transport, '_sharedSecret', BigInt.from(24));
      reflect(transport).invoke(privateSymbol('_applyLocalKeys'), const []);
      final second = getPrivate<OpenSSHChaCha20Poly1305?>(
        transport,
        '_localChaChaCipher',
      );
      expect(second, isNotNull);
      expect(identical(second, first), isFalse);

      setPrivate(transport, '_clientCipherType', SSHCipherType.aes128ctr);
      setPrivate(transport, '_clientMacType', SSHMacType.hmacSha256);
      reflect(transport).invoke(privateSymbol('_applyLocalKeys'), const []);
      expect(
        getPrivate<Object?>(transport, '_localChaChaCipher'),
        isNull,
      );
      expect(
        getPrivate<SSHCipherType?>(transport, '_localCipherType'),
        SSHCipherType.aes128ctr,
      );
      expect(
        getPrivate<SSHMacType?>(transport, '_localMacType'),
        SSHMacType.hmacSha256,
      );
      expect(getPrivate<Object?>(transport, '_encryptCipher'), isNotNull);

      transport.close();
    });

    test('remote rekey replaces the ChaCha context', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      setPrivate(transport, '_kexType', SSHKexType.x25519);
      setPrivate(transport, '_sharedSecret', BigInt.from(31));
      setPrivate(
        transport,
        '_exchangeHash',
        Uint8List.fromList(List<int>.filled(32, 32)),
      );
      setPrivate(
        transport,
        '_sessionId',
        Uint8List.fromList(List<int>.filled(32, 33)),
      );
      setPrivate(
        transport,
        '_serverCipherType',
        SSHCipherType.chacha20poly1305,
      );

      reflect(transport).invoke(privateSymbol('_applyRemoteKeys'), const []);
      final first = getPrivate<OpenSSHChaCha20Poly1305?>(
        transport,
        '_remoteChaChaCipher',
      );
      expect(first, isNotNull);

      setPrivate(transport, '_sharedSecret', BigInt.from(34));
      reflect(transport).invoke(privateSymbol('_applyRemoteKeys'), const []);
      final second = getPrivate<OpenSSHChaCha20Poly1305?>(
        transport,
        '_remoteChaChaCipher',
      );
      expect(second, isNotNull);
      expect(identical(second, first), isFalse);
      expect(
        getPrivate<SSHCipherType?>(transport, '_remoteCipherType'),
        SSHCipherType.chacha20poly1305,
      );
      expect(getPrivate<Object?>(transport, '_remoteMacType'), isNull);
      expect(getPrivate<Object?>(transport, '_remoteCipherKey'), isNull);
      expect(getPrivate<Object?>(transport, '_remoteIV'), isNull);

      setPrivate(transport, '_serverCipherType', SSHCipherType.aes128ctr);
      setPrivate(transport, '_serverMacType', SSHMacType.hmacSha256);
      reflect(transport).invoke(privateSymbol('_applyRemoteKeys'), const []);
      expect(
        getPrivate<Object?>(transport, '_remoteChaChaCipher'),
        isNull,
      );
      expect(
        getPrivate<SSHCipherType?>(transport, '_remoteCipherType'),
        SSHCipherType.aes128ctr,
      );
      expect(
        getPrivate<SSHMacType?>(transport, '_remoteMacType'),
        SSHMacType.hmacSha256,
      );
      expect(getPrivate<Object?>(transport, '_decryptCipher'), isNotNull);

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

          setPrivate(sender, '_clientCipherType', cipherType);
          setPrivate(sender, '_localCipherType', cipherType);
          setPrivate(sender, '_localCipherKey', key);
          setPrivate(sender, '_localIV', iv);
          setPrivate(sender, '_kexInProgress', false);
          setSequenceValue(sender, '_localPacketSN', 0);

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

          setPrivate(receiver, '_remoteVersion', 'SSH-2.0-test');
          setPrivate(receiver, '_serverCipherType', cipherType);
          setPrivate(receiver, '_remoteCipherType', cipherType);
          setPrivate(receiver, '_remoteCipherKey', key);
          setPrivate(receiver, '_remoteIV', iv);
          setPrivate(receiver, '_kexInProgress', false);
          setSequenceValue(receiver, '_remotePacketSN', 0);

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

        setPrivate(sender, '_clientCipherType', cipherType);
        setPrivate(sender, '_localCipherType', cipherType);
        setPrivate(sender, '_localCipherKey', key);
        setPrivate(sender, '_localIV', iv);
        setPrivate(sender, '_kexInProgress', false);
        setSequenceValue(sender, '_localPacketSN', 0);

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

        setPrivate(receiver, '_remoteVersion', 'SSH-2.0-test');
        setPrivate(receiver, '_serverCipherType', cipherType);
        setPrivate(receiver, '_remoteCipherType', cipherType);
        setPrivate(receiver, '_remoteCipherKey', key);
        setPrivate(receiver, '_remoteIV', iv);
        setSequenceValue(receiver, '_remotePacketSN', 0);

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
        () => reflect(transport).invoke(
          privateSymbol('_nonceForSequence'),
          [Uint8List(8), 0],
        ),
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

        setPrivate(transport, '_remoteVersion', 'SSH-2.0-test');
        setPrivate(transport, '_serverCipherType', cipherType);
        setPrivate(
            transport, '_remoteCipherKey', Uint8List(cipherType.keySize));
        setPrivate(transport, '_remoteIV', Uint8List(cipherType.ivSize));
        setSequenceValue(transport, '_remotePacketSN', 0);

        final resultNoHeader = reflect(transport).invoke(
            privateSymbol('_consumeAeadPacket'), [cipherType]).reflectee;
        expect(resultNoHeader, isNull);

        final dynamic buffer = getPrivate<dynamic>(transport, '_buffer');
        buffer.add(Uint8List.fromList([0, 0, 0, 20, 1, 2, 3]));

        final resultPartial = reflect(transport).invoke(
            privateSymbol('_consumeAeadPacket'), [cipherType]).reflectee;
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

        setPrivate(transport, '_kexType', SSHKexType.x25519);
        setPrivate(transport, '_sharedSecret', BigInt.from(1));
        setPrivate(transport, '_exchangeHash',
            Uint8List.fromList(List<int>.filled(32, 1)));
        setPrivate(transport, '_sessionId',
            Uint8List.fromList(List<int>.filled(32, 2)));
        setPrivate(transport, '_clientCipherType', cipherType);

        reflect(transport).invoke(privateSymbol('_applyLocalKeys'), const []);

        final localKey = getPrivate<Uint8List?>(transport, '_localCipherKey');
        final localIv = getPrivate<Uint8List?>(transport, '_localIV');
        expect(localKey, isNotNull);
        expect(localKey!.length, cipherType.keySize);
        expect(localIv, isNotNull);
        expect(localIv!.length, cipherType.ivSize);
        expect(getPrivate<Object?>(transport, '_encryptCipher'), isNull);
        expect(getPrivate<Object?>(transport, '_localMac'), isNull);

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

        setPrivate(transport, '_kexType', SSHKexType.x25519);
        setPrivate(transport, '_sharedSecret', BigInt.from(1));
        setPrivate(transport, '_exchangeHash',
            Uint8List.fromList(List<int>.filled(32, 3)));
        setPrivate(transport, '_sessionId',
            Uint8List.fromList(List<int>.filled(32, 4)));
        setPrivate(transport, '_serverCipherType', cipherType);

        reflect(transport).invoke(privateSymbol('_applyRemoteKeys'), const []);

        final remoteKey = getPrivate<Uint8List?>(transport, '_remoteCipherKey');
        final remoteIv = getPrivate<Uint8List?>(transport, '_remoteIV');
        expect(remoteKey, isNotNull);
        expect(remoteKey!.length, cipherType.keySize);
        expect(remoteIv, isNotNull);
        expect(remoteIv!.length, cipherType.ivSize);
        expect(getPrivate<Object?>(transport, '_decryptCipher'), isNull);
        expect(getPrivate<Object?>(transport, '_remoteMac'), isNull);

        transport.close();
      }
    });

    test('applyLocalKeys creates cipher and mac for non-AEAD algorithms', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      setPrivate(transport, '_kexType', SSHKexType.x25519);
      setPrivate(transport, '_sharedSecret', BigInt.from(5));
      setPrivate(transport, '_exchangeHash',
          Uint8List.fromList(List<int>.filled(32, 6)));
      setPrivate(
          transport, '_sessionId', Uint8List.fromList(List<int>.filled(32, 7)));
      setPrivate(transport, '_clientCipherType', SSHCipherType.aes128ctr);
      setPrivate(transport, '_clientMacType', SSHMacType.hmacSha256);

      reflect(transport).invoke(privateSymbol('_applyLocalKeys'), const []);

      expect(getPrivate<Object?>(transport, '_encryptCipher'), isNotNull);
      expect(getPrivate<Object?>(transport, '_localMac'), isNotNull);

      transport.close();
    });

    test('applyRemoteKeys creates cipher and mac for non-AEAD algorithms', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      setPrivate(transport, '_kexType', SSHKexType.x25519);
      setPrivate(transport, '_sharedSecret', BigInt.from(8));
      setPrivate(transport, '_exchangeHash',
          Uint8List.fromList(List<int>.filled(32, 9)));
      setPrivate(transport, '_sessionId',
          Uint8List.fromList(List<int>.filled(32, 10)));
      setPrivate(transport, '_serverCipherType', SSHCipherType.aes128ctr);
      setPrivate(transport, '_serverMacType', SSHMacType.hmacSha256);

      reflect(transport).invoke(privateSymbol('_applyRemoteKeys'), const []);

      expect(getPrivate<Object?>(transport, '_decryptCipher'), isNotNull);
      expect(getPrivate<Object?>(transport, '_remoteMac'), isNotNull);

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

        setPrivate(transport, '_kexInProgress', true);
        setPrivate(transport, '_sentKexInit', true);

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

        final result = reflect(transport).invoke(
            privateSymbol('_handleMessageKexInit'), [payload]).reflectee;
        await expectLater(result, completes);

        transport.close();
      }
    });

    test('sendPacket buffers non-kex packets during key exchange', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      setPrivate(transport, '_kexInProgress', true);

      // 94 is outside control/kex message ranges and should be buffered.
      transport.sendPacket(Uint8List.fromList([94, 1, 2]));

      final pending =
          getPrivate<List<Uint8List>>(transport, '_rekeyPendingPackets');
      expect(pending, hasLength(1));
      expect(pending.first, Uint8List.fromList([94, 1, 2]));

      transport.close();
    });

    test('applyLocalKeys throws when cipher type is missing', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      expect(
        () => reflect(transport)
            .invoke(privateSymbol('_applyLocalKeys'), const []),
        throwsA(isA<StateError>()),
      );

      transport.close();
    });

    test('applyRemoteKeys throws when cipher type is missing', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      expect(
        () => reflect(transport)
            .invoke(privateSymbol('_applyRemoteKeys'), const []),
        throwsA(isA<StateError>()),
      );

      transport.close();
    });

    test('applyLocalKeys throws when non-AEAD MAC type is missing', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      setPrivate(transport, '_kexType', SSHKexType.x25519);
      setPrivate(transport, '_sharedSecret', BigInt.from(11));
      setPrivate(transport, '_exchangeHash',
          Uint8List.fromList(List<int>.filled(32, 12)));
      setPrivate(transport, '_sessionId',
          Uint8List.fromList(List<int>.filled(32, 13)));
      setPrivate(transport, '_clientCipherType', SSHCipherType.aes128ctr);

      expect(
        () => reflect(transport)
            .invoke(privateSymbol('_applyLocalKeys'), const []),
        throwsA(isA<StateError>()),
      );

      transport.close();
    });

    test('applyRemoteKeys throws when non-AEAD MAC type is missing', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      setPrivate(transport, '_kexType', SSHKexType.x25519);
      setPrivate(transport, '_sharedSecret', BigInt.from(14));
      setPrivate(transport, '_exchangeHash',
          Uint8List.fromList(List<int>.filled(32, 15)));
      setPrivate(transport, '_sessionId',
          Uint8List.fromList(List<int>.filled(32, 16)));
      setPrivate(transport, '_serverCipherType', SSHCipherType.aes128ctr);

      expect(
        () => reflect(transport)
            .invoke(privateSymbol('_applyRemoteKeys'), const []),
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

      setPrivate(transport, '_kexInProgress', true);
      setPrivate(transport, '_sentKexInit', true);

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
        () async {
          final result = reflect(transport).invoke(
              privateSymbol('_handleMessageKexInit'), [payload]).reflectee;
          if (result is Future) {
            await result;
          }
        },
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

      setPrivate(transport, '_kexInProgress', true);
      setPrivate(transport, '_sentKexInit', true);

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
        () async {
          final result = reflect(transport).invoke(
              privateSymbol('_handleMessageKexInit'), [payload]).reflectee;
          if (result is Future) {
            await result;
          }
        },
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
