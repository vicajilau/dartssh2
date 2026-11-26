import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/ssh_algorithm.dart';
import 'package:dartssh2/src/utils/cipher_ext.dart';
import 'package:test/test.dart';

void main() {
  testCipher(SSHCipherType.aes128cbc);
  testCipher(SSHCipherType.aes192cbc);
  testCipher(SSHCipherType.aes256cbc);
  testCipher(SSHCipherType.aes128ctr);
  testCipher(SSHCipherType.aes192ctr);
  testCipher(SSHCipherType.aes256ctr);
  group('SSHAlgorithm', () {
    test('toString() returns correct format', () {
      final algorithm = SSHKexType.x25519;
      expect(algorithm.toString(), equals(SSHKexType.x25519.toString()));
    });
  });

  group('SSHAlgorithmList extension', () {
    test('toNameList() returns list of names', () {
      final algorithms = [SSHKexType.x25519, SSHKexType.nistp521];
      final names = algorithms.toNameList();
      expect(names, equals([SSHKexType.x25519.name, SSHKexType.nistp521.name]));
    });

    test('getByName() returns correct algorithm', () {
      final algorithms = [SSHKexType.x25519, SSHKexType.nistp521];
      final algorithm = algorithms.getByName(SSHKexType.nistp521.name);
      expect(algorithm, isNotNull);
      expect(algorithm!.name, equals(SSHKexType.nistp521.name));
    });

    test('getByName() returns null when not found', () {
      final algorithms = [SSHKexType.x25519, SSHKexType.nistp521];
      final algorithm = algorithms.getByName('nonexistent');
      expect(algorithm, isNull);
    });
  });

  group('AEAD cipher metadata', () {
    test('AES-GCM ciphers are marked as AEAD', () {
      expect(SSHCipherType.aes128gcm.isAead, isTrue);
      expect(SSHCipherType.aes256gcm.isAead, isTrue);
      expect(SSHCipherType.aes128gcm.ivSize, 12);
      expect(SSHCipherType.aes128gcm.aeadTagSize, 16);
    });

    test('OpenSSH ChaCha20-Poly1305 exposes packet-cipher metadata', () {
      final cipher = SSHCipherType.chacha20poly1305;

      expect(cipher.isAead, isTrue);
      expect(cipher.keySize, 64);
      expect(cipher.ivSize, 0);
      expect(cipher.blockSize, 8);
      expect(cipher.aeadTagSize, 16);
    });

    test('AEAD ciphers do not expose BlockCipher API', () {
      for (final cipher in [
        SSHCipherType.chacha20poly1305,
        SSHCipherType.aes128gcm,
      ]) {
        expect(
          () => cipher.createCipher(
            Uint8List(cipher.keySize),
            Uint8List(cipher.ivSize),
            forEncryption: true,
          ),
          throwsA(isA<UnsupportedError>()),
        );
      }
    });

    test('fromName resolves AEAD ciphers', () {
      expect(
        SSHCipherType.fromName('chacha20-poly1305@openssh.com'),
        SSHCipherType.chacha20poly1305,
      );
      expect(
        SSHCipherType.fromName('aes128-gcm@openssh.com'),
        SSHCipherType.aes128gcm,
      );
      expect(
        SSHCipherType.fromName('aes256-gcm@openssh.com'),
        SSHCipherType.aes256gcm,
      );
    });
  });

  test('Default values are set correctly', () {
    final algorithms = SSHAlgorithms();

    expect(
        algorithms.kex,
        equals([
          SSHKexType.x25519Rfc,
          SSHKexType.x25519,
          SSHKexType.nistp521,
          SSHKexType.nistp384,
          SSHKexType.nistp256,
          SSHKexType.dhGexSha256,
          SSHKexType.dh14Sha256,
        ]));

    expect(
        algorithms.hostkey,
        equals([
          SSHHostkeyType.ed25519,
          SSHHostkeyType.rsaSha512,
          SSHHostkeyType.rsaSha256,
          SSHHostkeyType.ecdsa521,
          SSHHostkeyType.ecdsa384,
          SSHHostkeyType.ecdsa256,
        ]));

    expect(
        algorithms.cipher,
        equals([
          SSHCipherType.aes256gcm,
          SSHCipherType.aes128gcm,
          SSHCipherType.chacha20poly1305,
          SSHCipherType.aes256ctr,
          SSHCipherType.aes128ctr,
        ]));

    expect(
        algorithms.mac,
        equals([
          SSHMacType.hmacSha256Etm,
          SSHMacType.hmacSha512Etm,
          SSHMacType.hmacSha256,
          SSHMacType.hmacSha512,
          SSHMacType.hmacSha1,
        ]));
  });

  group('Default algorithm preferences', () {
    final algorithms = SSHAlgorithms();

    test('prefer AEAD over CTR', () {
      final names = algorithms.cipher.toNameList();
      final lastCtr = names.lastIndexWhere((name) => name.endsWith('-ctr'));
      final lastGcm = names.lastIndexWhere((name) => name.contains('gcm'));

      expect(lastGcm, lessThan(lastCtr));
    });

    test('prefer encrypt-then-MAC over encrypt-and-MAC', () {
      final macs = algorithms.mac;
      final lastEtm = macs.lastIndexWhere((mac) => mac.isEtm);
      final firstPlain = macs.indexWhere((mac) => !mac.isEtm);

      expect(lastEtm, lessThan(firstPlain));
    });

    test('exclude broken algorithms', () {
      expect(algorithms.mac, isNot(contains(SSHMacType.hmacMd5)));
      expect(algorithms.mac, isNot(contains(SSHMacType.hmacSha256_96)));
      expect(algorithms.mac, isNot(contains(SSHMacType.hmacSha512_96)));
      expect(algorithms.kex, isNot(contains(SSHKexType.dh1Sha1)));
      expect(algorithms.kex, isNot(contains(SSHKexType.dh14Sha1)));
      expect(algorithms.kex, isNot(contains(SSHKexType.dhGexSha1)));
      expect(algorithms.hostkey, isNot(contains(SSHHostkeyType.rsaSha1)));
      expect(algorithms.cipher, isNot(contains(SSHCipherType.aes128cbc)));
      expect(algorithms.cipher, isNot(contains(SSHCipherType.aes256cbc)));
    });

    test('keep hmac-sha1 last for OpenSSH compatibility', () {
      expect(algorithms.mac.last, SSHMacType.hmacSha1);
    });

    test('legacy algorithms remain available through explicit configuration',
        () {
      const legacy = SSHAlgorithms(
        kex: [SSHKexType.dh14Sha1, SSHKexType.dhGexSha1],
        hostkey: [SSHHostkeyType.rsaSha1],
        cipher: [SSHCipherType.aes128cbc, SSHCipherType.aes256cbc],
      );

      expect(legacy.kex, [SSHKexType.dh14Sha1, SSHKexType.dhGexSha1]);
      expect(legacy.hostkey, [SSHHostkeyType.rsaSha1]);
      expect(
        legacy.cipher,
        [SSHCipherType.aes128cbc, SSHCipherType.aes256cbc],
      );
    });
  });
}

void testCipher(SSHCipherType type) {
  test('$type encrypt/decrypt', () {
    final key = Uint8List(type.keySize);
    final iv = Uint8List(type.blockSize);
    final encrypter = type.createCipher(key, iv, forEncryption: true);
    final decrypter = type.createCipher(key, iv, forEncryption: false);

    final plainText = Uint8List(type.blockSize * 100);
    for (var i = 0; i < plainText.length; i++) {
      plainText[i] = i & 0xff;
    }

    final cipherText = encrypter.processAll(plainText);
    final decrypted = decrypter.processAll(cipherText);

    expect(decrypted, plainText);
  });

  test('$type rejects invalid key length', () {
    expect(
      () => type.createCipher(
        Uint8List(type.keySize - 1),
        Uint8List(type.blockSize),
        forEncryption: true,
      ),
      throwsA(isA<ArgumentError>()),
    );
  });

  test('$type rejects invalid IV length', () {
    expect(
      () => type.createCipher(
        Uint8List(type.keySize),
        Uint8List(type.ivSize - 1),
        forEncryption: true,
      ),
      throwsA(isA<ArgumentError>()),
    );
  });

  // test('$type needs init after reset', () {
  //   final key = Uint8List(type.keySize);
  //   final iv = Uint8List(type.blockSize);
  //   final encrypter = type.createCipher(key, iv, forEncryption: true);
  //   encrypter.processAll(Uint8List(type.blockSize));
  //   encrypter.reset();
  //   expect(
  //     () => encrypter.processAll(Uint8List(type.blockSize)),
  //     throwsA(isA<StateError>()),
  //   );
  // });
}
