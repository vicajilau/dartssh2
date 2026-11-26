// A web-runnable AEAD test, independent of the transport.
//
// ssh_transport_aead_test.dart drives SSHTransport's own AES-GCM and
// ChaCha20-Poly1305 paths, on the web too except for ChaCha20-Poly1305.
// This file instead reproduces, at the public-API level, exactly what
// SSHTransport._nonceForSequence and _processAead do -- deriving an AEAD
// nonce from an IV and a packet sequence number via
// ByteData.addToUint64Split (see lib/src/utils/int.dart, added for W-01:
// ByteData.getUint64/setUint64 throw when compiled to JavaScript), then
// running it through PointyCastle's AES-GCM cipher -- and checks it runs
// correctly when compiled to JS.
//
// (PointyCastle's Poly1305 -- used by chacha20-poly1305@openssh.com -- is
// not web-compatible for unrelated reasons; see
// openssh_chacha20_poly1305_test.dart, which stays VM-only.)

import 'dart:typed_data';

import 'package:dartssh2/src/utils/int.dart';
import 'package:pointycastle/export.dart';
import 'package:test/test.dart';

/// Mirrors SSHTransport._nonceForSequence.
Uint8List _nonceForSequence(Uint8List iv, int sequence) {
  final nonce = Uint8List.fromList(iv);
  ByteData.sublistView(nonce).addToUint64Split(4, sequence);
  return nonce;
}

Uint8List _aesGcmEncrypt({
  required Uint8List key,
  required Uint8List nonce,
  required Uint8List input,
}) {
  final cipher = GCMBlockCipher(AESEngine());
  cipher.init(
      true, AEADParameters(KeyParameter(key), 128, nonce, Uint8List(0)));
  return cipher.process(input);
}

Uint8List _aesGcmDecrypt({
  required Uint8List key,
  required Uint8List nonce,
  required Uint8List input,
}) {
  final cipher = GCMBlockCipher(AESEngine());
  cipher.init(
      false, AEADParameters(KeyParameter(key), 128, nonce, Uint8List(0)));
  return cipher.process(input);
}

void main() {
  group('AES-GCM nonce derivation (RFC 5647 invocation counter)', () {
    test('increments the low word of the counter for consecutive packets', () {
      // Fixed 4-byte field + all-zero invocation counter.
      final iv = Uint8List.fromList([1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0]);

      expect(
        _nonceForSequence(iv, 0),
        [1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0],
      );
      expect(
        _nonceForSequence(iv, 1),
        [1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 1],
      );
      expect(
        _nonceForSequence(iv, 0x100),
        [1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 1, 0],
      );
    });

    test(
        'carries into the high word of the counter without ever combining '
        'it into a single int', () {
      final iv = Uint8List.fromList(
        [9, 9, 9, 9, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF],
      );

      final nonce = _nonceForSequence(iv, 1);
      expect(nonce, [9, 9, 9, 9, 0, 0, 0, 1, 0, 0, 0, 0]);
    });

    test(
        'is exact when the counter is derived from key material and has '
        'its top bit set -- the case that would need >53 bits if combined '
        'into a single int', () {
      final iv = Uint8List.fromList(
        [0, 0, 0, 0, 0x80, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF],
      );

      final nonce = _nonceForSequence(iv, 1);
      expect(nonce, [0, 0, 0, 0, 0x80, 0, 0, 1, 0, 0, 0, 0]);
    });

    test('the IV itself is not mutated', () {
      final iv = Uint8List.fromList([1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0]);
      final original = Uint8List.fromList(iv);
      _nonceForSequence(iv, 42);
      expect(iv, original);
    });
  });

  group('AES-GCM encrypt/decrypt with a derived nonce', () {
    test('round-trips a packet, keyed off the packet sequence number', () {
      final key = Uint8List.fromList(List<int>.generate(16, (i) => i));
      final iv = Uint8List.fromList(
        [0xDE, 0xAD, 0xBE, 0xEF, 0x80, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFE],
      );
      final plaintext =
          Uint8List.fromList('hello world, AEAD on web'.codeUnits);

      for (final sequence in [0, 1, 2, 1000]) {
        final nonce = _nonceForSequence(iv, sequence);
        final ciphertext = _aesGcmEncrypt(
          key: key,
          nonce: nonce,
          input: plaintext,
        );
        expect(ciphertext, isNot(equals(plaintext)));

        final decrypted = _aesGcmDecrypt(
          key: key,
          nonce: nonce,
          input: ciphertext,
        );
        expect(decrypted, plaintext);
      }
    });

    test('different sequence numbers produce different ciphertexts', () {
      final key = Uint8List.fromList(List<int>.generate(16, (i) => i));
      final iv = Uint8List(12);
      final plaintext = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);

      final ciphertextAt0 = _aesGcmEncrypt(
        key: key,
        nonce: _nonceForSequence(iv, 0),
        input: plaintext,
      );
      final ciphertextAt1 = _aesGcmEncrypt(
        key: key,
        nonce: _nonceForSequence(iv, 1),
        input: plaintext,
      );
      expect(ciphertextAt0, isNot(equals(ciphertextAt1)));
    });
  });
}
