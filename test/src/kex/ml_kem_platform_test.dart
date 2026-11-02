import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:dartssh2/src/kex/ml_kem.dart';
import 'package:pointycastle/digests/sha3.dart';
import 'package:test/test.dart';

/// Runs on every platform, the browser included, where integers are doubles
/// and bitwise operators truncate to 32 bits. The full NIST vectors live in
/// `ml_kem_test.dart`, which reads them from disk and so only runs on the VM;
/// this file fixes the same arithmetic to digests small enough to inline.
void main() {
  Uint8List bytes(String value) => Uint8List.fromList(hex.decode(value));
  String digest(Uint8List value) => hex.encode(SHA3Digest(256).process(value));

  // ACVP ML-KEM-keyGen-FIPS203, ML-KEM-768, tcId 26.
  final d =
      bytes('E582B7D75E6C80B05AE392A1FC9F7153B12390FD99930368CC67A768BAEBC8A0');
  final z =
      bytes('1CDACB8740C0B87C4A379575F187B367CBFA3B300BF591B109F79816E9CBE8F0');

  test('key generation matches the NIST vector', () {
    final pair = MLKem768.generateKeyPairFromSeed(d, z);
    expect(
      digest(pair.encapsulationKey),
      '81e66ef5a7a221619f6a64039cc369843e10df5c859f6959cc3fd8e5272330fd',
    );
    expect(
      digest(pair.decapsulationKey),
      'be81068c104cd6cf8efd800b294f4a15bb8a8050993fd54a2cc428841ef6ca44',
    );
  });

  test('encapsulation and decapsulation match the VM', () {
    // Expected values come from the VM, whose implementation passes the full
    // NIST set, so a mismatch here is a platform arithmetic difference.
    final pair = MLKem768.generateKeyPairFromSeed(d, z);
    final result = MLKem768.encapsulateWithRandomness(
      pair.encapsulationKey,
      bytes('4E77596168711E913965D8175AC3BD76AAB08B7F9385A02AE883CF6C6E17DD81'),
    );
    expect(
      digest(result.ciphertext),
      '046df07df242c00d5348d29c5d2fc061a353f2872b897ecb01df65e937958c15',
    );
    expect(
      hex.encode(result.sharedSecret),
      'b3847ad7d335b45d334820baea8190418e60abe99e7ac38deadc003a71fdce7a',
    );
    expect(
      MLKem768.decapsulate(pair.decapsulationKey, result.ciphertext),
      result.sharedSecret,
    );
  });
}
