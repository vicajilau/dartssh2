@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:dartssh2/src/kex/ml_kem.dart';
import 'package:test/test.dart';

/// Vectors from NIST's ACVP server, `ML-KEM-keyGen-FIPS203` and
/// `ML-KEM-encapDecap-FIPS203` (internalProjection.json), trimmed to the
/// ML-KEM-768 groups. They exercise the deterministic internal algorithms, so
/// a pass means the output is bit-for-bit what FIPS 203 specifies.
final _vectors = jsonDecode(
  File('test/fixtures/ml_kem_768_acvp.json').readAsStringSync(),
) as Map<String, dynamic>;

Iterable<Map<String, dynamic>> _cases(String group) =>
    (_vectors[group] as List).cast<Map<String, dynamic>>();

Uint8List _hex(Object? value) =>
    Uint8List.fromList(hex.decode(value as String));

void main() {
  group('ML-KEM-768 ACVP', () {
    for (final v in _cases('keyGen')) {
      test('keyGen tcId ${v['tcId']}', () {
        final pair =
            MLKem768.generateKeyPairFromSeed(_hex(v['d']), _hex(v['z']));
        expect(pair.encapsulationKey, _hex(v['ek']));
        expect(pair.decapsulationKey, _hex(v['dk']));
      });
    }

    for (final v in _cases('encapsulation')) {
      test('encapsulation tcId ${v['tcId']}', () {
        final result =
            MLKem768.encapsulateWithRandomness(_hex(v['ek']), _hex(v['m']));
        expect(result.ciphertext, _hex(v['c']));
        expect(result.sharedSecret, _hex(v['k']));
      });
    }

    for (final v in _cases('decapsulation')) {
      test('decapsulation tcId ${v['tcId']} (${v['reason']})', () {
        expect(MLKem768.decapsulate(_hex(v['dk']), _hex(v['c'])), _hex(v['k']));
      });
    }

    for (final v in _cases('encapsulationKeyCheck')) {
      test('encapsulation key check tcId ${v['tcId']} (${v['reason']})', () {
        expect(
            MLKem768.isValidEncapsulationKey(_hex(v['ek'])), v['testPassed']);
        if (v['testPassed'] == false) {
          expect(
              () => MLKem768.encapsulate(_hex(v['ek'])), throwsArgumentError);
        }
      });
    }

    for (final v in _cases('decapsulationKeyCheck')) {
      test('decapsulation key check tcId ${v['tcId']} (${v['reason']})', () {
        expect(
            MLKem768.isValidDecapsulationKey(_hex(v['dk'])), v['testPassed']);
        if (v['testPassed'] == false) {
          expect(
            () => MLKem768.decapsulate(
              _hex(v['dk']),
              Uint8List(MLKem768.ciphertextLength),
            ),
            throwsArgumentError,
          );
        }
      });
    }
  });

  group('ML-KEM-768', () {
    test('a fresh encapsulation decapsulates to the same secret', () {
      final pair = MLKem768.generateKeyPair();
      final result = MLKem768.encapsulate(pair.encapsulationKey);
      expect(result.ciphertext, hasLength(MLKem768.ciphertextLength));
      expect(
        MLKem768.decapsulate(pair.decapsulationKey, result.ciphertext),
        result.sharedSecret,
      );
    });

    test('a tampered ciphertext is implicitly rejected, not reported', () {
      final pair = MLKem768.generateKeyPair();
      final result = MLKem768.encapsulate(pair.encapsulationKey);
      final tampered = Uint8List.fromList(result.ciphertext)..[0] ^= 1;
      final secret = MLKem768.decapsulate(pair.decapsulationKey, tampered);
      expect(secret, hasLength(MLKem768.sharedSecretLength));
      expect(secret, isNot(result.sharedSecret));
    });

    test('rejects inputs of the wrong length', () {
      final pair = MLKem768.generateKeyPair();
      expect(
        () => MLKem768.encapsulate(
            Uint8List(MLKem768.encapsulationKeyLength - 1)),
        throwsArgumentError,
      );
      expect(
        () => MLKem768.decapsulate(pair.decapsulationKey, Uint8List(1)),
        throwsArgumentError,
      );
    });
  });
}
