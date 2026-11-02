import 'dart:typed_data';

import 'package:dartssh2/src/utils/list.dart';
import 'package:meta/meta.dart';
import 'package:pointycastle/digests/sha3.dart';
import 'package:pointycastle/digests/shake.dart';

/// ML-KEM-768, the module-lattice key-encapsulation mechanism of FIPS 203,
/// for the post-quantum half of `mlkem768x25519-sha256`.
///
/// Algorithm numbers in the comments refer to FIPS 203. Coefficients are kept
/// reduced into `[0, q)` after every operation, so no intermediate value
/// exceeds `2q²` (about 2²⁵) and the arithmetic stays exact on the web, where
/// integers are doubles and bitwise operators truncate to 32 bits.
///
/// This is not a constant-time implementation: reductions use `%` and
/// compression uses `~/` on secret values, and Dart guarantees nothing about
/// the timing of either. That is acceptable for an SSH key exchange, where
/// each key pair is generated for one connection and decapsulates exactly one
/// ciphertext, so an observer gets a single timing sample per key, whereas
/// timing attacks on ML-KEM such as KyberSlash need thousands against the same
/// key. Do not use it with long-lived decapsulation keys.
abstract final class MLKem768 {
  static const encapsulationKeyLength = 384 * _k + 32;

  static const decapsulationKeyLength = 768 * _k + 96;

  static const ciphertextLength = 32 * (_du * _k + _dv);

  static const sharedSecretLength = 32;

  /// Generates a key pair from fresh randomness (Algorithm 19).
  static MLKemKeyPair generateKeyPair() =>
      generateKeyPairFromSeed(randomBytes(32), randomBytes(32));

  /// Derives a key pair from the seeds [d] and [z] (Algorithm 16).
  @visibleForTesting
  static MLKemKeyPair generateKeyPairFromSeed(Uint8List d, Uint8List z) {
    _checkLength(d, 32, 'd');
    _checkLength(z, 32, 'z');
    final (ek, dkPke) = _pkeKeyGen(d);
    final dk = Uint8List(decapsulationKeyLength)
      ..setAll(0, dkPke)
      ..setAll(384 * _k, ek)
      ..setAll(768 * _k + 32, _h(ek))
      ..setAll(768 * _k + 64, z);
    return MLKemKeyPair(ek, dk);
  }

  /// Encapsulates a fresh shared secret to [encapsulationKey] (Algorithm 20).
  ///
  /// Throws [ArgumentError] if the key fails the input check of §7.2.
  static MLKemEncapsulation encapsulate(Uint8List encapsulationKey) =>
      encapsulateWithRandomness(encapsulationKey, randomBytes(32));

  /// Encapsulates with the message [m] instead of fresh randomness
  /// (Algorithm 17).
  @visibleForTesting
  static MLKemEncapsulation encapsulateWithRandomness(
    Uint8List encapsulationKey,
    Uint8List m,
  ) {
    if (!isValidEncapsulationKey(encapsulationKey)) {
      throw ArgumentError('invalid ML-KEM-768 encapsulation key');
    }
    _checkLength(m, 32, 'm');
    final g = _g(Uint8List.fromList([...m, ..._h(encapsulationKey)]));
    final ciphertext = _pkeEncrypt(encapsulationKey, m, g.sublist(32));
    return MLKemEncapsulation(ciphertext, g.sublist(0, 32));
  }

  /// Recovers the shared secret from [ciphertext] (Algorithms 18 and 21).
  ///
  /// A ciphertext that does not re-encrypt to itself yields the implicit
  /// rejection value instead of an error, as FIPS 203 requires, so a peer
  /// cannot tell a rejected ciphertext from an accepted one. Throws
  /// [ArgumentError] only for inputs that fail the checks of §7.3.
  static Uint8List decapsulate(
      Uint8List decapsulationKey, Uint8List ciphertext) {
    if (!isValidDecapsulationKey(decapsulationKey)) {
      throw ArgumentError('invalid ML-KEM-768 decapsulation key');
    }
    _checkLength(ciphertext, ciphertextLength, 'ciphertext');

    final dkPke = decapsulationKey.sublist(0, 384 * _k);
    final ek = decapsulationKey.sublist(384 * _k, 768 * _k + 32);
    final h = decapsulationKey.sublist(768 * _k + 32, 768 * _k + 64);
    final z = decapsulationKey.sublist(768 * _k + 64);

    final m = _pkeDecrypt(dkPke, ciphertext);
    final g = _g(Uint8List.fromList([...m, ...h]));
    final accepted = g.sublist(0, 32);
    final rejected = _j(Uint8List.fromList([...z, ...ciphertext]));
    final reencrypted = _pkeEncrypt(ek, m, g.sublist(32));

    // Select without branching on the comparison: 0xff keeps [accepted].
    var diff = 0;
    for (var i = 0; i < ciphertextLength; i++) {
      diff |= ciphertext[i] ^ reencrypted[i];
    }
    final mask = -(((diff - 1) >> 8) & 1) & 0xff;
    return Uint8List.fromList([
      for (var i = 0; i < sharedSecretLength; i++)
        (accepted[i] & mask) | (rejected[i] & ~mask & 0xff),
    ]);
  }

  /// The encapsulation key check of §7.2: the right length, and every
  /// coefficient of `t̂` already reduced modulo q.
  static bool isValidEncapsulationKey(Uint8List ek) {
    if (ek.length != encapsulationKeyLength) return false;
    for (var i = 0; i < _k; i++) {
      final raw = _byteDecode(ek, 384 * i, 12);
      for (final coefficient in raw) {
        if (coefficient >= _q) return false;
      }
    }
    return true;
  }

  /// The decapsulation key check of §7.3: the right length, and the embedded
  /// hash matching the embedded encapsulation key.
  static bool isValidDecapsulationKey(Uint8List dk) {
    if (dk.length != decapsulationKeyLength) return false;
    final ek = Uint8List.sublistView(dk, 384 * _k, 768 * _k + 32);
    final h = Uint8List.sublistView(dk, 768 * _k + 32, 768 * _k + 64);
    return constantTimeEquals(_h(ek), h);
  }
}

class MLKemKeyPair {
  final Uint8List encapsulationKey;

  final Uint8List decapsulationKey;

  MLKemKeyPair(this.encapsulationKey, this.decapsulationKey);
}

class MLKemEncapsulation {
  final Uint8List ciphertext;

  final Uint8List sharedSecret;

  MLKemEncapsulation(this.ciphertext, this.sharedSecret);
}

const _n = 256;
const _q = 3329;
const _k = 3;
const _eta1 = 2;
const _eta2 = 2;
const _du = 10;
const _dv = 4;

/// `ζ^BitRev7(i) mod q` for the NTT, with ζ = 17.
final _zetas = Int32List.fromList([
  for (var i = 0; i < 128; i++) _powMod(17, _bitRev7(i)),
]);

/// `ζ^(2·BitRev7(i)+1) mod q` for the base-case multiplication.
final _gammas = Int32List.fromList([
  for (var i = 0; i < 128; i++) _powMod(17, 2 * _bitRev7(i) + 1),
]);

int _bitRev7(int i) {
  var r = 0;
  for (var b = 0; b < 7; b++) {
    r |= ((i >> b) & 1) << (6 - b);
  }
  return r;
}

int _powMod(int base, int exponent) {
  var result = 1;
  for (var i = 0; i < exponent; i++) {
    result = result * base % _q;
  }
  return result;
}

void _checkLength(Uint8List bytes, int length, String name) {
  if (bytes.length != length) {
    throw ArgumentError.value(bytes.length, name, 'must be $length bytes');
  }
}

/// H: SHA3-256.
Uint8List _h(Uint8List input) => SHA3Digest(256).process(input);

/// G: SHA3-512, split by the caller into two 32-byte halves.
Uint8List _g(Uint8List input) => SHA3Digest(512).process(input);

/// J: SHAKE256 with a 32-byte output.
Uint8List _j(Uint8List input) {
  final out = Uint8List(32);
  (SHAKEDigest(256)..update(input, 0, input.length)).doOutput(out, 0, 32);
  return out;
}

/// PRF_η: SHAKE256 of `s ‖ b`, 64η bytes.
Uint8List _prf(int eta, Uint8List s, int b) {
  final out = Uint8List(64 * eta);
  (SHAKEDigest(256)
        ..update(s, 0, s.length)
        ..updateByte(b))
      .doOutput(out, 0, out.length);
  return out;
}

/// ByteEncode_d (Algorithm 5): packs 256 d-bit integers little-endian.
Uint8List _byteEncode(Int32List f, int d) {
  final out = Uint8List(32 * d);
  var acc = 0, bits = 0, o = 0;
  for (final x in f) {
    acc |= x << bits;
    bits += d;
    while (bits >= 8) {
      out[o++] = acc & 0xff;
      acc >>= 8;
      bits -= 8;
    }
  }
  return out;
}

/// ByteDecode_d (Algorithm 6) without the reduction modulo q that FIPS 203
/// applies for d = 12, so the encapsulation key check can see the raw value.
Int32List _byteDecode(Uint8List bytes, int offset, int d) {
  final f = Int32List(_n);
  final mask = (1 << d) - 1;
  var acc = 0, bits = 0, p = offset;
  for (var i = 0; i < _n; i++) {
    while (bits < d) {
      acc |= bytes[p++] << bits;
      bits += 8;
    }
    f[i] = acc & mask;
    acc >>= d;
    bits -= d;
  }
  return f;
}

/// ByteDecode_12 as FIPS 203 defines it, reducing each coefficient mod q.
Int32List _byteDecode12(Uint8List bytes, int offset) {
  final f = _byteDecode(bytes, offset, 12);
  for (var i = 0; i < _n; i++) {
    f[i] %= _q;
  }
  return f;
}

/// Compress_d: `round(2^d / q · x) mod 2^d`.
Int32List _compress(Int32List f, int d) => Int32List.fromList([
      for (final x in f) (((x << (d + 1)) + _q) ~/ (2 * _q)) & ((1 << d) - 1),
    ]);

/// Decompress_d: `round(q / 2^d · y)`.
Int32List _decompress(Int32List f, int d) => Int32List.fromList([
      for (final y in f) (_q * y + (1 << (d - 1))) >> d,
    ]);

/// SampleNTT (Algorithm 7): rejection-samples a polynomial in the NTT domain
/// from SHAKE128 of `ρ ‖ j ‖ i`.
Int32List _sampleNtt(Uint8List rho, int j, int i) {
  final xof = SHAKEDigest(128)
    ..update(rho, 0, rho.length)
    ..updateByte(j)
    ..updateByte(i);
  final a = Int32List(_n);
  // One SHAKE128 block: 168 bytes, a whole number of 3-byte candidates.
  final block = Uint8List(168);
  var n = 0;
  while (n < _n) {
    xof.doOutput(block, 0, block.length);
    for (var p = 0; p < block.length && n < _n; p += 3) {
      final d1 = block[p] | ((block[p + 1] & 0x0f) << 8);
      final d2 = (block[p + 1] >> 4) | (block[p + 2] << 4);
      if (d1 < _q) a[n++] = d1;
      if (d2 < _q && n < _n) a[n++] = d2;
    }
  }
  return a;
}

/// SamplePolyCBD_η (Algorithm 8): a centered binomial sample from 64η bytes.
Int32List _samplePolyCbd(Uint8List bytes, int eta) {
  final f = Int32List(_n);
  int bit(int index) => (bytes[index >> 3] >> (index & 7)) & 1;
  for (var i = 0; i < _n; i++) {
    var x = 0, y = 0;
    for (var j = 0; j < eta; j++) {
      x += bit(2 * i * eta + j);
      y += bit(2 * i * eta + eta + j);
    }
    f[i] = (x - y) % _q;
  }
  return f;
}

/// NTT (Algorithm 9), in place.
Int32List _ntt(Int32List f) {
  var i = 1;
  for (var len = 128; len >= 2; len >>= 1) {
    for (var start = 0; start < _n; start += 2 * len) {
      final zeta = _zetas[i++];
      for (var j = start; j < start + len; j++) {
        final t = zeta * f[j + len] % _q;
        f[j + len] = (f[j] - t) % _q;
        f[j] = (f[j] + t) % _q;
      }
    }
  }
  return f;
}

/// NTT⁻¹ (Algorithm 10), in place.
Int32List _nttInverse(Int32List f) {
  var i = 127;
  for (var len = 2; len <= 128; len <<= 1) {
    for (var start = 0; start < _n; start += 2 * len) {
      final zeta = _zetas[i--];
      for (var j = start; j < start + len; j++) {
        final t = f[j];
        f[j] = (t + f[j + len]) % _q;
        f[j + len] = zeta * ((f[j + len] - t) % _q) % _q;
      }
    }
  }
  // 3303 = 128⁻¹ mod q.
  for (var j = 0; j < _n; j++) {
    f[j] = f[j] * 3303 % _q;
  }
  return f;
}

/// MultiplyNTTs (Algorithms 11 and 12), accumulated into [acc].
void _multiplyNttsAdd(Int32List acc, Int32List f, Int32List g) {
  for (var i = 0; i < 128; i++) {
    final a0 = f[2 * i], a1 = f[2 * i + 1];
    final b0 = g[2 * i], b1 = g[2 * i + 1];
    final c0 = (a0 * b0 + a1 * b1 % _q * _gammas[i]) % _q;
    final c1 = (a0 * b1 + a1 * b0) % _q;
    acc[2 * i] = (acc[2 * i] + c0) % _q;
    acc[2 * i + 1] = (acc[2 * i + 1] + c1) % _q;
  }
}

void _addInPlace(Int32List f, Int32List g) {
  for (var i = 0; i < _n; i++) {
    f[i] = (f[i] + g[i]) % _q;
  }
}

/// Â, with `Â[i][j] = SampleNTT(ρ ‖ j ‖ i)`.
List<List<Int32List>> _matrix(Uint8List rho) => [
      for (var i = 0; i < _k; i++)
        [for (var j = 0; j < _k; j++) _sampleNtt(rho, j, i)],
    ];

/// K-PKE.KeyGen (Algorithm 13). Returns `(ek, dk_PKE)`.
(Uint8List, Uint8List) _pkeKeyGen(Uint8List d) {
  final g = _g(Uint8List.fromList([...d, _k]));
  final rho = g.sublist(0, 32);
  final sigma = g.sublist(32);
  final a = _matrix(rho);

  var nonce = 0;
  final s = [
    for (var i = 0; i < _k; i++)
      _ntt(_samplePolyCbd(_prf(_eta1, sigma, nonce++), _eta1)),
  ];
  final e = [
    for (var i = 0; i < _k; i++)
      _ntt(_samplePolyCbd(_prf(_eta1, sigma, nonce++), _eta1)),
  ];

  final ek = BytesBuilder(copy: false);
  final dk = BytesBuilder(copy: false);
  for (var i = 0; i < _k; i++) {
    final t = Int32List.fromList(e[i]);
    for (var j = 0; j < _k; j++) {
      _multiplyNttsAdd(t, a[i][j], s[j]);
    }
    ek.add(_byteEncode(t, 12));
    dk.add(_byteEncode(s[i], 12));
  }
  ek.add(rho);
  return (ek.toBytes(), dk.toBytes());
}

/// K-PKE.Encrypt (Algorithm 14).
Uint8List _pkeEncrypt(Uint8List ek, Uint8List m, Uint8List r) {
  final t = [for (var i = 0; i < _k; i++) _byteDecode12(ek, 384 * i)];
  final a = _matrix(Uint8List.sublistView(ek, 384 * _k));

  var nonce = 0;
  final y = [
    for (var i = 0; i < _k; i++)
      _ntt(_samplePolyCbd(_prf(_eta1, r, nonce++), _eta1)),
  ];
  final e1 = [
    for (var i = 0; i < _k; i++) _samplePolyCbd(_prf(_eta2, r, nonce++), _eta2),
  ];
  final e2 = _samplePolyCbd(_prf(_eta2, r, nonce++), _eta2);

  final c = BytesBuilder(copy: false);
  for (var i = 0; i < _k; i++) {
    final u = Int32List(_n);
    for (var j = 0; j < _k; j++) {
      _multiplyNttsAdd(u, a[j][i], y[j]);
    }
    _addInPlace(_nttInverse(u), e1[i]);
    c.add(_byteEncode(_compress(u, _du), _du));
  }

  final v = Int32List(_n);
  for (var i = 0; i < _k; i++) {
    _multiplyNttsAdd(v, t[i], y[i]);
  }
  _addInPlace(_nttInverse(v), e2);
  _addInPlace(v, _decompress(_byteDecode(m, 0, 1), 1));
  c.add(_byteEncode(_compress(v, _dv), _dv));
  return c.toBytes();
}

/// K-PKE.Decrypt (Algorithm 15).
Uint8List _pkeDecrypt(Uint8List dk, Uint8List c) {
  final w = _decompress(_byteDecode(c, 32 * _du * _k, _dv), _dv);
  final product = Int32List(_n);
  for (var i = 0; i < _k; i++) {
    final u = _ntt(_decompress(_byteDecode(c, 32 * _du * i, _du), _du));
    _multiplyNttsAdd(product, _byteDecode12(dk, 384 * i), u);
  }
  _nttInverse(product);
  for (var i = 0; i < _n; i++) {
    w[i] = (w[i] - product[i]) % _q;
  }
  return _byteEncode(_compress(w, 1), 1);
}
