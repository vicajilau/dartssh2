import 'dart:convert';
import 'dart:typed_data';

import 'package:dartssh2/src/utils/hostkey_fingerprint.dart';
import 'package:pointycastle/export.dart';
import 'package:test/test.dart';

void main() {
  test('formats host key fingerprints using OpenSSH SHA256 style', () {
    final hostkey =
        Uint8List.fromList(List<int>.generate(32, (index) => index));

    final fingerprint = utf8.decode(hostkeyFingerprint(hostkey));
    final expectedDigest = SHA256Digest().process(hostkey);
    final expected =
        'SHA256:${base64.encode(expectedDigest).replaceAll('=', '')}';

    expect(fingerprint, equals(expected));
  });
}
