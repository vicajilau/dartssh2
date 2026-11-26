// Uses dart:mirrors, which is VM-only.
@TestOn('vm')
library;

import 'dart:convert';
// Deprecated in Dart 3.14, still needed here to reach private state.
// ignore: deprecated_member_use
import 'dart:mirrors';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:pointycastle/export.dart';
import 'package:test/test.dart';

void main() {
  final transportLibrary = reflectClass(SSHTransport).owner as LibraryMirror;

  Uint8List invokeFingerprint(Uint8List hostkey) {
    final symbol =
        MirrorSystem.getSymbol('_hostkeyFingerprint', transportLibrary);
    return transportLibrary.invoke(symbol, [hostkey]).reflectee as Uint8List;
  }

  test('formats host key fingerprints using OpenSSH SHA256 style', () {
    final hostkey =
        Uint8List.fromList(List<int>.generate(32, (index) => index));

    final fingerprint = utf8.decode(invokeFingerprint(hostkey));
    final expectedDigest = SHA256Digest().process(hostkey);
    final expected =
        'SHA256:${base64.encode(expectedDigest).replaceAll('=', '')}';

    expect(fingerprint, equals(expected));
  });
}
