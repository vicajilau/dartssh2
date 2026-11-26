import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/digests/sha256.dart';

/// The OpenSSH-style SHA256 fingerprint of an encoded host key, UTF-8
/// encoded as `SHA256:<base64>` without padding, as `ssh-keygen -l` prints it.
Uint8List hostkeyFingerprint(Uint8List hostkey) {
  final fingerprint = SHA256Digest().process(hostkey);
  final encoded = base64.encode(fingerprint).replaceAll('=', '');
  return Uint8List.fromList(utf8.encode('SHA256:$encoded'));
}
