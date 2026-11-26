import 'dart:typed_data';

import 'package:dartssh2/src/utils/list.dart';
import 'package:meta/meta.dart';

/// Contains rfc4253 packet format related constants and helper functions.
abstract class SSHPacket {
  /// The maximum size of a packet including the header and MAC.
  static const maxLength = 35000;

  /// The maximum size of uncompressed packet payload.
  static const maxPayloadLength = 32768;

  /// rfc4253 requires the total length of the packet is a multiple of 8 or
  /// the cipher block size, whichever is larger.
  static const minAlign = 8;

  /// The length of the packet header, is the sum of the lengths of the
  /// length field and the padding length field.
  static const headerLength = 5;

  /// Returns the length field of the packet. This is the number of bytes
  /// following the length field except for the MAC. [packet] can be partitial.
  static int readPacketLength(Uint8List packet) {
    return ByteData.sublistView(packet).getUint32(0);
  }

  /// Returns the length of padding at the end of the packet before the MAC.
  /// [packet] can be partitial.
  static int readPaddingLength(Uint8List packet) {
    return ByteData.sublistView(packet).getUint8(4);
  }

  /// Computes the correct padding length for the packet from [payloadLength]
  /// and [align].
  static int paddingLength(int payloadLength, {required int align}) {
    final paddingLength = align - ((payloadLength + headerLength) % align);
    // ssh padding must be at least 4 bytes
    return paddingLength < 4 ? paddingLength + align : paddingLength;
  }

  /// Returns a rfc4253 packet built from [payload] and [align] including the
  /// length field, padding length field, and padding. Withouth the MAC.
  static Uint8List pack(Uint8List payload, {required int align}) {
    final padding = paddingLength(payload.length, align: align);
    final header = ByteData(5);
    header.setUint32(0, 1 + payload.length + padding);
    header.setUint8(4, padding);
    final result = BytesBuilder(copy: false);
    result.add(Uint8List.view(header.buffer));
    result.add(payload);
    // RFC 4253 §6 requires the padding to consist of random bytes.
    result.add(randomBytes(padding));
    return result.takeBytes();
  }
}

/// SSH packet sequence number wraps around to zero after every 2^32
/// packets.
class SSHPacketSN {
  SSHPacketSN(this._value);

  SSHPacketSN.fromZero() : _value = 0;

  var _value = 0;

  int get value => _value;

  /// Lets tests start near the 2³² wrap without sending that many packets.
  @visibleForTesting
  set value(int value) => _value = value;

  void increase() {
    if (_value == 0xffffffff) {
      _value = 0;
    } else {
      _value++;
    }
  }

  /// Resets the sequence number back to zero.
  ///
  /// Used by the strict key exchange mode, which resets both sequence numbers
  /// after every SSH_MSG_NEWKEYS instead of letting them run monotonically for
  /// the whole session.
  void reset() {
    _value = 0;
  }
}
