import 'dart:typed_data';
import 'package:dartssh2/src/message/msg_channel.dart';
import 'package:dartssh2/src/ssh_channel.dart';

const window = 2 * 1024 * 1024;

int countAdjusts({required int packetSize, required int totalBytes}) {
  var adjusts = 0;
  late SSHChannelController c;
  c = SSHChannelController(
    localId: 1,
    localMaximumPacketSize: 32768,
    localInitialWindowSize: window,
    remoteId: 42,
    remoteInitialWindowSize: 0,
    remoteMaximumPacketSize: 32768,
    sendMessage: (m) {
      if (m is SSH_Message_Channel_Window_Adjust) adjusts++;
    },
  );
  c.channel.stream.listen((_) {});
  var sent = 0;
  while (sent < totalBytes) {
    c.handleMessage(SSH_Message_Channel_Data(
        recipientChannel: 1, data: Uint8List(packetSize)));
    sent += packetSize;
  }
  return adjusts;
}

void main() {
  for (final (label, pkt, total) in [
    ('bulk transfer  32 KiB pkts, 8 MiB', 32768, 8 * 1024 * 1024),
    ('terminal-ish    512 B pkts, 1 MiB', 512, 1024 * 1024),
    ('chatty agent     64 B pkts, 256 KiB', 64, 256 * 1024),
  ]) {
    final inbound = total ~/ pkt;
    final adjusts = countAdjusts(packetSize: pkt, totalBytes: total);
    print('$label: inbound=$inbound uplinkAdjusts=$adjusts '
        'ratio=${(inbound / (adjusts == 0 ? 1 : adjusts)).toStringAsFixed(1)}:1');
  }
}
