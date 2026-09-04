/// Web stand-in for `sftp_file_io.dart`.
///
/// That library defines `SftpFileDownload.downloadToRandomAccess`, which takes
/// a `dart:io` [RandomAccessFile]. There is no such thing on the web and no
/// local file to hand it, so the extension simply is not there. Use
/// `SftpFile.downloadTo`, which takes a sink, or `SftpFile.read`.
library;
