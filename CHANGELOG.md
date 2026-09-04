## [4.1.0] - 2026-09-04
- Added `SSHClient.pipelineChannelRequests`, off by default, which sends all of a session's channel requests before reading any reply instead of waiting for each one in turn. `execute` and `shell` send `env`, agent forwarding, `pty-req` and `x11-req` ahead of `exec` or `shell`, and each of them cost a round trip: against a server 40 ms away, `execute` with a pty measured 246 ms before and 206 ms after. RFC 4254 §5.4 permits sending further messages without waiting and §4 requires the peer to answer a channel's requests in the order it received them, which is what `ssh(1)` relies on when it does the same thing. Setting it also adopts OpenSSH's reporting, because it has to: the command is on the wire before a refusal can come back, so a refused `pty-req`, `env`, agent forwarding or `x11-req` is reported through `printDebug` and the command runs, the way `ssh(1)` prints `PTY allocation request failed on channel 0` and carries on, rather than throwing an error that means the command has already run. Only a refused `exec` or `shell` still throws `SSHChannelRequestError`, because nothing has run when that one fails. Leaving it unset changes nothing, down to the order the requests go out and the message of every error [#243].
- Added a `dartssh2-nopty` account to the interop server, which `PermitTTY no` applies to, so both sides of a refused `pty-req` are exercised against a real OpenSSH: by default the command does not run, and with pipelining it does [#243].
- Fixed the package reading as web-incompatible on pub.dev. `SftpFile.downloadToRandomAccess` takes a `dart:io` `RandomAccessFile`, and naming that type from the SFTP library was enough for pub.dev to drop `platform:web` from the whole package, which also keeps it out of any search filtered to web. Everything else already compiled and ran there, and 4.0.0 made the ciphers and SFTP work. The method moves to an `SftpFileDownload` extension in its own library, exported conditionally the way `SSHSocket` and dynamic forwarding already are, so nothing changes for a caller on the VM: same import, same call. On the web the extension is simply absent, as is the `RandomAccessFile` it would need. Confirmed with pana, the tool pub.dev scores with: `platform:web` is present after and absent before [#248].
- Added browser interop tests, so "web is supported" is something CI checks rather than something the pieces individually suggest. Everything that ran under `-p chrome` until now proved the AEAD arithmetic, the SFTP encoding and the HTTP parsing compile and behave, and none of it put a packet on a wire, which is the gap that let every AEAD cipher and the whole of SFTP sit broken on the web until 4.0.0. The new tests run the browser against the same OpenSSH server the VM interop tests use, through `tool/ws_bridge.dart`, and cover a handshake, a command, an `aes256-gcm` session and an SFTP round trip. The `SSHSocket` they connect through is the WebSocket one the README tells web users to write, so it doubles as a worked example [#248].

## [4.0.1] - 2026-09-03
- Fixed a channel stalling permanently when data arrived before the application subscribed to it. `StreamController.isPaused` is true until something listens, which suppressed every `SSH_MSG_CHANNEL_WINDOW_ADJUST`, and Dart delivers the first subscription as `onListen` rather than `onResume` — the only hook wired — so a peer that legally filled the advertised window in that gap was left at zero credit with no further data able to arrive and trigger a grant. Reproduced at the client's own sizes with 64 packets of 32 KiB into a 2 MiB window, before and after the first listener and through `.map()`, in every case zero adjustments. The remote forwarding example in the README reaches it: it awaits `Socket.connect()` for each connection before subscribing, and the forwarded channel is created with no listener attached [#244].
- Changed the receive window to be granted back once half of it has been consumed rather than after every data packet. Any consumed byte made the outstanding grant positive, so each `SSH_MSG_CHANNEL_DATA` was answered with a window adjust of its own, and the smaller the packets the closer the uplink packet count got to the downlink one: counted on `SSHChannelController`, 256 inbound packets of 32 KiB produced 256 adjustments, and 4096 of 64 B produced 4096. They now produce 8 and 0. This is one of the two rules OpenSSH applies in `channels.c`, which refills at half the window or once `local_window_max - local_window > local_maxpacket * 3`, whichever comes first. Only the first is implemented here, so at a 2 MiB window with 32 KiB packets this defers further than OpenSSH would, thirty-two packets against its three or four, which is the point of the change. The threshold never defers past one maximum packet of remaining credit, so a window smaller than twice the packet size cannot leave a conforming peer holding a chunk it may neither send nor is obliged to split. Pausing the stream still suppresses the grant, which is the documented backpressure mechanism [#244].

## [4.0.0] - 2026-08-31
- **Breaking change.** Removed the legacy algorithms from the default proposals, leaving them implemented but off unless asked for: the SHA-1 key exchange methods `diffie-hellman-group14-sha1` and `diffie-hellman-group-exchange-sha1`, the `ssh-rsa` host key signature, and the `aes256-cbc` and `aes128-cbc` ciphers. This matches what OpenSSH proposes in `myproposal.h`, which drops all of them and keeps only `hmac-sha1` at the end of the MAC list, as this does. `ssh-rsa` signs host keys with SHA-1 and is open to chosen-prefix collisions, which is why OpenSSH disabled it by default in 8.8, and CBC in SSH is vulnerable to the plaintext recovery of CVE-2008-5161. A server that offers nothing but these will now fail to negotiate rather than connect weakly, which for older routers, NAS boxes and embedded servers is a real change: pass the algorithm through `SSHAlgorithms` to keep talking to it [#236]. Thanks [@GT-610].
- Changed SFTP uploads to pipeline a bounded number of outstanding write requests, 64 by default, matching OpenSSH's `DEFAULT_NUM_REQUESTS`. Writes were issued and awaited one at a time, so every chunk cost a full round trip and a high latency link spent most of its time idle. Acknowledgements are now accepted out of order without resubmitting an offset, and offsets are still assigned in stream order so concurrent writes cannot overlap. `SftpFile.write` and `SftpFileWriter` take `chunkSize` and `maxPendingRequests`, and reject a negative offset or a non-positive setting rather than misbehaving later [#237]. Thanks [@GT-610].
- Changed a failing SFTP upload to stop scheduling new writes, drain the ones already in flight and report the first error through the returned future, instead of surfacing whichever error happened to arrive last. This supersedes the narrower `SftpFileWriter` error handling added in #230, whose regression tests all still pass [#237].
- Deprecated `chunkSize` in favour of `defaultChunkSize`, and `maxBytesOnTheWire`, which nothing reads any more now that uploads are bounded by request count rather than by a byte window [#237].
- Changed `ChunkBuffer` to grow by reallocating with headroom instead of copying the whole buffer on every append, making `add()` amortised O(1) rather than O(n). Accumulating 64 MB in 8 KiB chunks without draining, which is what a burst of packets arriving faster than they are consumed looks like, drops from about 185 seconds to about 72 milliseconds. The steady drained case costs about 25% more, roughly 162 ms to 202 ms over 20k packets of 32 KiB, because `consume()` now returns a copy rather than an alias into a buffer a later `add()` may reallocate; both figures are around 3 GB/s, so neither is visible next to a network [#231].
- Removed the dead `MinChunkSize` stream transformer and two stale markers in `ssh_mac_type.dart`, neither of which anything referenced [#231].
- Removed the legacy analyzer plugin entry from `analysis_options.yaml`. Dart 3.13.2 warns on it and `dart analyze` exits non-zero on a warning, so every job on every branch started failing with nothing in the code having changed. It was dead configuration in any case: `dart_code_metrics_presets` ships preset YAML meant for `include:`, no analyzer plugin, so nothing was ever loaded through it. The now unused dev dependency went with it [#232] [#233].
- Scoped the encrypted key tests to the VM. They use `dart:io` for their `ssh-keygen` interoperability checks, which the web job cannot load [#239].
- **Breaking change.** `SftpFileAttrs` now drops a `uidgid` or `acmodtime` pair when only one half of it is set, instead of writing the flag with a single value. The pair is two fields under one flag in the SFTP wire format, so a half-filled one produced a packet the server misparsed, applying the wrong ownership or timestamps. Anyone calling `setStat` with only `modifyTime` set will find the value is now ignored rather than sent alongside a garbage access time; set both to change either [#230]. Thanks [@klc].
- **Breaking change.** A host key that changes during a rekey now terminates the connection with `SSHHostkeyError`, as OpenSSH does. The signature was already re-checked on every exchange, but that only proved the key presented was self-consistent, not that it was the key `onVerifyHostKey` had already approved, so a server could hand out one key at connect time and a different one on the first rekey. A connection that used to survive this will now drop. `onVerifyHostKey` is consulted once per connection, not once per exchange [#229]. Thanks [@klc].
- Fixed the version exchange failing when the banner arrives split across TCP segments or WebSocket frames. It was treated as a framing error rather than a partial read, which made the WebSocket transport the README recommends for web unreliable by construction, and any slow or proxied connection intermittently so. Lines of text sent before the identification line are also skipped now, which RFC 4253 §4.2 says clients MUST be able to process; at most 1024 of them, matching OpenSSH, so a server streaming them forever cannot keep a client busy [#229].
- Fixed `keyboard-interactive` responses being written to the trace log in plaintext, which put the user's password in any log a caller collected with `printTrace` set [#229].
- Changed MAC comparison to constant time, and removed both the received and the expected MAC from the failure message [#229].
- Fixed three of the four packet send paths using a fixed padding pattern instead of random bytes, contrary to RFC 4253 §6 [#229].
- Added validation of the peer's public value in every key exchange. Finite field Diffie-Hellman now requires `1 < f < p - 1`, the NIST curves reject points that fail to decode, lie off the curve or are the point at infinity, and X25519 rejects small-order points via the RFC 8731 §3 all-zero shared secret check and requires the key to be exactly 32 bytes. Without these a peer could force a shared secret it knew in advance [#229].
- Added the missing lower bound and AEAD path checks to packet length validation, and made a zero-length payload raise `SSHPacketError` instead of a `RangeError` that no `SSHError` handler would catch [#229].
- Changed the non-ETM receive path to verify the MAC before parsing the padding, so a forged packet is rejected before its length fields are trusted [#229].
- Fixed the non-ETM receive path accepting a packet whose encrypted length is not a multiple of the cipher block size. The decrypt loop pulled whole blocks until it had enough, so an unaligned length made it read past the ciphertext and on into the MAC, and the `RangeError` that followed was not an `SSHError` any handler would catch. The length is now rejected up front, as OpenSSH does in `ssh_packet_read_poll2()`, and the remaining ciphertext is decrypted in one pass instead of a block at a time [#234]. Thanks [@GT-610].
- Fixed `SSH_MSG_KEX_ECDH_REPLY` being encoded with its fields in the wrong order. RFC 5656 §4 specifies `K_S, Q_S, signature`, which is what this library's own decoder already expected, so only a peer decoding what dartssh2 sent as a server was affected [#229].
- Fixed `writeMpint(BigInt.zero)` emitting `00 00 00 01 00` where RFC 4251 §5 requires a zero-length string, and `readNameList` returning `['']` for an empty name-list [#229].
- Documented that leaving `onVerifyHostKey` null accepts any host key, which makes the connection trivially interceptable. The parameter is optional and the behaviour was not stated anywhere [#229].
- Added encrypted OpenSSH private-key writing. `OpenSSHKeyPair.toPem()` takes an optional `passphrase`, and a non-empty one encrypts the private section with `aes256-ctr` keyed by `bcrypt_pbkdf`, following what `sshkey_private_to_blob2()` writes: a 16-byte salt, 24 rounds, key and IV derived together in one call, the check integer written twice and the block padded with 1, 2, 3 and so on. A null or empty passphrase still writes the unencrypted form. `OpenSSHKeyPairs.encrypted` builds the container directly for callers that need it. The `SSHKeyPair` interface is unchanged, so the new arguments are reachable only through `OpenSSHKeyPair` [#235]. Thanks [@GT-610].
- Fixed a failing bcrypt KDF being ignored when reading an encrypted OpenSSH key. `bcrypt_pbkdf` reports invalid parameters through its return value, which was discarded, so a key with a zero round count or an empty salt carried on with an underived key and failed later as a check-integer mismatch. It now raises `SSHKeyDecryptError` at the point the KDF fails [#235]. Thanks [@GT-610].
- Added `SSHClient.rekey()`, which starts a new key exchange on an established connection and returns a `Future<void>` completing once the new keys are in effect, so a caller rekeying between transfers can await it instead of watching `done`. If an exchange is already running, whether this side or the server started it, no second one is sent and the future tracks the one in flight; if the connection ends first the future carries the error that ended it. `SSHTransport.rekey()` was already public and returns the same future now, where it used to return `void` [#229].
- Fixed every AEAD cipher and the whole of SFTP being dead on the web. `ByteData.getUint64` and `setUint64` throw `Unsupported operation: Uint64 accessor not supported by dart2js`, and four call sites went through them: the message reader, the int helper, the AES-GCM nonce and the ChaCha20-Poly1305 nonce. Since `aes256-gcm@openssh.com` sits first in the default cipher list, a browser connection died at the first encrypted packet even with a correct custom `SSHSocket`. Each now reads and writes two 32-bit words instead, bit-for-bit identical on the VM; compiled to JS a value needing more than 53 bits raises `UnsupportedError` rather than silently rounding, since these back SFTP file sizes and offsets [#230].
- Added a `test-web` CI job running `dart test -p chrome`, with `@TestOn` markers on the suites that genuinely need the VM. Nothing ran against dart2js before, which is how the above went unnoticed while the README listed web as supported [#230].
- Fixed virtual files such as those under `/proc` and `/dev` being handed back as empty. They report a stat size of 0 while still returning data, and `read`, `downloadTo` and `downloadToRandomAccess` all trusted the reported size and returned before issuing a read. Reads are now EOF-driven when the size cannot be trusted [#230].
- Fixed `SftpFileWriter` hanging forever when the local stream raised. Errors had no handler and `_handleLocalDone` completed the done future unguarded, so a failing upload never returned and could also double-complete [#230].
- Fixed an HTTP response body being discarded when the server sends no `Content-Length`. The body was read only up to a length that stayed 0, so whether it survived depended on TCP segment boundaries [#230].
- Fixed `HttpHeaders.host` and `HttpHeaders.port` returning null for a perfectly valid `Host` header [#230].
- Fixed a response that carries no body being read until the peer closes the connection. A 1xx, 204 or 304 response, and any response to `HEAD`, has no body whatever its framing headers say, so a server that keeps the connection open after sending one left the read waiting for bytes that were never coming. This was the sharp edge of reading unframed bodies to end of stream, added above [#230].
- Added `SSHHttpClient.idleTimeout`, which bounds the wait between two pieces of a response. A body delimited by connection close still has to be read to end of stream, and nothing else in the client bounded that, so a peer that stopped sending without closing could hang a request indefinitely. It is an inactivity timeout rather than a deadline for the whole response, so a large body that keeps arriving is never cut short; leaving it null keeps the unbounded behaviour [#230].
- Added overflow protection to the SFTP request id counter [#230].

## [3.3.1] - 2026-08-19
- Removed the background isolate offload from X25519 and NIST curve key exchange, which cost more than the work it was hiding. Generating an ephemeral key or computing the shared secret on these curves is one fixed-size scalar multiply, well under a millisecond, while `Isolate.run` takes several times that to spawn and tear down, and a client pays it twice per handshake. On a memory constrained Android device the spawn delay was long enough for the server to time out the key exchange and close the connection before `SSH_MSG_NEWKEYS` went out, surfacing as `SSHAuthAbortError` with a null reason [#226]. Thanks [@cesarcamps].
- Kept the offload for finite field Diffie-Hellman, which is the one exchange whose cost the peer controls: group exchange lets the server name a modulus of up to 8192 bits, and modular exponentiation grows steeply with it.
- Added debug logging around host key signature verification and the `onVerifyHostKey` callback. Everything between receiving the key exchange reply and sending `SSH_MSG_NEWKEYS` used to run without a single `printDebug` call, so a slow user callback and a slow shared secret were indistinguishable in a trace, and both looked like a hung handshake [#226].

## [3.3.0] - 2026-08-18
- Added `SSHDisconnectError`, so the reason the peer gave for terminating the connection reaches the caller. `SSH_MSG_DISCONNECT` carries a reason code and a description, which is where OpenSSH puts lines such as "no matching key exchange method found"; the transport used to log it and close cleanly, leaving an unexplained disconnection [#224].
- Fixed `SSHMessageReader.readBytes()` indexing the underlying buffer instead of the message, so it returned the wrong bytes whenever the message was a view into a larger buffer, which is what every SSH and SFTP payload is. Only OpenSSH private key decoding called it, on a freshly decoded blob where the two coincide, so nothing was broken in practice [#223].
- Changed malformed packets to raise `SSHPacketError` instead of `RangeError` or `IndexError`. Every decoder that parses peer-supplied bytes went through the latter, which are how Dart reports a bug in the caller: a handler catching `SSHError` missed them, and inside a stream callback they escaped as uncaught errors [#223].
- Deprecated `SSHTransport.onPacket` in favour of `onMessage`, which reports whether it recognized a message so the transport can answer unknown ones as RFC 4253 requires. `onPacket` keeps working [#221].
- Added interop tests that run a real dartssh2 client against a real OpenSSH server, forcing one algorithm per connection across the ciphers, key exchanges and MACs, plus a command and an SFTP round trip. Unit tests can only show the library agrees with itself, which is how the X11 screen number stayed a string until #194 [#224] [#225].
- Removed the last test helper pointing at infrastructure belonging to the previous maintainer's organisation. It was unused [#224].
- Added regression tests pinning how many requests an SFTP download costs, so a repeat of the 3.0.2 read size collapse fails a test rather than needing to be found by hand [#222].
- Documented hostbased authentication in the README, which 3.2.0 added without mentioning it anywhere outside the changelog [#220].

## [3.2.0] - 2026-08-18
- Added the `chacha20-poly1305@openssh.com` packet cipher, implemented as OpenSSH's own construction rather than the RFC 8439 AEAD: two independent ChaCha20 keys, a separately encrypted packet length, and Poly1305 over the raw encrypted length and body. It joins the default cipher list in third place, after the two AES-GCM variants, so it is negotiated with servers that do not offer AES-GCM [#217]. Thanks [@GT-610].
- Added RFC 4252 hostbased authentication through the asynchronous `SSHIdentity` API, with the new `SSHClient.hostbasedIdentities`, `SSHClient.hostName` and `SSHClient.userNameOnClientHost` options. The host key blob type is kept separate from the signature algorithm, so RSA SHA-2 signatures work [#218]. Thanks [@GT-610].
- Changed the authentication state machine to treat the server's `methodsLeft` as an allow-list while keeping the client's own preference order, to keep publickey and hostbased available only while identities remain, and to reset publickey state after a partial success, as OpenSSH does [#218]. Thanks [@GT-610].
- Added RFC 4253 `SSH_MSG_UNIMPLEMENTED` handling. Genuinely unrecognized messages are now reported with the rejected packet's own sequence number, while `SSH_MSG_IGNORE`, `SSH_MSG_DEBUG` and incoming `SSH_MSG_UNIMPLEMENTED` are consumed without creating reply loops. Unexpected messages during the initial strict key exchange disconnect, matching OpenSSH, while rekeys reply instead [#216]. Thanks [@GT-610].
- Added `SSHTransport.onMessage`, a handler that reports whether it recognized a message so the transport knows when to reply `SSH_MSG_UNIMPLEMENTED`. The existing `onPacket` keeps working unchanged and assumes every packet it receives is handled [#216]. Thanks [@GT-610].
- Added a 256 KiB limit on SFTP packets in both directions, matching `SFTP_MAX_MSG_LENGTH` in OpenSSH, with the four-byte length prefix excluded. Without it a peer could declare an arbitrarily large packet and make the client buffer indefinitely while waiting for a body that never arrives [#215]. Thanks [@GT-610].

## [3.1.0] - 2026-08-17
- Fixed operations hanging forever when the component they were waiting on terminated. A channel request, a global request or a channel open whose reply could no longer arrive now fails with the error that ended the connection or the channel, instead of leaving the caller awaiting a reply that will never come [#212]. Thanks [@GT-610].
- Changed `SSH_MSG_CHANNEL_CLOSE`, channel destruction and transport termination to be terminal for pending replies, while `SSH_MSG_CHANNEL_EOF` remains non-terminal, since RFC 4254 allows request replies to arrive after EOF [#212]. Thanks [@GT-610].
- Fixed a channel stalling forever once a slow reader paused the stream: the receive window was never replenished after it reached zero, so the channel could not accept another byte for the rest of its life. This affected any slow consumer, such as an SFTP download or shell output [#210]. Thanks [@GT-610].
- Added the channel limits required by RFC 4254 §5.2: data beyond the advertised maximum packet size or beyond the remaining receive window is rejected, and a window adjustment that would overflow the 32-bit window is refused [#210]. Thanks [@GT-610].
- Changed a peer that breaks those limits to fail only the affected channel, raising the error on its stream so the caller finds out, while the connection and its other channels stay alive [#213]. Thanks [@vicajilau].
- Added rejection of unsolicited and duplicate channel open confirmations and failures, which used to be ignored [#210]. Thanks [@GT-610].
- Fixed channel identifiers leaking on a failed channel open, on an open still pending when the connection closed, and when sending the open request threw [#210]. Thanks [@GT-610].
- Added strict key exchange (`kex-strict-c-v00@openssh.com`), the countermeasure against the Terrapin attack (CVE-2023-48795). It is negotiated automatically and, when the server supports it, packet sequence numbers are reset after every `SSH_MSG_NEWKEYS`, `SSH_MSG_IGNORE` / `SSH_MSG_UNIMPLEMENTED` / `SSH_MSG_DEBUG` are rejected during a key exchange, and the first `SSH_MSG_KEXINIT` is required to be the first packet of the connection. Exposed as `SSHClient.strictKex` [#207]. Thanks [@vicajilau].
- Added `SSH_MSG_EXT_INFO` support (RFC 8308). The client advertises `ext-info-c` and exposes the signature algorithms the server accepts as `SSHClient.serverSigAlgs` [#207]. Thanks [@vicajilau].
- **Changed the default algorithm preferences.** AES-GCM is now the preferred cipher instead of being opt-in, encrypt-then-MAC is preferred over encrypt-and-MAC, and `ssh-rsa` (SHA-1) is now last among the host key algorithms. CBC ciphers and `hmac-sha1` remain available but are only reached when a server offers nothing better [#207]. Thanks [@vicajilau].
- **Removed three broken algorithms from the defaults**: `diffie-hellman-group1-sha1` (1024-bit group), `hmac-md5`, and the truncated `hmac-sha2-[256|512]-96` variants. They are still implemented and can be re-enabled by passing them to `SSHAlgorithms` explicitly [#207]. Thanks [@vicajilau].
- Fixed `SSH_Message_Userauth_Request.decode()` swapping the old and new password when decoding a password change request, contrary to RFC 4252 §8 [#207]. Thanks [@vicajilau].
- Fixed `SSH_Message_Userauth_Request.decode()` not reading the boolean that precedes the algorithm name in a `publickey` request (RFC 4252 §7), which misparsed every signed request and could not represent an unsigned probe [#207]. Thanks [@vicajilau].
- Added a `SECURITY.md` with a private vulnerability reporting process [#207]. Thanks [@vicajilau].
- Documented `onVerifyHostKey` in the README. Host key signatures were and are always verified, but deciding whether the key is the expected one is the caller's job, and omitting the handler accepts any host key [#207]. Thanks [@vicajilau].

## [3.0.2] - 2026-08-17
- Fixed silent data loss in SFTP reads when a server returned fewer bytes than requested, which the protocol allows: the missing suffix is now retried instead of skipped, so `SftpFile.read()` and `SftpClient.download()` no longer return truncated, misaligned data [#200] [#203]. Thanks [@GT-610].
- Fixed NIST ECDH private scalar generation, which sampled only 65 bytes for P-521 and could therefore never set the 521st bit, and replaced the modulo reduction with rejection sampling for a uniform scalar in `1 <= x < n` [#201]. Thanks [@GT-610].
- Changed `SftpFile.read()` to process pipelined read replies as they arrive while still emitting chunks ordered by file offset [#200]. Thanks [@GT-610].
- Changed `SftpFile.read()` to throw `SftpError` when a server returns more bytes than requested, instead of silently truncating the surplus [#200]. Thanks [@GT-610].
- Registered SFTP reply waiters before sending each request, so a reply can no longer be discarded by a channel that delivers it synchronously [#199]. Thanks [@GT-610].
- Limited SFTP read resizing to short replies of at least 512 bytes, so a single tiny reply no longer pins every later request to that floor for the rest of a transfer [#203].

## [3.0.1] - 2026-08-16
- Fixed X11 forwarding by encoding and decoding the `x11-req` screen number as a `uint32` instead of a string, as required by RFC 4254 §6.3 [#194]. Thanks [@GT-610].
- Fixed `SSHChannel.remoteChannelId` returning the local channel id instead of the id assigned by the peer [#196]. Thanks [@GT-610].
- Fixed `SSHClient.run()` and `SSHClient.runWithResult()` hanging forever when the stdout stream emitted an error, by routing stdout errors to the stdout completer [#195]. Thanks [@GT-610].
- Fixed `SSHClient.run()` and `SSHClient.runWithResult()` raising an uncaught error, instead of throwing to the caller, when the stderr stream emitted an error while stdout was still open. Both streams are now awaited together, and the session is closed on failure so the SSH channel is no longer leaked [#197].
- Switched SSH protocol randomness to a `Random.secure()` source and widened byte generation to the full `0x00`-`0xff` range, covering key exchange cookies, ephemeral key exchange private values, and OpenSSH private key encryption seeds [#193]. Thanks [@GT-610].
- Switched the check int of OpenSSH private keys written by `SSHKeyPair.toPem()` to the same secure random source, removing the last insecure `Random()` usage in the library [#198].

## [3.0.0] - 2026-08-16
- **BREAKING**: Changed `SSHClient.identities` getter type from `List<SSHKeyPair>?` to `List<SSHIdentity>?` to support asynchronous external signers (OS agents, hardware tokens, smart cards, Secure Enclave, Android Keystore, and custom signers) [#190]. Constructor invocations passing `List<SSHKeyPair>` remain 100% source-compatible.
- **BREAKING**: Changed `SSHClient.close()` return type from `void` to `Future<void>` to allow awaiting complete socket and channel teardown.
- Added `SSHIdentity` abstraction, `SSHRawHostKey`, and `SSHRawSignature` with optional `comment` and `shouldProbe` properties [#190].
- Added support for Public-Key Probing (RFC 4252 §7.8) with `SSH_Message_Userauth_PK_Ok` and `SSHIdentity.shouldProbe` to check server key acceptance before requesting hardware token / user interaction.
- Exported `src/ssh_identity.dart` and `src/ssh_hostkey.dart` in `lib/dartssh2.dart`.

## [2.22.5] - 2026-07-30
- Exported `src/ssh_userauth.dart` in `lib/dartssh2.dart` to expose `SSHUserInfoRequest`, `SSHUserInfoPrompt`, `SSHAuthMethod`, and `SSHChangePasswordResponse` [#188]. Thanks [@vicajilau].

## [2.22.4] - 2026-07-27
- Advertised standard RFC 8731 key exchange name `curve25519-sha256` alongside legacy `curve25519-sha256@libssh.org` [#187]. Thanks [@nickn17].

## [2.22.3] - 2026-07-20
- Fixed an SSH channel leak in `SftpClient.close()` by closing the underlying SSH channel and returning `Future<void>` to allow awaiting channel teardown [#186]. Thanks [@keinstn].

## [2.22.2] - 2026-07-15
- Added `flush()` to `SSHSocket`, `SSHClient`, and `SSHChannel` to allow force flushing of buffered outgoing data [#183]. Thanks [@vicajilau].

## [2.22.1] - 2026-07-13
- Fixed a keepalive issue where overlapping pings could occur and caught errors during ping execution. Thanks [@vicajilau].

## [2.22.0] - 2026-07-03
- Added optional `handshakeTimeout` and `authTimeout` to `SSHClient` to limit connection negotiation and user authentication times [#182]. Thanks [@GT-610].

## [2.21.1] - 2026-07-02
- Fixed an `SSHTransport` busy-loop (100% CPU / ANR) that occurred when a partial packet remained in the read buffer [#179]. Thanks [@vicajilau].

## [2.21.0] - 2026-07-01
- Added `SSHSession.waitForExit({Duration? timeout})` to await remote process exit status with an optional timeout [#176]. Thanks [@GT-610].
- Hardened SOCKS5 dynamic forwarding (half-close streaming, dialing guards, timeout cancellation, malformed UTF-8 decoding, and buffer limits) [#175]. Thanks [@GT-610].
- Hardened SSH agent channel frame validation (rejecting empty or oversized frames) and fallback RSA signature type checks [#175]. Thanks [@GT-610].
- Improved EC private key parsing with proper ASN.1 OID curve detection, public point derivation validation, and robust comments decoding [#175]. Thanks [@GT-610].

## [2.20.0] - 2026-06-30
- **BREAKING**: Bumped the minimum Dart SDK constraint to `3.0.0` [#23]. Thanks [@vicajilau].
- **BREAKING**: Declared `OpenSSHKeyPair` as a `mixin class` to comply with Dart 3.0 class modifier rules [#23]. Thanks [@vicajilau].
- Offloaded all cryptographic key exchange (KEX) calculations to background isolates using `Isolate.run` on platforms that support it, preventing the Flutter main thread from blocking/freezing during connection [#23]. Thanks [@vicajilau].
- Refactored internal key exchange isolate communication payloads (X25519, NIST Curves, DH) to use Dart 3.0 type-safe Records [#23]. Thanks [@vicajilau].

## [2.19.0] - 2026-06-30
- Added tolerant HTTP-date parsing to accept all RFC 7231 §7.1.1.1 HTTP-date formats (`IMF-fixdate`, `RFC 850`, `asctime`) for HTTP response headers [#170]. Thanks [@GT-610].
- Added chunked transfer-encoding decoding for HTTP response bodies according to RFC 7230 §4.1, improving interoperability with HTTP/1.1 servers [#171]. Thanks [@GT-610].
- Added support for OpenSSH's `posix-rename@openssh.com` SFTP extension to perform atomic renames with POSIX semantics (replace destination if it exists) when advertised by the server [#172]. Thanks [@GT-610].
- Added `SftpFile.downloadToRandomAccess` to download a remote file directly into a `dart:io` `RandomAccessFile` using out-of-order pipelined writes, maximizing download performance on high-latency links [#173]. Thanks [@GT-610].
- Fixed a connection drop bug during AEAD (AES-GCM) decryption caused by incorrect padding length validation offset calculation [#168]. Thanks [@nuclear06].

## [2.18.0] - 2026-05-18
- Fixed AES-GCM cipher encryption and decryption sequence number/nonce counter resetting during key exchanges [#165]. Thanks [@vicajilau].
- **BREAKING**: `SSHHostkeyVerifyHandler` now receives an OpenSSH-style `SHA256:<base64>` host key fingerprint instead of the previous raw MD5 digest, so host key pinning code must be updated accordingly [#162]. Thanks [@thyssentishman].

## [2.17.1] - 2026-04-12
- Made `SSHPem.decode` accept CRLF (`\r\n`) line endings in addition to LF when parsing PEM content [#157]. Thanks [@gkc].

## [2.17.0] - 2026-03-28
- Improved Web/WASM compatibility by updating `SSHSocket` conditional imports so web runtimes consistently use the web socket shim and avoid incorrect native socket selection [#88]. Thanks [@vicajilau].
- Added local dynamic forwarding (`SSHClient.forwardDynamic`) with SOCKS5 `NO AUTH` + `CONNECT`, including configurable handshake/connect timeouts and connection limits.
- Added AES-GCM (`aes128-gcm@openssh.com`, `aes256-gcm@openssh.com`) AEAD groundwork in transport and cipher negotiation; currently opt-in (not enabled by default yet). `chacha20-poly1305@openssh.com` remains pending [#26]. Thanks [@vicajilau].

## [2.16.0] - 2026-03-24
- **BREAKING**: Changed `SSHChannelController.sendEnv()` from `void` to `Future<bool>` to properly await environment variable setup responses and avoid race conditions with PTY requests [#102]. Thanks [@itzhoujun] and [@vicajilau].
- Clarified shell stdio wiring for CLI-only usage and guarded `example/shell.dart` against missing local terminal handles (for example GUI-launched Windows `.exe`) [#121]. Thanks [@bradmartin333] and [@vicajilau].
- Added support for parsing legacy unencrypted `EC PRIVATE KEY` PEM format in `SSHKeyPair.fromPem` [#109]. Thanks [@jooy2] and [@vicajilau].
- Added `SSHClient.runWithResult()` to expose command output together with `exitCode` and `exitSignal` while keeping `run()` as a convenience API [#99]. Thanks [@falrom] and [@vicajilau].
- Added non-breaking high-level SFTP `download()` / `downloadTo()` APIs and read pipeline tuning knobs (`chunkSize`, `maxPendingRequests`) for improved large-file throughput while preserving stream compatibility [#124]. Thanks [@vicajilau].
- Made SFTP directory/file name parsing tolerant to malformed UTF-8 bytes to avoid `FormatException` on non-UTF-8 server filenames [#95]. Thanks [@vicajilau].

## [2.15.0] - 2026-03-20
- Updated `pointycastle` dependency to `^4.0.0` [#131]. Thanks [@vicajilau].
- Added foundational X11 forwarding support with session x11-req API, incoming x11 channel handling, and protocol tests [#1]. Thanks [@vicajilau].
- Exposed SSH ident configuration from `SSHClient` [#135]. Thanks [@Remulic] and [@vicajilau].
- Propagated the underlying exception in `SSHAuthAbortError` through `reason` for better diagnostics [#133]. Thanks [@james-thorpe] and [@vicajilau].
- Accepted `SSH-1.99-*` server banners as SSH-2 compatible during version exchange and added regression tests [#132]. Thanks [@james-thorpe] and [@vicajilau].
- Added SSH agent forwarding support (`auth-agent-req@openssh.com`) with in-memory agent handling and RSA sign-request flag support [#139]. Thanks [@Wackymax] and [@vicajilau].
- Normalized HTTP response line parsing in `SSHHttpClientResponse` to handle CRLF endings consistently and avoid trailing line-ending artifacts in parsed status/header fields [#145]. Thanks [@vicajilau].
- Fixed SFTP packet encoding/decoding consistency: `SftpInitPacket.decode` now parses extension pairs correctly and `SftpExtendedReplyPacket.encode` now preserves raw payload bytes [#145]. Thanks [@vicajilau].

## [2.14.0] - 2026-03-19
- Fixed SSH connections through bastion hosts where the target server sends its version string immediately upon connection (which is standard behavior per RFC 4253) [#141]. Thanks [@shihuili1218].
- Adds a new forwardLocalUnix() function, which is an equivalent of ssh -L localPort:remoteSocketPath [#140]. Thanks [@isegal].

## [2.13.0] - 2025-06-22
- docs: Update NoPorts naming [#115]. [@XavierChanth].
- Add parameter disableHostkeyVerification [#123]. Thanks [@alexander-irion].
- Add support for server initiated re-keying [#125]. Thanks [@MarBazuz].
- Add support for new algorithms "mac-sha2-256-96", "hmac-sha2-512-96", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com" [#126] [#127]. Thanks [@reinbeumer].

## [2.12.0] - 2025-02-08
- Fixed streams and channel not closing after receiving SSH_Message_Channel_Close [#116]. [@cbenhagen].
- Fixed lint issues.
- Added tests.
- Updated dependencies.

## [2.11.0] - 2024-11-19
- Fixed Type 'Uint8' not found issue.

## [2.10.0] - 2024-08-29
- Improved Readme.
- Bug fix in SftpFileWriter for [#50], [#71], [#100].
- Added DartShell product [#101].
- Fixed dynamic return on SftpFileOpenMode in | operator [#80].
- DCM updated.
- Fixed warnings related with new DCM version.
- Dependencies updated.
- Fixed Flutter 3.24 issue.

## [2.9.1-pre] - 2023-04-02
- Make the type of `SSHForwardChannel.sink` to `StreamSink<List<int>>` to match
  its super class.
- Added `SSHHttpClient` for easy http request forwarding.

## [2.9.0-pre] - 2023-03-31
- Better handling of channel close.
- Make `SSHForwardChannel` implement `SSHSocket` for better interoperability.

## [2.8.2] - 2023-03-07
- Make `SftpFileWriter` implement `Future<void>` for backward compatibility.

## [2.8.1] - 2023-03-07
- Export `SftpFileWriter`

## [2.8.0] - 2023-03-06
- `SftpFile.write` now returns a `SftpFileWriter` that can be used to control
  the writing process.
- Support `SftpClient.statvfs` and `SftpFile.statvfs`.
- Support automatic keepalive.

## 2.7.3
- Update README.md
- Move cli into separate package.
- Properly handle chunk read error during stream read.

## 2.7.2+3
- Update README.md

## 2.7.2+2
- Update README.md

## 2.7.2+1
- Update README.md

## 2.7.2
- Upgrade `pinenacl` to `0.5.0`.
- Fix bug in exporting openssh private key to pem, thanks [@PIDAMI]

## 2.7.1
- Upgrade rsa authentication algorithm to rsa-sha2-256.

## 2.7.0
- Support encrypted RSA format private key

## 2.6.1
- Allow username with `@` in `dartssh2` command [#24]

## 2.6.0
- Allow ignoring stdout or stderr in `SSHClient.run`.
- Add `SSHAuthFailError` and `SSHAuthAbortError`.
- Fix file type detection.
- Fix empty identity handling [#21]
- Add connection reset handing.
- Add more tests

## 2.5.0
- Fix js import path [#18].
- Ignore remote data after channel closed.

## 2.4.4
- Fix lint errors

## 2.4.3
- Remove unused dependencies
- Fix lint errors

## 2.4.2
- Fix null check error in `kill()` [#17]
- More examples in README.md
## 2.4.1
- More examples in README.md
- Limit the maximum size of channel packets

## 2.4.0
- Support session stdin streaming and EOF

## 2.3.1
- Support ssh v2 when version string does not contain CR [#14], thanks [@Migarl]

## 2.3.1-pre
- Add remoteVersion field to SSHClient

## 2.3.0-pre
- Add description field in SSHChannelOpenError

## 2.2.0
- Update README.md
- Support export keypair to PEM

## 2.1.0-pre
- Update README.md
- Support loading OpenSSH encrypted pem files.

## 2.0.0-pre
- Implements local port forwarding
- Implements remote port forwarding
- Implements SFTP client
- More supported algorithms
- Added `dartsftp` command

## 1.2.0-pre

- Rework login logic.
- `dartssh` command now supports login with public key.

## 1.1.4-pre

- `dartssh` command now supports terminal window resize.

## 1.1.3-pre

- Add `--verbose` option in `dartssh` command.

## 1.1.2-pre

- Fix typos.

## 1.1.1-pre

- Organize exports.
## 1.1.0-pre

- Dependency update.
- Sound null safety.
- Replace deprecated `pedantic` with `package:lints`
- Fix crash running vim by [@linhanyu].  [#1]

## 1.0.4+4

- Increase test coverage and documentation.

## 1.0.3+3

- Fix tunneled WebSocket issue.

## 1.0.2+2

- Add example/README.md

## 1.0.1+1

- Add SSHTunneledSocketImpl, SSHTunneledWebSocketImpl, and SSHTunneledBaseClient.

## 1.0.0+0

- Initial release.

[#1]: https://github.com/TerminalStudio/dartssh/pull/1/files
[#14]: https://github.com/vicajilau/dartssh2/pull/14
[#17]: https://github.com/vicajilau/dartssh2/issues/17
[#18]: https://github.com/vicajilau/dartssh2/issues/18
[#21]: https://github.com/vicajilau/dartssh2/issues/21
[#23]: https://github.com/vicajilau/dartssh2/issues/23
[#24]: https://github.com/vicajilau/dartssh2/issues/24
[#26]: https://github.com/vicajilau/dartssh2/issues/26
[#50]: https://github.com/vicajilau/dartssh2/issues/50
[#71]: https://github.com/vicajilau/dartssh2/issues/71
[#80]: https://github.com/vicajilau/dartssh2/issues/80
[#88]: https://github.com/vicajilau/dartssh2/issues/88
[#95]: https://github.com/vicajilau/dartssh2/issues/95
[#99]: https://github.com/vicajilau/dartssh2/issues/99
[#100]: https://github.com/vicajilau/dartssh2/issues/100
[#101]: https://github.com/vicajilau/dartssh2/pull/101
[#102]: https://github.com/vicajilau/dartssh2/issues/102
[#109]: https://github.com/vicajilau/dartssh2/issues/109
[#115]: https://github.com/vicajilau/dartssh2/pull/115
[#116]: https://github.com/vicajilau/dartssh2/issues/116
[#121]: https://github.com/vicajilau/dartssh2/issues/121
[#123]: https://github.com/vicajilau/dartssh2/pull/123
[#124]: https://github.com/vicajilau/dartssh2/issues/124
[#125]: https://github.com/vicajilau/dartssh2/pull/125
[#126]: https://github.com/vicajilau/dartssh2/pull/126
[#127]: https://github.com/vicajilau/dartssh2/pull/127
[#131]: https://github.com/vicajilau/dartssh2/pull/131
[#132]: https://github.com/vicajilau/dartssh2/pull/132
[#133]: https://github.com/vicajilau/dartssh2/pull/133
[#135]: https://github.com/vicajilau/dartssh2/pull/135
[#139]: https://github.com/vicajilau/dartssh2/pull/139
[#140]: https://github.com/vicajilau/dartssh2/pull/140
[#141]: https://github.com/vicajilau/dartssh2/pull/141
[#145]: https://github.com/vicajilau/dartssh2/pull/145
[#153]: https://github.com/vicajilau/dartssh2/pull/153
[#157]: https://github.com/vicajilau/dartssh2/pull/157
[#162]: https://github.com/vicajilau/dartssh2/pull/162
[#165]: https://github.com/vicajilau/dartssh2/issues/165
[#168]: https://github.com/vicajilau/dartssh2/issues/168
[#170]: https://github.com/vicajilau/dartssh2/pull/170
[#171]: https://github.com/vicajilau/dartssh2/pull/171
[#172]: https://github.com/vicajilau/dartssh2/pull/172
[#173]: https://github.com/vicajilau/dartssh2/pull/173
[#175]: https://github.com/vicajilau/dartssh2/pull/175
[#176]: https://github.com/vicajilau/dartssh2/pull/176
[#179]: https://github.com/vicajilau/dartssh2/pull/179
[#182]: https://github.com/vicajilau/dartssh2/pull/182
[#183]: https://github.com/vicajilau/dartssh2/issues/183
[#186]: https://github.com/vicajilau/dartssh2/pull/186
[#187]: https://github.com/vicajilau/dartssh2/pull/187
[#188]: https://github.com/vicajilau/dartssh2/issues/188
[#190]: https://github.com/vicajilau/dartssh2/issues/190
[#193]: https://github.com/vicajilau/dartssh2/pull/193
[#194]: https://github.com/vicajilau/dartssh2/pull/194
[#195]: https://github.com/vicajilau/dartssh2/pull/195
[#196]: https://github.com/vicajilau/dartssh2/pull/196
[#197]: https://github.com/vicajilau/dartssh2/pull/197
[#198]: https://github.com/vicajilau/dartssh2/pull/198
[#199]: https://github.com/vicajilau/dartssh2/pull/199
[#200]: https://github.com/vicajilau/dartssh2/pull/200
[#201]: https://github.com/vicajilau/dartssh2/pull/201
[#203]: https://github.com/vicajilau/dartssh2/pull/203
[#207]: https://github.com/vicajilau/dartssh2/pull/207
[#210]: https://github.com/vicajilau/dartssh2/pull/210
[#212]: https://github.com/vicajilau/dartssh2/pull/212
[#213]: https://github.com/vicajilau/dartssh2/pull/213
[#215]: https://github.com/vicajilau/dartssh2/pull/215
[#216]: https://github.com/vicajilau/dartssh2/pull/216
[#217]: https://github.com/vicajilau/dartssh2/pull/217
[#218]: https://github.com/vicajilau/dartssh2/pull/218
[#220]: https://github.com/vicajilau/dartssh2/pull/220
[#221]: https://github.com/vicajilau/dartssh2/pull/221
[#222]: https://github.com/vicajilau/dartssh2/pull/222
[#223]: https://github.com/vicajilau/dartssh2/pull/223
[#224]: https://github.com/vicajilau/dartssh2/pull/224
[#225]: https://github.com/vicajilau/dartssh2/pull/225
[#226]: https://github.com/vicajilau/dartssh2/issues/226
[#229]: https://github.com/vicajilau/dartssh2/pull/229
[#230]: https://github.com/vicajilau/dartssh2/pull/230
[#231]: https://github.com/vicajilau/dartssh2/pull/231
[#232]: https://github.com/vicajilau/dartssh2/pull/232
[#233]: https://github.com/vicajilau/dartssh2/pull/233
[#234]: https://github.com/vicajilau/dartssh2/pull/234
[#235]: https://github.com/vicajilau/dartssh2/pull/235
[#236]: https://github.com/vicajilau/dartssh2/pull/236
[#237]: https://github.com/vicajilau/dartssh2/pull/237
[#239]: https://github.com/vicajilau/dartssh2/pull/239
[#243]: https://github.com/vicajilau/dartssh2/issues/243
[#248]: https://github.com/vicajilau/dartssh2/pull/248
[#244]: https://github.com/vicajilau/dartssh2/pull/244

[@linhanyu]: https://github.com/linhanyu
[@Migarl]: https://github.com/Migarl
[@PIDAMI]: https://github.com/PIDAMI
[@XavierChanth]: https://github.com/XavierChanth
[@MarBazuz]: https://github.com/MarBazuz
[@reinbeumer]: https://github.com/reinbeumer
[@alexander-irion]: https://github.com/alexander-irion
[@Remulic]: https://github.com/Remulic
[@james-thorpe]: https://github.com/james-thorpe
[@itzhoujun]: https://github.com/itzhoujun
[@jooy2]: https://github.com/jooy2
[@falrom]: https://github.com/falrom
[@bradmartin333]: https://github.com/bradmartin333
[@Wackymax]: https://github.com/Wackymax
[@gkc]: https://github.com/gkc
[@vicajilau]: https://github.com/vicajilau
[@GT-610]: https://github.com/GT-610
[@cesarcamps]: https://github.com/cesarcamps
[@klc]: https://github.com/klc
