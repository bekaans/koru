# ADR-0007: koru-notify — channels, injection defense, rate limit, persistent queue, heartbeat and personal data

- **Status:** Accepted. Default IP masking in notifications (§8) and the send-result API and client checks (§10) are part of the decision.
- **Date:** 2026-10-15
- **Related:** [security](../architecture.md#security),
  [performance and resilience](../architecture.md#performance-and-resilience), `dependency-rules.toml`;
  `deny.toml`; [threat model](../threat-model.md) (KT-03, KT-04, KT-07, KT-15, KT-26, KT-31, KT-38,
  KT-68–KT-75); ADR-0006 §7; ADR-0001, ADR-0004, ADR-0006

## Context

`koru-notify` is the only layer where Koru talks to the outside: it delivers findings to the operator's channels (ntfy,
Telegram, email) and sends a regular "I am alive" signal to Healthchecks.io. This layer is risky for
three reasons:

1. **It carries attacker content.** A notification can contain fields under the attacker's control
   like a path, a command line and a file name (KT-15). Header, command or formatting injection both
   misleads the receiver and abuses the channel.
2. **It carries secrets.** The bot token, ntfy token, SMTP password and ping address are in this
   layer's hands (KT-38, KT-68).
3. **It demands reliability.** The network can be cut, the channel can crash, the attacker can
   produce a flood of events. The architecture requires a local queue and retry when the notification
   channel is unreachable (KT-31).

As the dependency matrix requires, koru-notify depends only on koru-event; it does not know
koru-store, koru-detect or Pulsar. The composition that produces the notification is in the `koru`
CLI.

## Decisions

### 1. Channel design and dependencies

- **Three channels, a `koru_event::NotificationChannel` implementation.**
  - **ntfy:** `POST <address>`, plain-text body, headers `Title`, `Priority` (2/4/5), `Tags`,
    `Authorization: Bearer` if there is a token.
  - **Telegram:** `POST <api>/bot<token>/sendMessage`, JSON body `{chat_id, text,
    disable_web_page_preview}`. `parse_mode` is **never sent**: the text is plain text (decision 2).
  - **SMTP:** direct TLS (465) or STARTTLS (other ports); `AUTH PLAIN` (or `LOGIN`); the body goes
    with `base64` transfer encoding.
- **Its own small HTTP/1.1 and SMTP client (`src/http.rs`, `src/smtp.rs`), no separate library.**
  Evaluated: `ureq` 3 (its default `rustls` feature pulls in `webpki-roots`, a CDLA-Permissive-2.0
  licensed package; and a 24-package tree with `ureq-proto`, `http`, `httparse` and the like) and
  `lettre` (SMTP; many packages including the `idna`/ICU chain). The need is limited to three simple
  request shapes: a single `POST`/`GET`, only the status code is read from the response, and no
  redirect is followed. So the tree grows only with the TLS library and the system certificate store
  reader. The code's safety is ensured by tests and by its smallness (the HTTP client is ~300 lines,
  the SMTP client ~420 lines, no `unsafe`).
- **TLS is rustls only (0.23.46, `std` + `ring` + `tls12`).** OpenSSL and native-tls are banned in
  `deny.toml` and are not in the tree (`cargo tree -p koru-notify --target all -i openssl-sys`,
  `-i native-tls` and `-i webpki-roots` all return "did not match any packages"). Server certificate
  chain and host name verification are always on; there is **no** setting that turns verification
  off, no `dangerous_configuration` and no extra root certificate field.
- **Crypto provider: `ring` 0.17.14.** `aws-lc-rs` was not chosen: `aws-lc-sys` brings
  OpenSSL-licensed (`ISC AND (Apache-2.0 OR ISC) AND OpenSSL`) C code, and the maintainers do not accept that license
  in the dependency tree. `ring`'s license as read by cargo-deny is `Apache-2.0 AND ISC`.
  No additional C library is needed; there is only its own code compiled with `cc` (`cc` is already
  installed on the CI runners and in the lab VM; compilation is tried on macOS, x86_64 and arm64
  Linux in CI).
- **Root certificates from the system store** (`rustls-native-certs` 0.8.5; license
  `Apache-2.0 OR ISC OR MIT`). `webpki-roots` is CDLA-Permissive-2.0 licensed; this license was not added to the list and the package is not in the tree. If the store is empty
  or unreadable, sending fails with a transient error (it goes into the queue); the failure is not
  cached, and when the store is fixed it recovers on its own.
- **License change:** only `ISC` was added to the general allow list in
  `deny.toml` (a separate commit `12bdc0d`).
  ISC is an OSI-approved permissive license equivalent to MIT/BSD-2; it is unavoidable in the rustls
  chain (`ring`, `rustls-webpki`, `untrusted`). No other exception was added.
- **New direct dependencies** (`dependency-rules.toml`, additions only; each with a rationale):
  `rustls`, `rustls-native-certs`, `serde`, `serde_json`, `thiserror`, `rustix`, `getrandom`;
  `tempfile` in development. New transitive packages: `ring`, `rustls-webpki`, `rustls-pki-types`,
  `untrusted`, `subtle`; by platform `security-framework` and `core-foundation` (macOS),
  `openssl-probe` (Linux; it only finds the certificate directory, it is not OpenSSL).
- **Addresses are `https` only.** `HttpsAddress::parse_parts` rejects: `http` (unless the host is
  exactly `127.0.0.1`; this is only for the fake servers in tests), user info (`@`), fragment (`#`),
  space, control and non-ASCII characters, an IPv6 literal, port 0. The error message does not
  contain the address. For SMTP, plain connection is also only `127.0.0.1`, and it is re-checked in
  the channel's `send` operation (since the field is public, the check in the constructor is not
  trusted).
- **Time budget.** Connect, handshake, write and read are bound to a single time budget (default
  10 s; SMTP 15 s); name resolution is awaited in a separate thread with a timeout. A slow server
  (slow-loris) cannot hold Koru. Redirects are not followed (the token does not leak to another
  address).
- **Error classification.** `2xx` success; `408`, `425`, `429`, `5xx`, connection error, timeout and
  TLS error are **transient** (they go into the queue); other `4xx` and `3xx` are **permanent**
  (dropped and counted). In SMTP `4xx` is transient and `5xx` permanent. STARTTLS not being offered
  counts as transient: a man in the middle must not be able to destroy the notification permanently
  by stripping STARTTLS (KT-70).

### 2. Injection defense

All notification texts pass through `src/text.rs` before going to the channel. The rule is the same
as `Untrusted::safe_display` (C0, DEL and C1 control characters, Unicode direction formatting
characters and the backslash are written as `\u{..}` / `\\`); additionally U+2028 and U+2029 are
neutralized. Boundaries are never cut in the middle of a character or in the middle of an escape
sequence; on overflow `…` is put, and the output stops when it reaches the boundary without scanning
the whole input (a 2 million character input in linear time).

| Attack | Defense | Test |
|---|---|---|
| CR/LF in the ntfy `Title`/`Tags` header | The header is sanitized; if the sanitizing changed the content it is RFC 2047 "B" encoded, and only base64 is visible in the raw header. The header configuration is re-checked before the request is built (CR, LF, control and non-ASCII → the request is not sent at all). `Tags` is built only from constant values. | `ntfy.rs`, `injection.rs` |
| CRLF in the SMTP `Subject` and other headers | The same rule; `From`/`To` are strictly validated in `local@domain` form at configuration and at send time (no quotes, `<>`, spaces, `,`, line ending); `MAIL FROM`/`RCPT TO` take only a validated address. Since the body goes `base64`-encoded, an SMTP command or a `.` line cannot be injected with the body; dot stuffing is also applied. | `smtp.rs`, `injection.rs` |
| Telegram `parse_mode` formatting injection | `parse_mode` is never sent; the text is plain text (`<b>`, `*`, `_`, `[x](y)` are not interpreted). The JSON is built with `serde_json`: escape attempts like `",\"parse_mode\":...` stay inside the value. The token and chat id go through strict format checking (they enter the URL path). | `telegram.rs`, `injection.rs` |
| Terminal and direction characters | The sanitizing above (all three channels). | `text.rs`, `injection.rs` |
| Excessive length | Header 120–200 bytes, body 4000 bytes (ntfy and Telegram) or 20 000 bytes (SMTP); in the queue header 200, body 4000 bytes. | `text.rs`, `ntfy.rs`, `telegram.rs`, `smtp.rs`, `queue.rs` |

The header limit is per channel: the ntfy header goes into an HTTP header and grows by 4/3 when
encoded, so it is 120 bytes; the others are 200 bytes.

### 3. Rate limit and summarization

- **A token bucket per channel** (`TokenBucket`): capacity, refill time per token and summary window
  are configurable (default: capacity 5, 12 s per token, window 60 s). Time is given from outside
  (unix ms); the tests do not depend on the real clock. Credit is kept in milliseconds, partial
  refills are not lost; if the clock goes backwards, no token is added or subtracted.
- **Summarization** (`Summarizer`): notifications arriving while the bucket is empty are not sent,
  **only counted**; their contents are not stored. When the summary window fills (from the first
  suppression) a single notification goes out: "`In the last 60 s, N more findings (not sent one by
  one due to the rate limit).`" Its severity is the highest of the suppressed ones and the event id
  is the last one's; it carries no attacker data. If the summary cannot be sent it goes into the
  queue.
- Suppressed notifications stay in the store (koru-store is the evidence; not the notification).
  Limit: the counter is kept in memory; if the process dies before the summary, the summary is lost.
- **Known weakness (KT-73):** the bucket is independent of severity. If the attacker drains the
  bucket with low-severity events, a real critical finding can be delayed by up to the summary window
  (at most 60 s). A bucket per severity can be added in the CLI composition; it is
  out of scope for this layer.

### 4. Persistent queue

- **Place and format.** `<dir>/<channel>.queue`; a single JSON document (`version`, counters,
  records; `deny_unknown_fields`). A separate file per channel; channels do not see each other's
  queue.
- **Safe file** (`src/safe_file.rs`, ADR-0004 and ADR-0006 principles, no `unsafe`): the path is
  absolute, no `.`/`..`; the directory chain is opened component by component with
  `openat(O_DIRECTORY | O_NOFOLLOW)`; only the last directory is created 0700 if it is missing; the
  directory must belong to the user running Koru and be 0700. After the file is opened with
  `O_NOFOLLOW | O_NONBLOCK` it is checked through the open handle: regular file, same user, 0600,
  single link (hard link leak, KT-47); it does not wait on a FIFO.
- **Atomic writing.** Every change is written to a 0600 temporary file (`.<name>.tmp`,
  `O_EXCL | O_NOFOLLOW`), `fsync`ed, put in place with `rename`, and the directory is `fsync`ed. A
  leftover old temporary file (or a symbolic link left in its place) is first `unlink`ed, never
  followed. `kill -9` never leaves the queue half-written; when the process restarts, the records
  are loaded from disk.
- **A corrupt or oversized file** (over 16 MiB, invalid JSON, unknown field, unsupported version,
  duplicate or out-of-order record number) is set aside as `<name>.queue.corrupt` (0600), counted
  (`corrupt`) and the queue starts empty; it can be inspected, but the notification flow does not
  stop. On mode, owner, symbolic link and hard link errors the file is **not set aside**; the open
  errors out (we do not move someone else's file).
- **Overflow.** When the capacity (default 1000) is full, the oldest record drops and
  `dropped_overflow` grows (permanent). Header and body are bounded at queue time; the file cannot
  grow without limit.
- **If the queue file is hand-edited (KT-69):** the records are sanitized again when they are sent
  (header and body pass the channel's rule); a record with an invalid severity or event id is
  dropped and counted as `permanent_errors`. There is no integrity signature: since the key would
  sit on the same machine, it gives no protection against root (residual risk, threat model §6).

### 5. Retry

- **Exponential backoff + jitter:** `d = min(max, base · 2^attempt)`; the delay is in `[d/2, d]`
  ("equal jitter"; `getrandom`). Default base 5 s, cap 10 min, at most 48 attempts (about 7 hours).
  Many Koru instances or records coming back from an outage at once are not loaded concurrently.
  There is no overflow (`saturating`).
- **Dispatcher flow:** if the rate limit allows, it is sent to the channel; on a transient error it
  goes into the queue (first delay base); on a permanent error it is dropped and counted.
  `process(now_ms)` is called regularly: it sends a summary whose window has filled and tries the
  records whose time has come **oldest first**. **While the network is down it stops at the first
  failure**; the whole queue is not loaded on every call. A record that exceeds the attempt limit is
  dropped and `dropped_retries` grows. Sends from the queue are also subject to the rate limit (after
  an outage it does not flood the channel).
- **Delivery guarantee: at least once.** If the process dies after a record is delivered but before
  it is deleted, the notification goes out twice; losing it is not preferred.
- If the queue cannot be written (disk full, permission), the notification is lost and
  `queue_errors` is counted (KT-74).

### 6. Heartbeat

- **`HealthchecksHeartbeat`:** `GET <ping address>` (`ping`), `/start` (`begin`) and `/fail`
  (`failed`); the query string is preserved. `HeartbeatLoop` runs in a separate thread and pings
  immediately first, then at every interval; a network error does not kill the loop (it is counted
  and the loop continues when the network returns). Stopping does not keep a sleeping loop waiting
  (it is woken through a channel); a loop that drops without `stop` being called also stops the
  thread, that is, the ping stops.
- **If Koru stops, Healthchecks goes "down".** When the ping stops, Healthchecks makes the check
  "down" after the period and grace and sends an alarm. This is the only way for `kill -9`, power
  loss and a crash (the period and grace are configured in the agent).
- **On SIGTERM `/fail` is sent (a decision).** Stopping Koru is a threat event. On a
  clean shutdown, only cutting the ping delays the alarm by the period + grace (e.g. minutes); an
  attacker doing `systemctl stop` is free during that time. `/fail` makes Healthchecks "down" at
  once. The cost: planned maintenance (`systemctl restart`, version upgrade) produces a false alarm.
  Therefore `stop(send_fail: bool)` supports both: the CLI passes `true` on SIGTERM; a separate
  "maintenance" flag for planned maintenance is added in the agent (the flag only through a convenience
  the operator defines, and recorded in Healthchecks; from a self-protection point of view the maintenance
  window is also an event). On SIGKILL `/fail` cannot be sent; the ping cut is enough. Signal
  handling (catching SIGTERM) is the agent's job (ADR-0003 §7); this layer only provides the mechanism (KT-72).
- **The ping address is a secret:** the `Debug` output, the error message and the log do not contain
  the address, the host or the port; the address is read only from the environment/`.env`.

### 7. Secrets

- **Source:** only environment variables or `.env` (`KORU_NTFY_*`, `KORU_TELEGRAM_*`,
  `KORU_SMTP_*`, `KORU_HEARTBEAT_URL`). `ChannelSet::from_env` ignores empty values; if only some of
  a channel's variables are present it errors. **The error message contains only the variable
  names** ("missing variables: …", "invalid variables: …"), never the values.
- **Reading `.env`** (`read_dotenv`): no symbolic link is followed, regular file, owned by the user
  running Koru, **0600** (a wider mode is rejected), at most 64 KiB; there is no line-end comment
  interpretation (a secret value is not truncated because of a `#`). No variable is written into the
  environment; the caller gets the map.
- **Wrappers:** `Secret` (token, password) and `HttpsAddress` write `***` to `Debug`; they do not
  implement `Display`. Since the Telegram token goes in the URL path, the raw address never enters
  any message. The tests verify that in network errors, HTTP errors and `Debug` outputs the token,
  password, address, host and port are not exposed (`*_hides_the_secret`).
- **Secret in the VM (KT-38):** `.env` is never copied into the VM. The live channel test runs on
  the Mac. Only for the `systemctl stop` → "down" test is `KORU_HEARTBEAT_URL` temporarily given to
  the VM: root-owned, 0600, outside `/koru` (`/etc/koru/heartbeat.env`); it is deleted as soon as the test
  ends and the deletion is proven; no secret must remain in the VM (KT-75).

### 8. Personal data

- **Third parties.** The notification text passes through Telegram (servers abroad), the email
  provider and (if used publicly) ntfy.sh; these providers see the attacker IP and user names. Purpose limitation
  and cross-border transfer rules for personal data also apply to the notification channels; the
  operator is responsible for choosing channels that fit their legal setting.
- **Decision (KT-71): IP is masked by default in notifications** (IPv4 /24, IPv6
  /48); it can be turned off in the configuration; **the full IP stays only in the local store**.
  `Dispatcher` masks every notification once before it goes to the channel and before it is written
  to the queue (`mask_notification`: title and body; severity and event id stay the same). Result:
  the queue file (on disk) also holds no full IP. To turn it off: `Dispatcher::set_masking(false)`
  or the environment variable `KORU_NOTIFY_MASK_IP=false` (`ChannelSet::mask_ip`; empty or
  `true`/`1`/`yes` on, `false`/`0`/`no` off, any other value is rejected with the variable name
  written). When it is off, the full IP goes to the channel and (on a transient error) to the local
  queue.
- **The masking code moved to koru-event (a structural note).** koru-notify does not know koru-store
  (dependency matrix); the masking function was in koru-store. The function (`mask_ip_in_text`,
  `mask_ip`) was moved to `koru-event/src/mask.rs` without any behavior change; koru-store
  re-exports `mask_ip_in_text` under the same name and `mask_event` stays there. The matrix did not
  change (both crates already depend on koru-event); all of koru-store's masking tests
  (`tests/masking*.rs`) pass unchanged, and the basic forms are additionally tested in koru-event
  (`crates/koru-event/tests/ip_mask.rs`). The known limits of masking (KT-67) also hold for
  notifications.
- **Notification content principle:** the body carries the event id (SMTP: `X-Koru-Event` and
  `Message-ID`; Telegram: the `Event:` line), it does not carry the attacker's raw fields (the
  `Notification` document; KT-15). Since the ntfy body is preserved verbatim it has no event id
  (fixed by test). The composition that produces the notification text from the `Event` is in the
  `koru` crate; not putting raw fields in is its responsibility, and masking is the second
  defense.

### 9. Test strategy

Strict TDD: the tests and the `todo!()` skeleton were committed while red (`47b7c33`). The tests run
only against fake HTTP and SMTP servers on 127.0.0.1; they never touch the real network. The fake
servers record the incoming bytes raw and parse them like a real server; if an injection had
succeeded, the fake server would see an extra header, command or second request. In `https` and
direct TLS connections the fake server records the first bytes and shows that the client sends a TLS
ClientHello (0x16 0x03) and no plaintext. The fake channel (`FakeChannel`) tests the dispatcher,
rate limit and retry logic independent of the network; since time is given from outside there is no
sleeping in the tests. For live evidence `crates/koru-notify/examples/live_ntfy.rs` sends a
"[Koru test]" notification to real ntfy and demonstrates the network outage in two processes by
turning the target into an unreachable local address (without touching network settings); the topic
address never enters any output.

### 10. Send result and client checks (code review note)

- **Send result.** `NtfyChannel::last_status`, `TelegramChannel::last_status` and
  `HealthchecksHeartbeat::last_status` give the last HTTP status code (`Option<u16>`; the failed
  response's code too, `None` if no response was received); `SmtpChannel::last_response` gives the
  last server response (`250 2.0.0 Ok: queued as ...`; on failure the error response). The status
  code is only a number. The SMTP response is stripped of control characters, cut at 200 bytes, and
  even if the user name, password and their base64 forms appear in the response they are replaced
  with `***` (tests `send_result.rs`). The purpose is live lab evidence (manual lab runs); the
  error messages still do not contain the server text.
- **SMTP response codes are fully checked.** 220 for the greeting and STARTTLS, 250 for EHLO and the
  mail steps (250 or 251 for RCPT), 235 for AUTH (334 in LOGIN), 354 for DATA. "Any 2xx" is not
  accepted: a test written during code review (`a_non_220_greeting_is_rejected_and_nothing_is_sent`)
  revealed that a 250 greeting was accepted, and it was fixed.
- **What was looked at in the review, and their tests:**

| Question | Answer | Test |
|---|---|---|
| Is STARTTLS mandatory in SMTP, does it fall back to plaintext in a downgrade attack? | Mandatory (`StartTls` is the default, direct TLS on 465). If the server does not offer STARTTLS, refuses it (454, 500, 554), gives a code other than 220, or sends extra data in the same packet as 220, the connection is cut; no credential, MAIL, RCPT or DATA goes in plaintext; the error counts as transient (let it wait in the queue). | `client_safety.rs`: `a_refused_starttls_never_falls_back_to_plaintext`, `a_missing_starttls_offer_cuts_the_connection`, `extra_buffered_data_after_starttls_is_rejected`; `smtp.rs` |
| Are certificate and host name verification always on? | Yes; there is no setting that turns them off. Against a real TLS server (self-signed certificate), HTTPS, Telegram, heartbeat, direct TLS SMTP and STARTTLS SMTP are rejected, and the server sees no application data. A source scan fixes that there are no constructs that turn verification off (`dangerous`, custom verifier etc.) and no second TLS setting. The host name is verified only in rustls-webpki; the root certificates are built in one place. | `tls_validation.rs`, `source_safety.rs` |
| Is there a limit in response parsing? | HTTP: status line 4096 bytes, only the status line is read (the body is not read). SMTP: line 2048 bytes, response 64 lines, a malformed code is rejected. All are bound to a single total time budget (a drip-feeding server cannot exceed the budget). | `client_safety.rs`: `an_overlong_*`, `a_slow_*`, `broken_*`, `malformed_*` |
| Are redirects (3xx) followed? | No. 301, 302, 303, 307 and 308 count as permanent errors in all three HTTP channels; no request goes to the target (no token leak). `Location` is not read in the source. | `client_safety.rs`: `no_redirect_code_is_followed_on_any_channel`; `source_safety.rs` |

- **Test dependency:** for a real TLS server the tests use `rcgen` (development only; ring provider,
  no aws-lc-rs) to generate a self-signed certificate at runtime; the private key is never written
  to disk and there is no key in the repository (gitleaks clean). Since the self-signed certificate
  is in no system store, these tests do not additionally test the "host name wrong but chain valid"
  case; that check belongs to rustls-webpki and cannot be turned off in the client.

## Conclusions

- **Positive:** the tree is small (TLS + certificate reader); the injection defense is in one place
  and tested; secret leakage is blocked at type level; a network outage or process death does not
  lose a notification (at least once).
- **Negative / limits:** our own HTTP and SMTP clients bring maintenance load (only the status code
  and a single request; the narrow scope limits this); the system certificate store is trusted (a
  root attacker can add a root to the store; KT-70); the queue file has no protection against root
  (KT-69); the rate limit is independent of severity (KT-73); SIGTERM catching and the maintenance
  mode are in the agent (KT-72).
- **Handed over to the agent:** the composition (turning the `Event` into a `Notification`, passing the
  `ChannelSet::mask_ip` value to `Dispatcher::set_masking`, the `process` loop, `/fail` on SIGTERM,
  the maintenance mode, the Healthchecks period and grace settings) and a bucket per severity.
- **Live evidence (requires `.env`):** the real-channel checks (live delivery, network outage and
  heartbeat) run only when the operator supplies the channel variables; the fake-server tests
  cover the same behavior without secrets.
