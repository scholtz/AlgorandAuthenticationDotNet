# Risk Registry — AlgorandAuthenticationDotNet

This is a **living document**. It is updated (never rewritten from scratch) every time an audit is performed per `AUDITS-INSTRUCTIONS.md`. IDs are never reused or renumbered. Closed risks are kept for history, not deleted.

Status values: `Open` · `Mitigated` · `Accepted` · `Closed`

---

## Summary table

| ID | Title | Severity | Status | First Identified | Last Verified | Report |
|---|---|---|---|---|---|---|
| RISK-001 | Fail-open authentication when algod rekey lookup fails and `AllowEmptyAccounts=true` (V2) | High | Open | 2026-07-19 | 2026-07-19 | [2026-07-19_claude-sonnet-5_arc14-audit.md](reports/2026-07-19_claude-sonnet-5_arc14-audit.md) |
| RISK-002 | `EmptySuccessOnFailure` issues an authenticated ticket with an empty identity on any auth failure | Medium | Accepted (opt-in, default off) | 2026-07-19 | 2026-07-19 | [2026-07-19_claude-sonnet-5_arc14-audit.md](reports/2026-07-19_claude-sonnet-5_arc14-audit.md) |
| RISK-003 | `Options.Debug=true` logs the raw `Authorization` header at Debug level | Low | Open | 2026-07-19 | 2026-07-19 | [2026-07-19_claude-sonnet-5_arc14-audit.md](reports/2026-07-19_claude-sonnet-5_arc14-audit.md) |
| RISK-004 | Unsynchronized shared `static` block-height cache (`t`, `block`) in both handlers | Low | Open | 2026-07-19 | 2026-07-19 | [2026-07-19_claude-sonnet-5_arc14-audit.md](reports/2026-07-19_claude-sonnet-5_arc14-audit.md) |
| RISK-005 | `CheckExpiration` defaults to `false`, allowing indefinite replay of a captured header unless the integrator opts in | Medium | Accepted (documented default, integrator-controlled) | 2026-07-19 | 2026-07-19 | [2026-07-19_claude-sonnet-5_arc14-audit.md](reports/2026-07-19_claude-sonnet-5_arc14-audit.md) |
| RISK-006 | Realm check via `Encoding.ASCII.GetString(tr.Tx.Note)` throws on null `Note`, falling into generic exception handling | Low | Open | 2026-07-19 | 2026-07-19 | [2026-07-19_claude-sonnet-5_arc14-audit.md](reports/2026-07-19_claude-sonnet-5_arc14-audit.md) |
| RISK-007 | V2 `Realms.Any() == false` and `Realm` empty silently disables realm/domain-separation checking | Medium | Open | 2026-07-19 | 2026-07-19 | [2026-07-19_claude-sonnet-5_arc14-audit.md](reports/2026-07-19_claude-sonnet-5_arc14-audit.md) |
| RISK-008 | No independent audit of `Algorand4` SDK / BouncyCastle Ed25519 implementation (trusted dependency) | Informational | Accepted (out of scope, tracked) | 2026-07-19 | 2026-07-19 | [2026-07-19_claude-sonnet-5_arc14-audit.md](reports/2026-07-19_claude-sonnet-5_arc14-audit.md) |
| RISK-009 | Test suite embeds real-format mnemonics for test-only accounts | Informational | Accepted (public, well-known test values; no real funds) | 2026-07-19 | 2026-07-19 | [2026-07-19_claude-sonnet-5_arc14-audit.md](reports/2026-07-19_claude-sonnet-5_arc14-audit.md) |

---

## RISK-001 — Fail-open authentication on algod rekey-lookup failure (V2, `AllowEmptyAccounts=true`)

- **Severity:** High
- **Status:** Open
- **Affected code:** `AlgorandAuthenticationHandlerV2.AuthAddress` (`AlgorandAuthentication/AlgorandAuthenticationHandlerV2.cs`)
- **Description:** When `AllowEmptyAccounts` is `true`, *any* exception thrown while calling the configured algod node's `AccountInformationAsync` (network timeout, 5xx, DNS failure, deserialization error — not just "account does not exist") causes the code to fabricate an `Account` object with `AuthAddr = tr.Tx.Sender`, i.e. it assumes the account was **never rekeyed**. If the real account was in fact rekeyed away from its original spending key (e.g. because that key was compromised or intentionally retired), this fallback authenticates the request using the original (possibly compromised/retired) key's signature instead of rejecting it or requiring the current authorized key. This turns a transient algod outage into a security-relevant authentication bypass rather than a safe failure.
- **Recommended remediation:** Distinguish "account not found" (safe to treat as non-rekeyed, brand-new account) from *any other* exception (network/timeout/transport errors), and fail closed (reject the request) on the latter regardless of `AllowEmptyAccounts`.
- **History:**
  - 2026-07-19 — Identified during initial audit by `claude-sonnet-5`. Status: Open.

## RISK-002 — `EmptySuccessOnFailure` issues authenticated ticket with empty identity

- **Severity:** Medium
- **Status:** Accepted (default is `false`; opt-in footgun, documented here for integrators)
- **Affected code:** `AlgorandAuthenticationHandler.HandleAuthenticateWithRequestAsync`, `AlgorandAuthenticationHandlerV2.HandleAuthenticateWithRequestAsync`
- **Description:** If enabled, any `UnauthorizedException` (bad signature, wrong network, expired tx, etc.) results in `AuthenticateResult.Success` with an identity carrying an **empty** `NameIdentifier`/`Name` claim, rather than an authentication failure. A downstream `[Authorize]` policy that only checks "is authenticated" (rather than checking the claim value is non-empty) would treat this as a valid, anonymous-but-authenticated user. This is a design footgun rather than a bug — it is off by default and presumably intended for endpoints that want "authenticate if possible, otherwise proceed as anonymous" semantics — but it is easy to misuse.
- **Recommended remediation:** Document prominently (README + XML doc comment) that any consumer enabling this flag must explicitly check for a non-empty identity/claim before treating the caller as authorized, and consider renaming/relocating the option or emitting a distinguishable claim (e.g. `IsAnonymousFallback=true`) so downstream authorization logic can't accidentally miss it.
- **History:**
  - 2026-07-19 — Identified during initial audit by `claude-sonnet-5`. Status: Accepted.

## RISK-003 — Debug logging of raw Authorization header

- **Severity:** Low
- **Status:** Open
- **Affected code:** `AlgorandAuthenticationHandler.cs:92`, `AlgorandAuthenticationHandlerV2.cs:93` — `logger.LogDebug($"Auth header: {Request.Headers[header]}")`
- **Description:** When `Options.Debug = true`, the full raw `Authorization` header (the base64 msgpack-encoded **signed transaction**, not a private key) is written to the configured logger at Debug level. This does not expose private key material — the header only ever contains a signature and public transaction fields — but it does expose the sender's address, note/realm value, and full signed transaction to anyone with log access, and could aid replay if `CheckExpiration=false`. `Debug` defaults to `false` in both option classes.
- **Recommended remediation:** Keep default `false` (already the case). Add an explicit XML-doc / README warning that `Debug=true` must never be enabled in production, and consider redacting or truncating the logged value.
- **History:**
  - 2026-07-19 — Identified during initial audit by `claude-sonnet-5`. Status: Open.

## RISK-004 — Unsynchronized shared static block-height cache

- **Severity:** Low
- **Status:** Open
- **Affected code:** `private static DateTimeOffset? t; private static ulong block;` in both `AlgorandAuthenticationHandler.cs` and `AlgorandAuthenticationHandlerV2.cs`
- **Description:** These fields are shared across all concurrent requests and all configured networks (in V2, a single pair of statics is reused regardless of which network in `AllowedNetworks` produced the cached round) without any locking. Concurrent requests can race on read/write, and in V2 a cached block/timestamp from network A can be reused to estimate the current round for network B if requests interleave, producing an incorrect expiration estimate. This is a correctness/robustness issue, not a direct key-leak or auth-bypass, but could weaken the `CheckExpiration` guarantee.
- **Recommended remediation:** Key the cache by network genesis hash (V2) and use thread-safe primitives (e.g. `Interlocked`, a lock, or a small per-network cache with expiry) instead of bare static fields.
- **History:**
  - 2026-07-19 — Identified during initial audit by `claude-sonnet-5`. Status: Open.

## RISK-005 — `CheckExpiration` defaults to `false`

- **Severity:** Medium
- **Status:** Accepted (integrator-controlled, documented default)
- **Affected code:** `AlgorandAuthenticationOptions.CheckExpiration`, `AlgorandAuthenticationOptionsV2.CheckExpiration`
- **Description:** With the default configuration, a captured/leaked `SigTx` header can be replayed indefinitely — there is no expiration check unless the integrator explicitly sets `CheckExpiration = true`. Since the README's example `appsettings.json` does set it to `true`, this is a reasonably-guided default in practice, but the library's own default (`false`) is the less-safe choice.
- **Recommended remediation:** Consider flipping the default to `true` in a future major version (breaking change), or at minimum add a startup-time warning log when `CheckExpiration=false` is in effect.
- **History:**
  - 2026-07-19 — Identified during initial audit by `claude-sonnet-5`. Status: Accepted.

## RISK-006 — Null `Tx.Note` crashes realm check via unhandled exception path

- **Severity:** Low
- **Status:** Open
- **Affected code:** `VerifyCommon` in both handlers — `Encoding.ASCII.GetString(tr.Tx.Note)`
- **Description:** If a transaction has no `Note` field (null) and a `Realm`/`Realms` check is configured, `Encoding.ASCII.GetString(null)` throws `ArgumentNullException`, which is caught by the outer generic `catch (Exception e)` and returned as `AuthenticateResult.Fail(e)`. Functionally this still rejects the request (no security bypass), but it does so via an unintended code path rather than a clean `UnauthorizedException`, and depending on how the hosting application surfaces `AuthenticateResult.Fail`'s exception, internal exception details (type name, stack trace) could reach a client or log sink inconsistently with the rest of the library's clean-rejection design.
- **Recommended remediation:** Explicitly check `tr.Tx.Note == null` and throw a clean `UnauthorizedException("Missing realm note")` before attempting to decode it.
- **History:**
  - 2026-07-19 — Identified during initial audit by `claude-sonnet-5`. Status: Open.

## RISK-007 — Empty realm configuration silently disables domain separation (V2)

- **Severity:** Medium
- **Status:** Open
- **Affected code:** `AlgorandAuthenticationHandlerV2.VerifyCommon` — `if (Options.Realms.Any()) {...} else if (!string.IsNullOrEmpty(Options.Realm)) {...}` (no `else` branch)
- **Description:** If an integrator leaves `Realms` empty **and** explicitly sets `Realm` to `""`/null (overriding the `"Authentication"` default), no realm check is performed at all — a signed transaction crafted for a *completely different application* sharing the same network and algod config would be accepted here, since domain separation is realm-based rather than tied to this specific service. This requires an explicit misconfiguration (clearing both `Realm` and `Realms`), so it is not exploitable purely by an attacker, but it is a silent-fail configuration trap rather than a fail-closed default.
- **Recommended remediation:** Log a startup warning (or throw) if both `Realm` and `Realms` are empty, since that combination removes an important defense against cross-application signature reuse.
- **History:**
  - 2026-07-19 — Identified during initial audit by `claude-sonnet-5`. Status: Open.

## RISK-008 — Trusted third-party crypto/SDK dependencies not independently re-audited

- **Severity:** Informational
- **Status:** Accepted (explicitly out of scope per `AUDITS-INSTRUCTIONS.md`, tracked for CVE monitoring)
- **Affected code:** `Algorand4` NuGet package, `Org.BouncyCastle` (Ed25519 signature verification)
- **Description:** This library's security depends entirely on the correctness of `Algorand4`'s msgpack decoding and transaction model, and BouncyCastle's `Ed25519Signer`/`Ed25519PublicKeyParameters` for signature verification. Neither was independently source-audited in this engagement.
- **Recommended remediation:** Track CVE advisories for `Algorand4` and `BouncyCastle.Cryptography` on each future audit pass (see Phase 5 of `AUDITS-INSTRUCTIONS.md`).
- **History:**
  - 2026-07-19 — Logged during initial audit by `claude-sonnet-5`. Status: Accepted.

## RISK-009 — Test suite contains real-format BIP-39-style mnemonics

- **Severity:** Informational
- **Status:** Accepted
- **Affected code:** `TestAlgorandAuthentication/MultisigTests.cs`, `TestAlgorandAuthentication/MultisigV2Tests.cs`
- **Description:** Unit tests construct `Algorand.Algod.Model.Account` objects from hardcoded 25-word mnemonics. These are well-known, publicly-committed test-only values with no association to real funds (standard practice for TestNet-only integration tests), and `TestNet` — not `MainNet` — endpoints are used. No actual private key/mnemonic secret is at risk. Flagged only so future audits confirm these remain test-only and are never reused as real account seeds.
- **Recommended remediation:** None required; optionally add a code comment marking them explicitly as public test vectors to prevent future reuse confusion.
- **History:**
  - 2026-07-19 — Logged during initial audit by `claude-sonnet-5`. Status: Accepted.
