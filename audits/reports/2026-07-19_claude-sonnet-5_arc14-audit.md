# Security Audit Report — AlgorandAuthenticationDotNet

- **Audit date:** 2026-07-19
- **Auditor / model:** Claude Sonnet 5 (`claude-sonnet-5`)
- **Commit audited:** `71ea7d4a8c8ea2c43e1b67e14d6b5454db3c4a65`
- **Package version audited:** `2.1.4` (`AlgorandAuthentication.csproj`)
- **Target frameworks:** net8.0, net9.0, net10.0
- **Audit type:** Initial audit (no prior report exists to diff against)
- **Scope:** Per `audits/AUDITS-INSTRUCTIONS.md` — the ARC-0014 authentication handlers (V1 and V2), options, client-side header-construction helper, extensions, tests, README, and release workflow. Cryptographic primitives inside `Algorand4`/BouncyCastle and consumer applications are out of scope (see Assumptions).

---

## Executive summary

This library implements server-side verification of Algorand-signed authentication transactions (ARC-0014) for ASP.NET Core, plus a small client-side helper for constructing the signed header. **The core question this audit was commissioned to answer — can this library leak a user's private key, seed, or mnemonic — has a clear answer: no.** The server-side verification path (`AlgorandAuthenticationHandler`/`V2`) never receives, stores, or requires a private key at any point; it only ever handles public addresses, a pre-computed signature, and public transaction fields decoded from the request header. The one place a private key does exist in memory anywhere in this codebase is inside the client-side `ARC14.CreateHeader(Account, ...)` helper, which passes the account straight into the underlying SDK's `Sign()` call and does not log, cache, retain, or otherwise expose it. No hardcoded production secrets, private keys, or mnemonics tied to real funds were found anywhere in source, tests, or CI configuration.

The library is reasonably safe to use as intended, provided integrators follow the documented configuration (in particular, setting `CheckExpiration = true` and configuring `AllowedNetworks`/`Realm` correctly, as the README's own example does). One **High**-severity finding was identified: under `AllowEmptyAccounts = true` (V2), a transient failure calling the configured algod node — not just a genuinely nonexistent account — causes the library to fail *open*, assuming the account was never rekeyed. This should be fixed before the library is relied upon in environments where rekeying is used as a key-rotation/compromise-recovery mechanism. Several Medium/Low findings around default configuration safety, logging, and edge-case exception handling are documented below; none of them involve private key exposure.

**Bottom line: the library does not handle or leak private keys, and is safe to use for production authentication when configured per the documented recommendations — but the `AllowEmptyAccounts` fail-open behavior (RISK-001) should be treated as a priority fix, and `EmptySuccessOnFailure`/empty-realm configurations (RISK-002, RISK-007) require integrator care.**

---

## Findings table

| ID | Title | Severity | File:Line | Status |
|---|---|---|---|---|
| RISK-001 | Fail-open auth on algod rekey-lookup failure (V2, `AllowEmptyAccounts=true`) | High | `AlgorandAuthenticationHandlerV2.cs:184-217` | New |
| RISK-002 | `EmptySuccessOnFailure` issues authenticated ticket with empty identity | Medium | `AlgorandAuthenticationHandler.cs:121-141`, `AlgorandAuthenticationHandlerV2.cs:129-149` | New |
| RISK-007 | Empty realm config silently disables domain separation (V2) | Medium | `AlgorandAuthenticationHandlerV2.cs:293-311` | New |
| RISK-005 | `CheckExpiration` defaults to `false` | Medium | `AlgorandAuthenticationOptions.cs:8`, `AlgorandAuthenticationOptionsV2.cs:48` | New |
| RISK-003 | Debug logging of raw Authorization header | Low | `AlgorandAuthenticationHandler.cs:92`, `AlgorandAuthenticationHandlerV2.cs:93` | New |
| RISK-004 | Unsynchronized shared static block-height cache | Low | `AlgorandAuthenticationHandler.cs:26-27`, `AlgorandAuthenticationHandlerV2.cs:27-28` | New |
| RISK-006 | Null `Tx.Note` crashes realm check via generic exception path | Low | `AlgorandAuthenticationHandler.cs:245`, `AlgorandAuthenticationHandlerV2.cs:295,305` | New |
| RISK-008 | Trusted crypto/SDK dependencies not independently re-audited | Informational | `AlgorandAuthentication.csproj:21` | New |
| RISK-009 | Test suite contains real-format test mnemonics | Informational | `MultisigTests.cs:30-32`, `MultisigV2Tests.cs:29-31` | New |

Full detail, remediation, and history for each is tracked in [`audits/RISKS.md`](../RISKS.md); this report only summarizes them.

---

## Detailed findings

### RISK-001 — Fail-open authentication on algod rekey-lookup failure (High)

**File:** `AlgorandAuthentication/AlgorandAuthenticationHandlerV2.cs`, `AuthAddress` method, lines ~184–217.

```csharp
try
{
    account = await algodClient.AccountInformationAsync(tr.Tx.Sender.EncodeAsString());
}
catch
{
    if (Options.AllowEmptyAccounts)
    {
        account = new Algorand.Algod.Model.Account
        {
            AuthAddr = tr.Tx.Sender,
            Address = tr.Tx.Sender,
            Amount = 0
        };
    }
}
```

The `catch` block is unconditional — it fires on a genuine 404/"account does not exist" response just as readily as on a network timeout, DNS failure, TLS error, algod node downtime, or a transient 500. In every one of those cases, if `AllowEmptyAccounts` is `true`, the code assumes `AuthAddr == tr.Tx.Sender`, i.e., that the account has never been rekeyed, and proceeds to verify the transaction's signature against the sender address itself.

**Why this matters:** rekeying is Algorand's supported mechanism for rotating away from a compromised or retired spending key. An application that relies on rekeying as part of its security model (e.g., "the original hot-wallet key was compromised, we rekeyed to a new key") would, during any algod outage or network blip, silently accept a signature from the **old, rekeyed-away key** instead of rejecting the request or requiring the currently-authorized key. This converts an availability problem (algod is down) into an authentication-bypass problem, which is a materially worse failure mode.

**Reproduction reasoning:** Point `AllowedNetworks[...].Server` at an unreachable/timing-out host with `AllowEmptyAccounts=true`, submit a validly-signed-by-the-original-key transaction for an address that has (in reality, on-chain) been rekeyed away from that key. The handler will authenticate successfully because it never learns about the rekey.

**Recommendation:** Only synthesize the "no-rekey" fallback account on a confirmed "account does not exist" response (Algorand's `HttpOperationException` with 404, or an explicit not-found error code from the SDK) — never on generic/transport-level exceptions. Any other exception should propagate to a fail-closed `UnauthorizedException`.

### RISK-002 — `EmptySuccessOnFailure` issues authenticated ticket with empty identity (Medium)

**File:** both handlers, `catch (UnauthorizedException e)` blocks.

When enabled, any authentication failure (bad signature, wrong realm, expired tx, wrong network, etc.) results in `AuthenticateResult.Success` carrying an identity with `NameIdentifier = ""` and `Name = ""`, rather than a failed authentication. This is intentional (the option's name says as much) and defaults to `false`, so it is not a vulnerability in the library itself, but it is a sharp edge: any consuming application that gates access purely on `User.Identity.IsAuthenticated` (a common but incomplete pattern) rather than on the claim value would grant access to an unauthenticated caller. This is a common ASP.NET Core authorization mistake this design makes easy to fall into.

**Recommendation:** documented in RISKS.md; consider a distinguishing claim (e.g. `"AlgoAuthFallback" = "true"`) so downstream policies can positively detect this state instead of relying on absence of information.

### RISK-007 — Empty realm configuration silently disables domain separation (Medium, V2 only)

**File:** `AlgorandAuthenticationHandlerV2.VerifyCommon`, lines ~293–311.

```csharp
if (Options.Realms.Any())
{ /* check */ }
else
if (!string.IsNullOrEmpty(Options.Realm))
{ /* check */ }
// else: no check performed at all
```

`Realm` defaults to `"Authentication"` (non-empty), so this requires an integrator to actively clear both `Realm` and `Realms` to hit the silent no-check branch — but if they do (e.g. templating configuration that sets `Realm: ""` expecting `Realms` to be the new source of truth, then never populates `Realms`), realm/domain separation between different applications sharing the same `AllowedNetworks` configuration is silently disabled. A transaction signed for a different ARC-0014-consuming application on the same network would then be accepted here.

**Recommendation:** treat "both empty" as a configuration error — throw at startup or log a loud warning — rather than silently proceeding without domain separation.

### RISK-005 — `CheckExpiration` defaults to `false` (Medium)

Both `AlgorandAuthenticationOptions` and `AlgorandAuthenticationOptionsV2` default `CheckExpiration` to `false`. Without it, a captured `SigTx` header (e.g. exfiltrated from browser storage, a proxy log, or a MITM'd non-TLS deployment) can be replayed indefinitely as a valid credential — there is no expiration enforcement unless the integrator explicitly opts in. The README's own example configuration sets this to `true`, so documented usage is safe, but the library's default is the less-safe choice, and a developer who skips straight to `services.AddAuthentication(...).AddAlgorand()` with no options block gets no replay protection at all.

**Recommendation:** consider defaulting to `true` in a future major version, or emit a one-time startup log warning when expiration checking is disabled.

### RISK-003 — Debug logging of raw Authorization header (Low)

```csharp
if (Options.Debug) { logger.LogDebug($"Auth header: {Request.Headers[header]}"); }
```

Confirmed **not** a private-key leak — the header only ever contains a base64 msgpack-encoded signed transaction (signature + public fields), never key material. It does expose the full signed credential (replayable if `CheckExpiration=false`) to any log sink `Debug`-level logs reach. `Debug` correctly defaults to `false` in both option classes, and the README does not suggest enabling it in production.

**Recommendation:** add an explicit doc-comment/README warning against enabling `Debug` in production; optionally truncate the logged value.

### RISK-004 — Unsynchronized shared static block-height cache (Low)

```csharp
private static DateTimeOffset? t;
private static ulong block;
```

Shared, unlocked, process-wide mutable state used to estimate the current Algorand round without hitting algod on every request. In V2 this cache is **not partitioned by network**, so under concurrent traffic against multiple `AllowedNetworks`, a round number fetched for network A can be used to estimate expiration for network B, and concurrent writers can race without synchronization. This is a correctness/hardening gap in the expiration-estimation logic, not an authentication bypass or key-leak vector — worst case it makes expiration estimates slightly wrong in either direction.

**Recommendation:** partition by genesis hash and use a thread-safe update pattern (e.g. `Interlocked.CompareExchange`, a small lock, or a `ConcurrentDictionary<string, (DateTimeOffset, ulong)>`).

### RISK-006 — Null `Tx.Note` crashes realm check via generic exception path (Low)

`Encoding.ASCII.GetString(tr.Tx.Note)` throws `ArgumentNullException` if `Note` is null and a realm check is configured. The outer `catch (Exception e)` still converts this into `AuthenticateResult.Fail(e)` — the request is rejected either way, so there is no security bypass — but it takes an unclean path that could be confusing to debug and, depending on the hosting pipeline's handling of `AuthenticateResult.Fail(Exception)`, might surface an exception type/stack trace rather than the library's normal clean rejection message.

**Recommendation:** explicitly guard `tr.Tx.Note == null` and throw `UnauthorizedException` before attempting to decode it.

---

## Positive findings (controls confirmed sound)

1. **No private key handling on the verification path.** Traced `HandleAuthenticateWithRequestAsync` → `HandleAuthenticateWithRequestSingleSigAsync` / `HandleAuthenticateWithRequestMultiSigAsync` → `VerifyCommon` in both V1 and V2: the only cryptographic material handled server-side is a **public** address/key (`sender.Bytes`, `subsig.key.GetEncoded()`) and a **signature** (`tr.Sig.Bytes`, `subsig.sig.Bytes`). No private key, seed, or mnemonic is ever received, constructed, or referenced by the server-side verification code.
2. **Client-side signing helper does not retain key material.** `ARC14.CreateHeader(Account algo25Account, ...)` passes `algo25Account` directly into `payload.Sign(algo25Account)` (a single call into the `Algorand4` SDK) and returns only the resulting base64 signed-transaction string. No field, cache, or logger anywhere in `ARC14.cs` captures the `Account` object or any derived secret.
3. **Signature verification uses standard, correct primitives.** `Verify()` uses BouncyCastle's `Ed25519Signer`/`Ed25519PublicKeyParameters` for genuine elliptic-curve signature verification (not a raw byte/string comparison), which is the appropriate approach and not subject to a naive timing-based comparison oracle.
4. **Genesis-hash network pinning is enforced on every request** in both V1 (`Options.NetworkGenesisHash`) and V2 (`Options.AllowedNetworks` dictionary keyed by genesis hash), preventing a transaction signed for one network from being replayed against a service configured for another.
5. **Multisig threshold and duplicate-key protection is implemented correctly:** the `checkedSet` guard rejects a subsignature list that reuses the same public key twice, each present signature is independently verified before counting toward the threshold, and the reconstructed `MultisigAddress` is compared against the resolved sender address, preventing a forged multisig envelope from substituting an unrelated set of keys.
6. **No hardcoded secrets tied to real funds** were found in source, tests, or `.github/workflows/release.yml`. The release workflow uses NuGet Trusted Publishing (OIDC short-lived token exchange), not a long-lived static NuGet API key, which is the current best-practice pattern for supply-chain security on this kind of pipeline.
7. **Safe defaults on the most dangerous options:** `EmptySuccessOnFailure` and `Debug` both default to `false`; `AllowEmptyAccounts` defaults to `false`. An integrator who accepts all defaults except the ones the README explicitly walks through does not opt into any of the higher-risk behaviors by accident.

---

## Comparison to previous audit

None — this is the initial audit for this repository. Future runs (triggered via `do new audit`) must diff against this report.

---

## Dependency / CVE review

| Package | Version(s) referenced in `.csproj` | Notes |
|---|---|---|
| `Algorand4` | `4.7.4.2026071920` | Core Algorand SDK (transaction model, msgpack encode/decode, signing). No independent source audit performed this cycle (out of scope per instructions) — recommend checking the package's GitHub advisories/NuGet.org security tab on each future audit. |
| `Microsoft.AspNetCore.Authentication.Negotiate` | 8.0.20 / 9.0.10 / 10.0.10 (per TFM) | Framework-provided; only used transitively for `AuthenticationBuilder` typing, not for actual Negotiate/Kerberos flows in this library. |
| `Microsoft.Extensions.Caching.Abstractions` | 8.0.0 / 9.0.10 / 10.0.10 | Abstractions-only package; low risk. |
| `Microsoft.Extensions.Logging.Abstractions` | 10.0.10 (all TFMs) | Abstractions-only package; low risk. |
| `Microsoft.Extensions.Options` | 8.0.2 / 9.0.10 / 10.0.10 | Standard options pattern; low risk. |
| `Org.BouncyCastle.*` (Ed25519) | transitive via `Algorand4` — exact version not pinned directly by this project | Recommend pinning/reviewing the transitive BouncyCastle version explicitly in a future audit, since it performs the actual signature verification this library's security rests on. |

No known/public CVEs were identified against the referenced version strings at the time of this review based on the package metadata visible in the repository; this is not a substitute for querying a live vulnerability database (e.g. GitHub Advisory Database, NVD) at audit time with tooling access to do so, and should be repeated with such tooling on the next cycle if available.

---

## Test coverage assessment

Existing tests (`MultisigTests.cs`, `MultisigV2Tests.cs`) cover the **happy path** well: single-sig, 2-of-3 multisig, rekeyed single-sig, and multi-network acceptance, all against live TestNet algod endpoints. They do **not** currently cover:

- Bad/forged signature rejection (negative test)
- Wrong network / genesis-hash mismatch rejection
- Wrong or missing realm rejection (including the null-`Note` crash path, RISK-006)
- Expired transaction rejection (`CheckExpiration=true` with a `LastValid` in the past)
- Multisig threshold-not-met rejection
- Duplicate-signer-key rejection in a multisig envelope
- `AllowEmptyAccounts` / algod-failure interaction (RISK-001's exact scenario)
- `EmptySuccessOnFailure` behavior
- Malformed/garbage base64 or msgpack input (DoS/robustness)

Given this is an authentication library, the near-total absence of negative-path tests is a notable gap — the positive-path tests confirm the library *can* authenticate a legitimate user, but do not confirm it correctly *rejects* an illegitimate one, which is the more security-critical property. Recommend prioritizing tests for RISK-001 and the negative signature/network/realm/expiration cases above.

---

## Scope, assumptions, and limitations

- This audit is a code-level static review performed by an AI model (Claude Sonnet 5) reading the source in this repository. It is not a substitute for a human-led, tooled penetration test, a formal cryptographic proof, or a live dependency-vulnerability-database query.
- The correctness of `Algorand4`'s msgpack decoding, transaction model, and BouncyCastle's Ed25519 implementation is assumed (trusted dependency), per the scope defined in `AUDITS-INSTRUCTIONS.md`.
- No dynamic testing (fuzzing, live exploitation, running the test suite against a real algod outage) was performed in this cycle; findings are based on static code reasoning.
- The audit did not have access to a live CVE/vulnerability database lookup tool during this run; the dependency table above should be re-checked against GitHub Advisory Database / NVD with live tooling on the next cycle.
- Consumer-application misuse beyond what the library's own API/README actively encourages is out of scope.

---

## Appendix — files reviewed

- `AlgorandAuthentication/AlgorandAuthenticationHandler.cs`
- `AlgorandAuthentication/AlgorandAuthenticationHandlerV2.cs`
- `AlgorandAuthentication/AlgorandAuthenticationOptions.cs`
- `AlgorandAuthentication/AlgorandAuthenticationOptionsV2.cs`
- `AlgorandAuthentication/ARC14.cs`
- `AlgorandAuthentication/Extensions.cs`
- `AlgorandAuthentication/ExtensionsV2.cs`
- `AlgorandAuthentication/UnauthorizedException.cs`
- `AlgorandAuthentication/AlgorandAuthentication.csproj`
- `TestAlgorandAuthentication/MultisigTests.cs`
- `TestAlgorandAuthentication/MultisigV2Tests.cs`
- `TestAlgorandAuthentication/TestAlgorandAuthentication.csproj`
- `TestAlgorandAuthentication/Usings.cs`
- `README.md`
- `.github/workflows/release.yml`
- `.github/workflows/README.md`
