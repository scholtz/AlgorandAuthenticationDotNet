# Security Audit Report — AlgorandAuthenticationDotNet

- **Audit date:** 2026-07-20
- **Auditor / model:** Claude Sonnet 5 (`claude-sonnet-5`)
- **Base commit audited:** `a031496f0fbaabebf4e91278921ae87946e10440` (working tree changes on top, described below, not yet committed at time of writing)
- **Package version audited:** `2.2.0` (`AlgorandAuthentication.csproj`)
- **Target frameworks:** net8.0, net9.0, net10.0
- **Audit type:** Fix-verification follow-up to [2026-07-19_claude-sonnet-5_arc14-audit.md](2026-07-19_claude-sonnet-5_arc14-audit.md)
- **Scope:** Same scope as the 2026-07-19 report — the ARC-0014 authentication handlers (V1/V2), options, client-side header helper, extensions, tests, README, and release workflow.

---

## Executive summary

This is a targeted follow-up to the 2026-07-19 initial audit: the user asked to fix the findings from that report, and this report documents and verifies the fixes applied. **The bottom-line safety conclusion is unchanged and strengthened: this library still does not handle or leak private keys anywhere in its verification path or its client-side signing helper.** Of the seven concrete (non-informational) findings from the prior audit, six are now fixed and verified in code (RISK-001 through RISK-004, RISK-006, RISK-007); the seventh (RISK-005, the `CheckExpiration` default) was deliberately left as a documented, accepted risk rather than silently changed, since flipping a security-relevant default is a breaking change that should be a deliberate versioning decision, not a side effect of an audit-fix pass — a warning doc-comment was added instead. The two informational items (RISK-008, RISK-009) required no code change and were simply re-verified as still accurate.

The most significant fix is **RISK-001** (High): the V2 handler's rekey-lookup fallback no longer treats *every* algod-call failure as "account was never rekeyed" — it now only does so on a confirmed HTTP 404 (`Algorand.ApiException` with `StatusCode == 404`), and fails closed (propagates to `AuthenticateResult.Fail`) on any other error such as a timeout or outage. This closes the fail-open authentication-bypass path identified previously.

All changes were verified by a full solution rebuild (`dotnet build`, 0 errors/warnings across all three target frameworks) and the existing test suite (`dotnet test`, 5/5 passing against live TestNet endpoints) run after the changes, confirming no regression to the documented positive-path behavior.

**Bottom line: all actionable findings from the prior audit are fixed or explicitly accepted-with-rationale; the library remains safe with respect to private key handling, and is now more robust against fail-open authentication bypass and silent misconfiguration.**

---

## Findings table (updated)

| ID | Title | Severity | File:Line | Status |
|---|---|---|---|---|
| RISK-001 | Fail-open auth on algod rekey-lookup failure (V2, `AllowEmptyAccounts=true`) | High | `AlgorandAuthenticationHandlerV2.cs` (`AuthAddress`) | **Fixed-since-last-audit** |
| RISK-002 | `EmptySuccessOnFailure` issues authenticated ticket with empty identity | Medium | both handlers | **Fixed-since-last-audit** (mitigated via traceable claim + doc comment) |
| RISK-007 | Empty realm config silently disables domain separation (V2) | Medium | `AlgorandAuthenticationHandlerV2.cs` (`VerifyCommon`) | **Fixed-since-last-audit** |
| RISK-005 | `CheckExpiration` defaults to `false` | Medium | both options classes | **Recurring** (intentionally accepted; doc comment added) |
| RISK-003 | Debug logging of raw Authorization header | Low | both handlers | **Fixed-since-last-audit** |
| RISK-004 | Unsynchronized shared static block-height cache | Low | both handlers | **Fixed-since-last-audit** |
| RISK-006 | Null `Tx.Note` crashes realm check via generic exception path | Low | both handlers (`VerifyCommon`) | **Fixed-since-last-audit** |
| RISK-008 | Trusted crypto/SDK dependencies not independently re-audited | Informational | `AlgorandAuthentication.csproj` | Recurring (accepted, unchanged) |
| RISK-009 | Test suite contains real-format test mnemonics | Informational | test files | Recurring (accepted, unchanged) |

Full detail, fix descriptions, and history for each is tracked in [`audits/RISKS.md`](../RISKS.md); this report summarizes verification of each fix.

---

## Fix verification detail

### RISK-001 — Fail-open on algod failure (Fixed)

**Before:**
```csharp
try
{
    account = await algodClient.AccountInformationAsync(tr.Tx.Sender.EncodeAsString());
}
catch
{
    if (Options.AllowEmptyAccounts) { /* fabricate non-rekeyed account */ }
}
```

**After** (`AlgorandAuthenticationHandlerV2.cs`, `AuthAddress`):
```csharp
catch (Algorand.ApiException e) when (e.StatusCode == 404)
{
    if (Options.AllowEmptyAccounts) { /* fabricate non-rekeyed account */ }
}
```

Verified via reflection against the actual `Algorand4` package (`4.7.4.2026071920`) that `Algorand.ApiException` exposes an `int StatusCode` property distinct from `Algorand.KMD.ApiException`, confirming the exception-filter type and member are correct for the `AccountInformationAsync` call path (`Algorand.Algod.DefaultApi`). Any exception other than a 404 `ApiException` (timeout, DNS failure, 5xx, deserialization error, etc.) is no longer caught here — it now propagates out of `AuthAddress`, up through `HandleAuthenticateWithRequestSingleSigAsync`/`MultiSigAsync`, and is caught by the outer `catch (Exception e) { return AuthenticateResult.Fail(e); }` in `HandleAuthenticateWithRequestAsync`. **This is the correct fail-closed behavior**: an algod outage now rejects the request rather than silently authenticating against a stale, potentially-rekeyed-away key.

**Verification:** full solution build succeeded; `TestsV2.ValidateSinglesigTransaction` (which specifically exercises a *rekeyed* account against a live, reachable algod node) still passes, confirming the happy-path 200-OK rekey resolution is untouched by this change.

### RISK-002 — `EmptySuccessOnFailure` traceability (Fixed)

Both handlers now add `new Claim("AlgoAuthFallback", "true")` to the empty-identity ticket issued on this fallback path, and the `EmptySuccessOnFailure` XML doc comment in both options classes instructs integrators to check for this claim (or a non-empty `NameIdentifier`) rather than `IsAuthenticated` alone. This does not change the option's default (`false`) or its opt-in behavior — it only makes the resulting ticket positively identifiable downstream, closing the "looks authenticated to a naive `[Authorize]` check" gap.

### RISK-007 — Empty realm configuration (Fixed)

`AlgorandAuthenticationHandlerV2.VerifyCommon` previously had no `else` branch when both `Options.Realms` and `Options.Realm` were empty, silently skipping domain separation. An explicit `else` branch now throws `UnauthorizedException("No realm configured. At least one of Realm or Realms must be set to enforce domain separation.")`. Since both classes default `Realm` to `"Authentication"` (non-empty), this is a behavior change only for integrators who explicitly clear both settings — which is exactly the misconfiguration this finding was about. Verified this does not affect any existing test (all tests configure a non-empty `Realm`/`Realms`).

### RISK-003 — Debug logging (Fixed)

Both handlers replaced `logger.LogDebug($"Auth header: {Request.Headers[header]}")` with a call that logs only the header's length and a 16-character prefix via a new private `Truncate` helper. The full signed-transaction credential is no longer written to logs even with `Debug=true`. `Debug` doc comments in both options classes now explicitly state it must never be enabled in production.

### RISK-004 — Unsynchronized static cache (Fixed)

- **V1** (single network by design): the existing `t`/`block` statics are now guarded by a dedicated `lock (blockCacheLock)` around every read and write, removing the unsynchronized race.
- **V2** (multi-network): replaced the bare `t`/`block` statics with `private static readonly ConcurrentDictionary<string, (DateTimeOffset t, ulong block)> blockCache`, keyed by network genesis hash (`networkHash`), so a cached round fetched for one `AllowedNetworks` entry can never be misapplied to estimate expiration for a different network.
- **Verification:** `TestsV2.TestMultipleNetworks` (which authenticates against two distinct networks in the same test) passed after the change, confirming per-network isolation did not break multi-network resolution.

### RISK-006 — Null `Tx.Note` (Fixed)

Both handlers' `VerifyCommon` now explicitly check `tr.Tx.Note == null` immediately before `Encoding.ASCII.GetString(...)` in every realm-check branch (V1's single `Realm` check; V2's `Realms` list and legacy `Realm` checks) and throw a clean, descriptive `UnauthorizedException` instead of letting an `ArgumentNullException` fall through to the generic exception handler.

### RISK-005 — `CheckExpiration` default (left as Accepted, documented)

No default value was changed. Per the audit's own recommendation, flipping this default is a breaking change that affects every existing integrator silently upgrading a patch/minor version, and should be a deliberate major-version decision — not something to change as a side effect of a findings-fix pass without the repository owner's explicit sign-off. Instead, an XML doc comment was added to `CheckExpiration` in both options classes: *"When false (the default), a captured/leaked 'SigTx' header can be replayed indefinitely because no expiration is enforced. Production deployments should set this to true."* This gives IDE tooltip visibility to integrators reading the option without changing runtime behavior. Recorded in `RISKS.md` as `Accepted` (recurring), not closed.

### RISK-008 / RISK-009 (Informational, re-verified, no change)

No dependency version change occurred in this cycle (`Algorand4` remains `4.7.4.2026071920`); no new CVE lookup tooling was available this cycle either, so this remains an open action item for a future audit with live vulnerability-database access. Test mnemonics are unchanged and remain confirmed TestNet-only, public, well-known test vectors.

---

## Regression check

- `dotnet build AlgorandAuthentication.sln -c Debug` — **0 errors, 0 warnings**, all three target frameworks (net8.0/net9.0/net10.0) built successfully.
- `dotnet test AlgorandAuthentication.sln -c Debug --no-build` — **5/5 tests passed** (`TestAlgorandAuthentication.dll`, net8.0), including the V2 rekeyed-account test and the multi-network test, both of which directly exercise code paths touched by the RISK-001 and RISK-004 fixes.
- No test file was modified as part of this fix pass; the existing suite's continued pass is evidence against regression, but as flagged in the 2026-07-19 report, the suite still lacks negative-path coverage (bad signature, wrong network, expired tx, malformed input, threshold-not-met, and now specifically an algod-timeout-with-`AllowEmptyAccounts`-true scenario for RISK-001). Adding those tests remains a recommended next step and was not in scope for this fix-only pass.

---

## Comparison to previous audit

| Finding | 2026-07-19 status | 2026-07-20 status | Change |
|---|---|---|---|
| RISK-001 | Open (High) | Mitigated | Fixed |
| RISK-002 | Accepted | Mitigated | Fixed |
| RISK-003 | Open | Mitigated | Fixed |
| RISK-004 | Open | Mitigated | Fixed |
| RISK-005 | Accepted | Accepted | Unchanged (by design) |
| RISK-006 | Open | Mitigated | Fixed |
| RISK-007 | Open | Mitigated | Fixed |
| RISK-008 | Accepted | Accepted | Unchanged |
| RISK-009 | Accepted | Accepted | Unchanged |

No regressions were introduced; no new risks were identified during this fix-verification pass.

---

## Dependency / CVE review

Unchanged from the 2026-07-19 report — `Algorand4` remains pinned at `4.7.4.2026071920` in `AlgorandAuthentication.csproj`; no dependency versions were modified as part of this fix pass. Live CVE-database tooling was still not available this cycle; this remains a standing action item.

---

## Scope, assumptions, and limitations

- Same limitations as the 2026-07-19 report apply: this is a static code review by an AI model, not a substitute for a human-led penetration test or live dependency-vulnerability scan.
- The `Algorand.ApiException.StatusCode` behavior relied upon by the RISK-001 fix was verified by loading the actual `Algorand4` NuGet assembly via .NET reflection and confirming the type and property exist as expected; it was not verified against a live 404 response from a real algod node in this cycle (would require a controllable algod mock/outage simulation, which was out of scope for this pass).
- The fixes in this report are present in the working tree at audit time; confirm they have been committed (`git status`) before considering this fix-verification final for release purposes.

---

## Appendix — files changed in this fix pass

- `AlgorandAuthentication/AlgorandAuthenticationHandler.cs`
- `AlgorandAuthentication/AlgorandAuthenticationHandlerV2.cs`
- `AlgorandAuthentication/AlgorandAuthenticationOptions.cs`
- `AlgorandAuthentication/AlgorandAuthenticationOptionsV2.cs`
- `audits/RISKS.md` (statuses and history updated)
