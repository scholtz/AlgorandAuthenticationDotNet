# AlgorandAuthenticationDotNet — Security Audit Instructions

## Purpose

This document defines the scope, methodology, and deliverables for a **professional, $20,000-grade security audit** of the `AlgorandAuthenticationDotNet` library (NuGet package `AlgorandAuthentication`).

The library implements **ARC-0014** ("SigTx" header) authentication for ASP.NET Core: it verifies Algorand-signed transactions presented as bearer-style HTTP `Authorization` headers, and includes a small client-side helper (`ARC14.cs`) for constructing those signed headers.

**The single most important audit objective, above all others:**

> **Confirm that this library can never cause a user's Algorand private key, seed phrase, or mnemonic to be exposed, logged, transmitted, or otherwise leaked — and that it is safe for a developer to depend on in a production system that protects real funds.**

Every other finding is secondary to that objective. If an auditor must choose where to spend limited time, spend it there first.

This is a paid, professional-grade engagement. Findings must be evidence-based (file + line references), reproducible, and actionable. This is not a superficial linting pass — treat it as if a client paid $20,000 USD for the result and is relying on it before shipping to production with real assets on Algorand MainNet.

---

## Scope

### In scope

- `AlgorandAuthentication/AlgorandAuthenticationHandler.cs` (V1 handler)
- `AlgorandAuthentication/AlgorandAuthenticationHandlerV2.cs` (V2 handler, multi-network)
- `AlgorandAuthentication/AlgorandAuthenticationOptions.cs`, `AlgorandAuthenticationOptionsV2.cs`
- `AlgorandAuthentication/ARC14.cs` (client-side signed-header construction helper)
- `AlgorandAuthentication/Extensions.cs`, `ExtensionsV2.cs`
- `AlgorandAuthentication/UnauthorizedException.cs`
- `AlgorandAuthentication/AlgorandAuthentication.csproj` (dependency versions/provenance)
- `TestAlgorandAuthentication/*` (test coverage adequacy, and whether tests embed any real-world-usable secrets)
- `README.md` (whether documented usage patterns could mislead a developer into an insecure integration)
- `.github/workflows/*` (build/release pipeline — supply-chain risk to the published NuGet package)

### Out of scope (but note as an assumption/limitation in the report)

- The Algorand blockchain protocol itself, the `Algorand4` SDK internals, and BouncyCastle's Ed25519 implementation — treated as trusted third-party dependencies. The audit should still record their **versions** and check for **known CVEs**, but a full independent cryptographic audit of those libraries is out of scope.
- Consumer applications that use this library (their own storage of JWTs/cookies, wallet integrations, frontend code) — except to the extent the library's README/API design actively encourages an insecure pattern.

---

## Auditor persona and standard of care

Act as an independent, senior application-security auditor with expertise in:

- .NET / ASP.NET Core authentication internals (`AuthenticationHandler<T>`, claims, ticket issuance)
- Applied cryptography, specifically Ed25519 signature verification and replay/expiration protections
- Blockchain wallet-authentication patterns (ARC-0014, SIWE-style challenge/response designs) and their common pitfalls
- Secure coding review (OWASP ASVS, CWE Top 25) and supply-chain security (NuGet/CI provenance)

Hold the code to the standard you would apply if your own funds, or a client's customers' funds, depended on this library being correct.

---

## Methodology

Work through these phases in order. Do not skip a phase because an earlier one looked clean.

### Phase 1 — Private-key / secret-material leak analysis (mandatory, highest priority)

1. Search the entire codebase (not just `.cs` files — also README, workflows, tests) for any code path that:
   - Accepts, stores, or forwards a private key, seed, or mnemonic (`Account`, `PrivateKey`, `Seed`, `Mnemonic`, `SecretKey`, `Sign(` call sites).
   - Logs (`ILogger`, `Console`, `Debug.WriteLine`) any request/response data, headers, exceptions, or objects that could directly or transitively contain key material.
   - Serializes or reflects over objects that might contain a private key (e.g., exception `ToString()`, model binding, JSON serialization of an `Account`).
2. For every logging call gated by an `Options.Debug` flag (or equivalent), determine exactly what is logged and whether it could ever include key material, and whether the *default* value of that flag is safe for production.
3. Confirm that the **verification path** (server side) never needs, receives, or handles a private key — only public keys/addresses and signatures. Explicitly state this in the report as a positive finding if true.
4. Confirm that the **signing helper** (`ARC14.CreateHeader(Account, ...)`, client-side) does not itself log, cache, retain, or transmit the `Account` (which carries the private key) anywhere beyond the single local `Sign()` call. Check for accidental capture in closures, static fields, or exception handlers.
5. Check for any static/shared mutable state (e.g. `private static` fields) that could leak data across requests/tenants in a multi-user hosting scenario.

### Phase 2 — Authentication & authorization logic correctness

1. Trace every code path in `HandleAuthenticateWithRequestAsync` (V1 and V2) from raw header to `AuthenticateResult`. For each `throw new UnauthorizedException(...)`, confirm the check is complete and cannot be bypassed by a malformed or adversarial input.
2. Signature verification: confirm single-sig and multi-sig (`MSig`) verification cannot be tricked by empty signatures, duplicate keys, signature malleability, or wrong-message signing (i.e., confirm `BytesToSign()` binds to the exact transaction that was validated, including network/genesis hash and note/realm).
3. Multisig threshold logic: verify threshold and address-derivation (`MultisigAddress`) matches the real Algorand multisig address algorithm, and that an attacker cannot satisfy a threshold with fewer distinct valid signers than required.
4. Replay protection: assess `CheckExpiration`, `FirstValid`/`LastValid`, block-time estimation logic (including the cached `t`/`block` static fields) for staleness, clock-skew, and replay windows. Consider: can a captured header be replayed indefinitely if `CheckExpiration=false` (the documented default)? Is this default appropriately called out as a risk to integrators?
5. Realm/domain-separation checks: confirm the `Realm`/`Realms` (note field) check cannot be bypassed (e.g., null `Note`, encoding mismatches, empty realm list treated as "allow all").
6. Rekeying / `AuthAddress` logic: assess whether a rekeyed account is correctly resolved via the configured algod node, and — critically — what happens when the algod call **fails** (timeout, 5xx, network partition). Determine whether failure modes fail open (authenticate anyway) or fail closed (reject), and flag any fail-open behavior as a high-severity finding.
7. `EmptySuccessOnFailure` option: assess the blast radius of this design (issuing an authenticated ticket with an empty identity on auth failure) and whether it's clearly documented as dangerous, off by default, and safely composable with `[Authorize]` policies downstream.
8. `AllowEmptyAccounts` (V2): assess whether treating an unknown/zero-balance account as valid (with `AuthAddr == Sender`, i.e. assuming no rekey) can be abused, especially combined with #6's failure-mode question.
9. Network confusion: confirm a signed transaction for network A cannot be replayed/accepted against a service configured for network B (genesis hash pinning), across both V1 (single network) and V2 (multi-network dictionary) designs.

### Phase 3 — Input handling & robustness

1. Untrusted input parsing: `Convert.FromBase64String`, MsgPack decoding (`DecodeFromMsgPack`) of attacker-controlled bytes — assess exception handling, DoS potential (oversized headers, malformed msgpack, decompression-bomb-style structures), and information disclosure in error responses.
2. Confirm no unhandled exception path leaks stack traces, internal paths, or configuration (e.g., algod tokens) to the HTTP response.
3. Header parsing edge cases (case sensitivity, `bearer`/`SigTx` prefix handling, whitespace-to-`+` substitution in V2) — confirm no smuggling/bypass vector.

### Phase 4 — Configuration & secrets handling

1. `AlgodServerToken` / `AlgodConfig.Token` — confirm these algod API tokens (not user private keys, but still secrets) are only ever sent to the configured algod `Server` over the configured transport, never logged, and the README does not encourage committing them to source control or client-side config.
2. Confirm no hard-coded secrets, tokens, or private keys exist anywhere in the repository (source, tests, workflows, git history if accessible).
3. Review `.github/workflows/*` for supply-chain risks to the published NuGet package (e.g., who can trigger a release, are secrets scoped minimally, is the package signed).

### Phase 5 — Dependency & supply-chain review

1. Enumerate all NuGet dependencies and versions in `AlgorandAuthentication.csproj`. Check each for known CVEs / security advisories as of the audit date.
2. Assess whether version pinning is precise enough to avoid an unreviewed transitive upgrade silently entering the trust boundary.

### Phase 6 — Test coverage assessment

1. Assess whether `TestAlgorandAuthentication/*` covers the negative/adversarial cases identified in Phases 1–3 (bad signatures, wrong network, expired tx, malformed msgpack, threshold bypass attempts, empty-account handling).
2. Identify concrete missing test cases and, where feasible, note the exact scenario a future test should cover (not required to write the tests unless asked).

---

## Severity rubric

Rate every finding using this scale (align with CVSS-like reasoning but keep it simple):

| Severity | Definition |
|---|---|
| **Critical** | Leaks or could leak private key/seed material, or allows full authentication bypass (impersonate any address without a valid signature). |
| **High** | Allows authentication bypass under specific conditions (e.g., fail-open on algod outage, replay of expired tx), or other serious integrity failure. |
| **Medium** | Weakens a security property but requires unusual configuration or additional attacker capability to exploit (e.g., unsafe defaults that are documented, DoS via malformed input). |
| **Low** | Defense-in-depth / hardening gap, unlikely to be independently exploitable. |
| **Informational** | Best-practice deviation, documentation gap, or positive control worth recording. |

---

## Deliverables

Each audit run produces **two artifacts**:

### 1. A dated audit report

- Location: `audits/reports/`
- Filename pattern (mandatory, for correct chronological sorting):
  `YYYY-MM-DD_<auditor-slug>_arc14-audit.md`
  - `YYYY-MM-DD` = the date the audit was performed (ISO-8601, so filenames sort correctly).
  - `<auditor-slug>` = a lowercase, hyphenated identifier of the model/auditor that performed the review, e.g. `claude-sonnet-5`, `claude-opus-4-8`, `gpt-5-1`, `human-jsmith`. **Always include this** so readers know which model/person produced a given report, and so audit quality can be compared across model versions over time.
  - If more than one audit happens on the same calendar day by the same auditor, append `_2`, `_3`, etc. before `.md`.
  - Example: `audits/reports/2026-07-19_claude-sonnet-5_arc14-audit.md`
- The report must contain, in this order:
  1. **Header**: audit date, auditor/model identifier, commit hash audited (`git rev-parse HEAD`), package version audited (from the `.csproj`), scope statement.
  2. **Executive summary**: 3–8 sentences, written for a non-technical stakeholder, stating the bottom-line answer to *"is this safe to use, and can it leak private keys?"*
  3. **Findings table**: ID, title, severity, file:line, status (New / Recurring / Fixed-since-last-audit / Regressed).
  4. **Detailed findings**: one subsection per finding — description, affected code (file + line numbers), proof-of-concept or reasoning for exploitability, recommended remediation.
  5. **Positive findings**: security controls that are correctly implemented — do not only report problems; a professional audit documents what is done right and why it's sound (e.g., "server-side verification never touches private key material — confirmed by code trace").
  6. **Comparison to previous audit** (if a prior report exists in `audits/reports/`): explicitly state which prior findings are fixed, which persist, and whether any regression was introduced.
  7. **Dependency/CVE review** results.
  8. **Scope, assumptions, and limitations.**
  9. **Appendix**: full list of files reviewed.

### 2. An updated risk registry

- Location: `audits/RISKS.md`
- This is a **living document**, not a per-audit snapshot. Every audit run must:
  - Add newly discovered risks with a new `RISK-NNN` ID (never reuse or renumber IDs).
  - Update the status of existing risks (`Open`, `Mitigated`, `Accepted`, `Closed`) based on current code state — re-verify each open risk against the current code, don't just copy old status forward.
  - Update the `Last Verified` date for every risk touched during the audit, and add an entry to that risk's history log.
  - Never delete a risk row, even once closed — keep history for auditability. Closed risks remain with status `Closed` and the closing audit's date/report link.

---

## Trigger phrase for re-audits

When the repository owner writes **`do new audit`** (case-insensitive, anywhere in a message), the assistant must:

1. Re-read this instructions file (`audits/AUDITS-INSTRUCTIONS.md`) and the current `audits/RISKS.md`.
2. Re-review the current state of the in-scope source files (do not rely on memory of a previous audit — the code may have changed).
3. Identify the most recent existing report in `audits/reports/` (highest date, then check for `_2`/`_3` suffixes) to diff against for the "comparison to previous audit" section.
4. Perform the full methodology in this document against the **current** code.
5. Write a new report file following the naming convention above, dated with **today's actual date** and tagged with the auditor/model identifier actually performing the work (do not reuse a prior auditor's name).
6. Update `audits/RISKS.md` in place per the rules above.
7. Summarize the outcome back to the user: what's new, what's fixed, what regressed, and the overall safety verdict.

Do not ask the user clarifying questions before proceeding — `do new audit` is a complete, self-sufficient instruction to run the full process end to end.
