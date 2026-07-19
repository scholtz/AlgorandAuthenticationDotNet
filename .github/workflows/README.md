# Publishing to NuGet

`publish-nuget.yml` builds the solution, runs the tests, and publishes
`AlgorandAuthentication` to nuget.org whenever a tag matching `v*.*.*`
(e.g. `v2.1.2`) is pushed. It can also be run manually from the
**Actions** tab (`workflow_dispatch`).

Publishing uses nuget.org's **Trusted Publishing** (OIDC) instead of a
long-lived API key: GitHub issues a short-lived, single-use token to the
workflow, which nuget.org exchanges for a NuGet API key valid for one hour.
No NuGet API key is ever stored in this repo.

## One-time setup

### 1. GitHub secret

Only one secret is needed, and it is **not** a credential — it's your
public nuget.org profile username (not your email address):

| Secret name   | Value                                                        |
|---------------|---------------------------------------------------------------|
| `NUGET_USER`  | Your nuget.org username (the account/org that owns the trusted publishing policy below) |

Add it under **Settings → Secrets and variables → Actions → New repository secret**.

### 2. Trusted Publishing policy on nuget.org

1. Sign in to [nuget.org](https://www.nuget.org).
2. Click your username → **Trusted Publishing**.
3. Add a new policy with:
   - **Repository Owner:** `scholtz`
   - **Repository:** `AlgorandAuthenticationDotNet`
   - **Workflow File:** `publish-nuget.yml` (file name only, not the `.github/workflows/` path)
   - **Environment:** leave empty (this workflow doesn't use a GitHub Actions environment)
4. Choose the policy owner (your user or an org) — this must be the same
   account/org that owns the `AlgorandAuthentication` package on nuget.org.

Policies on private repos start in a temporary 7-day active state until
the first successful publish; this repo is public so the policy activates
immediately.

## Releasing a new version

1. Bump `<Version>` / `<AssemblyVersion>` in `AlgorandAuthentication/AlgorandAuthentication.csproj`.
2. Commit and push to `main`.
3. Tag the commit and push the tag, e.g.:

   ```bash
   git tag v2.1.2
   git push origin v2.1.2
   ```

The workflow verifies the tag (`v2.1.2`) matches the csproj `<Version>`
(`2.1.2`) before packing, so a mismatched tag fails fast instead of
publishing the wrong version.
