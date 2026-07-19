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

Run **release.yml** from the **Actions** tab (`workflow_dispatch`) and
enter the new version (e.g. `2.1.3`) in the `version` input. It will:

1. Update `<Version>` / `<AssemblyVersion>` in
   `AlgorandAuthentication/AlgorandAuthentication.csproj`.
2. Commit that change to the branch the workflow was run on.
3. Create tag `v2.1.3` and push both the commit and the tag.

Pushing the tag automatically triggers `publish-nuget.yml`, which builds,
tests, packs, and publishes the release. The publish workflow also
verifies the tag matches the csproj `<Version>` before packing, so a
mismatch fails fast instead of publishing the wrong version.

This job needs `contents: write` (already granted in the workflow) since
it pushes a commit and a tag using the default `GITHUB_TOKEN`.

### Manual alternative

You can still do it by hand instead of using `release.yml`:

```bash
# after bumping <Version>/<AssemblyVersion> in the csproj and committing
git tag v2.1.3
git push origin v2.1.3
```
