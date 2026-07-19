# Publishing to NuGet

There are two workflows:

- **`release.yml`** — the normal way to cut a release. Run it manually
  from the **Actions** tab (`workflow_dispatch`), enter the new version
  (e.g. `2.1.3`), and in one run it bumps the csproj version, builds,
  tests, packs, publishes to nuget.org, then commits and tags the release.
- **`publish-nuget.yml`** — a fallback that publishes whenever a tag
  matching `v*.*.*` is pushed by a human (e.g. `git tag v2.1.3 && git push origin v2.1.3`).
  It isn't used by `release.yml` itself — see "Why one workflow, not two" below.

Both use nuget.org's **Trusted Publishing** (OIDC) exclusively — no NuGet
API key and no GitHub personal access token is stored anywhere in this repo.

## One-time setup

### 1. GitHub secret

Only one secret is needed, and it is **not** a credential — it's your
public nuget.org profile username (not your email address):

| Secret name   | Value                                                        |
|---------------|---------------------------------------------------------------|
| `NUGET_USER`  | Your nuget.org username (the account/org that owns the trusted publishing policy below) |

Add it under **Settings → Secrets and variables → Actions → New repository secret**.

### 2. Trusted Publishing policy on nuget.org

A Trusted Publishing policy is scoped to one workflow filename, and both
workflows here can publish, so add one policy per workflow:

1. Sign in to [nuget.org](https://www.nuget.org).
2. Click your username → **Trusted Publishing**.
3. Add a policy for the release workflow:
   - **Repository Owner:** `scholtz`
   - **Repository:** `AlgorandAuthenticationDotNet`
   - **Workflow File:** `release.yml`
   - **Environment:** leave empty
4. Add a second policy the same way with **Workflow File:** `publish-nuget.yml`
   (only needed if you plan to use the manual tag-push fallback).
5. Choose the policy owner (your user or an org) for both — this must be
   the same account/org that owns the `AlgorandAuthentication` package on
   nuget.org.

Policies on private repos start in a temporary 7-day active state until
the first successful publish; this repo is public so policies activate
immediately.

## Releasing a new version

1. Go to **Actions → Release → Run workflow**.
2. Enter the version, e.g. `2.1.3`.
3. The workflow: validates the version format and that the tag doesn't
   already exist, updates `<Version>`/`<AssemblyVersion>` in
   `AlgorandAuthentication/AlgorandAuthentication.csproj`, builds, runs
   the tests, packs, and publishes to nuget.org via Trusted Publishing.
   Only once the publish succeeds does it commit the version bump, create
   tag `v2.1.3`, and push both.

### Why one workflow, not two

The obvious split — a `release.yml` that bumps/commits/tags, whose tag
push then triggers `publish-nuget.yml` — doesn't work without a personal
access token: GitHub deliberately does not trigger other workflows from a
commit/tag pushed using the default `GITHUB_TOKEN`. Rather than add a PAT
just to work around that, `release.yml` does the build/test/pack/publish
itself in the same run, so the whole release only ever relies on
nuget.org Trusted Publishing.

`publish-nuget.yml` still exists and still triggers correctly for a tag
pushed manually by a person (a real user push isn't subject to that
restriction) — useful if you ever want to publish from a tag without going
through the `release.yml` version-bump flow.

### Manual alternative

```bash
# after bumping <Version>/<AssemblyVersion> in the csproj and committing
git tag v2.1.3
git push origin v2.1.3
```
