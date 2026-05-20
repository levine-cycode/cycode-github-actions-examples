# Cycode scan reusable workflow for GitHub Actions

A centralized Cycode scanning workflow plus a minimal consumer pattern. Each app team adds a small consumer workflow (~15 lines, inputs only) to their repo; the scan logic, summary rendering, and gating all live in one central reusable workflow that evolves independently.

## What this delivers

- **Delta scans on push and PR.** Each push triggers a Cycode scan of only the new commits since the previous tip of the branch (`github.event.before`). PRs scan the commits in the PR (`github.event.pull_request.base.sha..HEAD`). Falls back to a full scan if no base can be resolved.
- **Multiple scan types in one workflow run.** Any subset of `secret`, `sast`, `sca`, `iac`. Each scan produces a job-summary section plus a raw JSON in the run artifact.
- **Configurable gate.** Job fails when findings exceed the chosen severity threshold, or runs in report-only mode if preferred.
- **Runs on `ubuntu-latest` by default**, configurable via the `runsOn` input.

## Repo layout

```
.github/workflows/cycode-scan.yml   Centralized reusable workflow (the only thing customers reference)
.github/workflows/self-scan.yml     Self-scan of this repo (proof the workflow runs end-to-end)
examples/consumer-workflow.yml      Sample consumer workflow for app teams to copy
```

## Workflow inputs

| Input | Default | Description |
|---|---|---|
| `scanTypes` | `'["secret"]'` | **JSON-array string.** Any subset of `secret`, `sast`, `sca`, `iac`. Scans run in the listed order. |
| `severityThreshold` | `"high"` | `info` \| `low` \| `medium` \| `high` \| `critical`. Findings at or above this severity count toward the gate. |
| `blockOnFindings` | `true` | `true` fails the job on findings above the threshold; `false` scans and publishes the summary without failing. |
| `runsOn` | `"ubuntu-latest"` | Runner image label. Tested on `ubuntu-latest`; also valid: `windows-2022`, `macos-latest`, `self-hosted`. |
| `scanMode` | `""` (auto) | Leave empty for auto-detect: `push`/`pull_request` triggers run a diff scan; `workflow_dispatch`/`schedule` runs scan the full repo. Override with `"full"` or `"diff"` to force. |

**Note on `scanTypes`:** GitHub Actions reusable workflows do not support `array` as a native input type, so `scanTypes` is a JSON-array string. Wrap it in single quotes (`'["secret","sca"]'`).

## Scan behavior at a glance

| Trigger | Scan mode | What gets scanned |
|---|---|---|
| `push` | diff | Commits since `github.event.before` (previous tip of the branch) |
| `pull_request` | diff | Commits in the PR (`github.event.pull_request.base.sha..HEAD`) |
| `workflow_dispatch` | full | The entire repository working tree |
| `schedule` | full | The entire repository working tree |
| New-branch push or force-push | full (fallback) | No reachable base commit, so diff has no baseline |

## What gets published per workflow run

- A **job summary** with one section per `scanType`: severity counts (Critical / High / Medium / Low).
- A run **artifact** named `cycode-scan-results` containing the raw Cycode JSON output for every enabled scan type (`cycode-secret.json`, `cycode-sast.json`, etc.).

## Setup (one-time, per repo)

### 1. Add Cycode credentials as repository secrets

In the target repo: **Settings → Secrets and variables → Actions → New repository secret**.

Add two secrets:
- `CYCODE_CLIENT_ID`
- `CYCODE_CLIENT_SECRET`

For multiple repos in the same org, prefer **organization secrets** so the credentials are managed in one place.

### 2. Add a consumer workflow to each target repo

Copy `examples/consumer-workflow.yml` to `.github/workflows/cycode-scan.yml` in the target repo. The critical pieces:

```yaml
name: Cycode security scan

on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:

jobs:
  cycode:
    uses: levine-cycode/cycode-github-actions-examples/.github/workflows/cycode-scan.yml@v1
    with:
      scanTypes: '["secret","sca","iac","sast"]'   # any subset of: secret, sast, sca, iac
      severityThreshold: high                       # info | low | medium | high | critical
      blockOnFindings: true                         # true = fail on findings; false = report only
      # runsOn: ubuntu-latest                       # OPTIONAL — ubuntu-latest | windows-2022 | self-hosted
      # scanMode: ''                                # OPTIONAL — '' (auto) | 'diff' | 'full'
    secrets: inherit
```

`secrets: inherit` passes the caller repo's `CYCODE_CLIENT_ID` and `CYCODE_CLIENT_SECRET` into the reusable workflow without re-declaring them. If your org policy disallows `secrets: inherit`, pass them explicitly:

```yaml
    secrets:
      CYCODE_CLIENT_ID: ${{ secrets.CYCODE_CLIENT_ID }}
      CYCODE_CLIENT_SECRET: ${{ secrets.CYCODE_CLIENT_SECRET }}
```

### 3. Pinning the workflow version

In production, pin to a tag (or a SHA for stricter supply-chain controls):

```yaml
uses: levine-cycode/cycode-github-actions-examples/.github/workflows/cycode-scan.yml@v1
uses: levine-cycode/cycode-github-actions-examples/.github/workflows/cycode-scan.yml@<full-sha>
```

`@main` is fine for evaluation but means every consumer picks up changes immediately.

### 4. Cross-org consumption (only if the templates repo lives in a different GitHub org)

GitHub Actions can call a reusable workflow across repos and orgs, with two extra requirements when the templates repo is **private**:

1. **In the templates repo:** Settings → Actions → General → "Access" → choose **Accessible from repositories in the '\<org\>' organization** (same-org private) or **Accessible from repositories owned by the user account** (personal). For broader org-to-org sharing, the templates repo must be **public**, or each consumer must have explicit access.
2. **In the consumer repo's org:** Settings → Actions → General → ensure "Allow \<org\>/\<repo\>" or "Allow all actions and reusable workflows" includes the templates repo path.

For **public** templates repos, no extra wiring is needed — any repo can `uses:` them as long as the consumer's org policy permits external actions.

## Required permissions

The reusable workflow requests only `contents: read`. This is the default permission for `GITHUB_TOKEN` in most repos. If your org has set the default to `none`, add to your consumer:

```yaml
jobs:
  cycode:
    permissions:
      contents: read
    uses: ...
```

## Notes

- The reusable workflow handles `actions/checkout@v4` itself with `fetch-depth: 0`, so diff scans can resolve any reachable BASE commit. Customers do not need to add their own checkout.
- IaC scans always run in path mode regardless of `scanMode` — the Cycode CLI does not support commit-range scanning for IaC, and IaC misconfigurations apply to the current state of files regardless of when they were changed.
- `--soft-fail` is used on every scan so the JSON is always written; the gate step decides pass/fail based on the JSON content.
- If a scan errors at the CLI level (auth, network, etc.), the gate **loud-fails** rather than silently treating it as zero findings.
