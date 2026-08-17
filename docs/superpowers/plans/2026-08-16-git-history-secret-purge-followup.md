# Runbook: Purging Leaked Secrets from Git History

> **NOT part of `docs/superpowers/plans/2026-08-16-secrets-in-git-remediation.md`'s
> automated execution.** That plan fixes the working tree, `.gitignore`, CI, and
> rotates every rotatable secret. This document is the deferred git-history
> rewrite it deliberately does not run. **Schedule and run this separately,
> with the human maintainer's explicit go-ahead** — it force-pushes rewritten
> history on every branch and requires every collaborator to re-clone or hard-reset.

This is an operational runbook, not a TDD implementation plan — there is no
code or test involved, only git history surgery and a coordination checklist.

## Why this is still needed after the other plan lands

`docs/superpowers/plans/2026-08-16-secrets-in-git-remediation.md` removes every
known-compromised secret literal from the **current working tree**, untracks
`.rocketvault.yaml`, and adds a CI gate so none of it comes back. None of that
touches history that already exists. Every commit that ever added or modified
one of the files below still has the old blob content, byte for byte, in every
clone, fork, and mirror of this repository — including this one. Anyone with
read access to any of those can run `git log -p -- .rocketvault.yaml` (or
simply `git show <old-sha>:.rocketvault.yaml`) and recover the exact secret
values, rotation or no rotation. Rotation makes the *specific rotated* values
(the new `master_key`, the new `bootstrap_token`) safe going forward; it does
nothing about the values that were already public before rotation, which
remain public in history forever unless the history itself is rewritten.

This is exactly the gap the 2026-03-07 incident's own fix left open — its own
writeup recommended `git filter-repo` as "OPERATOR ACTION REQUIRED" step 2, and
that step was never actually run (verified: `git log --all --diff-filter=A
--name-only -- '.password-manager.yaml' '.password-manager-production.yaml'
'.password-manager-staging.yaml' '.password-manager-test.yaml'` still finds
every one of those additions in this repository's current history).

## Scope: every file and pattern to purge

### Whole-file removal (files that only ever held secrets — remove entirely, all versions)

Verified via `git log --all --diff-filter=A --name-only` against each name:

| Path | First added | Notes |
|---|---|---|
| `.password-manager.yaml` | `a20296e` (Initial commit) | pre-rename production config |
| `.password-manager-production.yaml` | `f6d3e22` | |
| `.password-manager-staging.yaml` | `01c0fce` | |
| `.password-manager-test.yaml` | `e3f00ef`, content confirmed present at `cb93bc9^` (removed by plain `git rm` in `cb93bc9`, 2026-03-07 — the blob survives in every ancestor of that commit) | contains a *third* generation of secrets, distinct from the ones in `.rocketvault.yaml` — see "Secret values in scope" below |
| `.rocketvault.yaml` | `5dd5490` (rename commit) | the file this whole finding is about |
| `.rocketvault-production.yaml` | never actually added under this name (checked; the 2026-03-07 incident doc anticipated it, but the real historical name was always the `.password-manager-*` prefix pre-rename) | included defensively — a no-op if genuinely absent |
| `.rocketvault-staging.yaml` | same — included defensively | |
| `.rocketvault-test.yaml` | same — included defensively | |

### Text redaction (files with real ongoing content — keep the file, scrub the secret bytes from every historical version)

Every other file identified by the full-repo grep sweep (see
`docs/superpowers/specs/2026-08-16-secrets-in-git-remediation-design.md`,
§"Blast radius") that ever contained one of the values below, in any commit,
not just the current tip: `doc/README_ADMIN_SETUP.md`,
`doc/README_ADMIN_SETUP.html`, `docs/testing-guide.md`, `docs/usage-guide.md`,
`docs/usage-guide.html`, `docs/rocketvault-architecture.html`,
`scripts/capture-manual-examples.sh`, `internal/backup/backup_test.go`,
`scripts/README.md`, plus any earlier revision of any file, anywhere in
history, that happens to also contain one of these exact byte strings (the
`--replace-text` pass below is content-based, not path-based, so it does not
require enumerating every historical path — any blob containing the string is
scrubbed, in every file, in every commit, automatically).

### Secret values in scope

Three generations of leaked secrets, all must be purged:

1. **Current** (`.rocketvault.yaml`, rotated by the other plan but still in
   history pre-rotation):
   - `master_key`: `***SECRET-REMOVED-2026-08-17***`
   - `jwt_secret`: `***SECRET-REMOVED-2026-08-17***`
   - `bootstrap_token`: `***SECRET-REMOVED-2026-08-17***`
2. **Older** (`.password-manager-test.yaml`, removed from the working tree in
   `cb93bc9` but still duplicated in `scripts/README.md` before that plan's
   fix, and present in every ancestor commit that has the file):
   - `master_key`: `***SECRET-REMOVED-2026-08-17***`
   - `jwt_secret`: `***SECRET-REMOVED-2026-08-17***`
   - `bootstrap_token`: `***SECRET-REMOVED-2026-08-17***`
3. **`hsm.pin`**: `1234` — deliberately **not** included in the redaction list
   below. It is a 4-digit numeric string with no distinguishing structure;
   `--replace-text` on a bare `1234` would corrupt unrelated historical content
   (port numbers, list indices, arbitrary numeric literals) throughout the
   repository. `hsm.pin` is rotated via `docs/runbooks/hsm-pin-rotation.md`
   (real token state, not a config value) — history exposure of a since-rotated
   4-digit PIN for a token that no longer uses it is accepted residual risk,
   not purged here.

## Prerequisites

- `git-filter-repo` installed: `pip install git-filter-repo` (or `brew install
  git-filter-repo` / distro package — **not** the older `git filter-branch`,
  which this repo's own 2026-03-07 incident doc already correctly avoided).
- A fresh **mirror clone**, never the working directory anyone is actively
  developing in:
  ```bash
  git clone --mirror <remote-url> rocketvault-history-purge.git
  cd rocketvault-history-purge.git
  ```
- A full backup of that mirror clone, made *before* running filter-repo, kept
  somewhere outside the repository itself:
  ```bash
  cp -a . ../rocketvault-history-purge-BACKUP-$(date +%Y%m%d).git
  ```

## Step 1: Build the replacement-text file

Create `replacements.txt` (outside the repo, e.g. in this machine's scratch
directory — it contains the secrets being purged, so it must never itself be
committed anywhere):

```
***SECRET-REMOVED-2026-08-17***==>***SECRET-REMOVED-2026-08-16***
***SECRET-REMOVED-2026-08-17***==>***SECRET-REMOVED-2026-08-16***
***SECRET-REMOVED-2026-08-17***==>***SECRET-REMOVED-2026-08-16***
***SECRET-REMOVED-2026-08-17***==>***SECRET-REMOVED-2026-08-16***
***SECRET-REMOVED-2026-08-17***==>***SECRET-REMOVED-2026-08-16***
***SECRET-REMOVED-2026-08-17***==>***SECRET-REMOVED-2026-08-16***
```

(`git-filter-repo`'s `--replace-text` format is `literal-string==>replacement`
per line, applied to every blob in history. These are exact literal strings,
not regexes — no escaping needed even though several contain `/` and `+`.)

## Step 2: Run `git-filter-repo`

From inside the fresh mirror clone:

```bash
git filter-repo --force \
  --path .password-manager.yaml \
  --path .password-manager-production.yaml \
  --path .password-manager-staging.yaml \
  --path .password-manager-test.yaml \
  --path .rocketvault.yaml \
  --path .rocketvault-production.yaml \
  --path .rocketvault-staging.yaml \
  --path .rocketvault-test.yaml \
  --invert-paths \
  --replace-text replacements.txt
```

This does both passes in one rewrite (recommended — two separate `filter-repo`
runs each rewrite every commit hash a second time, which is strictly worse for
collaborators reconciling their clones). `--invert-paths` with `--path` means
"remove these paths entirely, keep everything else"; `--replace-text` then
additionally scrubs the six secret strings from whatever blob content remains,
anywhere they appear.

## Step 3: Verify the purge

```bash
# No commit anywhere should still add these files.
git log --all --diff-filter=A --name-only | grep -E '\.password-manager|\.rocketvault.*\.yaml$'
# Expected: no output.

# No blob anywhere should still contain any of the six values.
git rev-list --all | while read -r commit; do
  git grep -lF \
    -e '***SECRET-REMOVED-2026-08-17***' \
    -e '***SECRET-REMOVED-2026-08-17***' \
    -e '***SECRET-REMOVED-2026-08-17***' \
    -e '***SECRET-REMOVED-2026-08-17***' \
    -e '***SECRET-REMOVED-2026-08-17***' \
    -e '***SECRET-REMOVED-2026-08-17***' \
    "$commit" 2>/dev/null && echo "STILL PRESENT in $commit"
done
# Expected: no "STILL PRESENT" lines. This walks every commit, so it is slow
# on a large repo — acceptable for a one-time verification.
```

Do not proceed to Step 4 until both checks are clean.

## Step 4: Coordination checklist (complete every item, in order, before force-pushing)

- [ ] Announce a maintenance window to every collaborator with push access or
      an open local clone. State the exact time the force-push will happen and
      that all local branches diverge from that point.
- [ ] Confirm every collaborator has pushed or otherwise backed up any local
      work-in-progress they care about (open branches, stashes, unpushed
      commits). Anything not pushed before the rewrite is not recoverable
      through the normal `git fetch && reset` recovery path below.
- [ ] Confirm all open pull/merge requests are either merged, closed, or their
      authors are aware their branch's history is about to be invalidated.
- [ ] Confirm the backup mirror from the Prerequisites section exists and is
      stored somewhere outside this repository (a separate disk, not just a
      separate directory on the same machine).
- [ ] Re-run Step 3's verification one more time immediately before pushing —
      confirm nothing changed between verification and push.
- [ ] Force-push every branch and tag from the rewritten mirror:
      ```bash
      git push --force --all origin
      git push --force --tags origin
      ```
- [ ] Notify every collaborator that the force-push is complete and it is now
      safe to run their recovery step.
- [ ] Each collaborator recovers their own local clone — either:
      - **Simplest, always safe:** delete the local clone entirely and
        `git clone` fresh, or
      - **Keeps local uncommitted changes:** for each branch they track,
        ```bash
        git fetch origin
        git reset --hard origin/<branch>
        git reflog expire --expire=now --all
        git gc --prune=now --aggressive
        ```
        The `reflog expire`/`gc` steps matter — without them, the old
        (secret-containing) commits remain locally reachable via reflog even
        after `reset --hard`.
- [ ] Confirm CI still runs green on the rewritten `main`/`v-4.0.0` — commit
      SHAs have all changed, so anything pinned to a specific SHA (deploy
      configs, submodule references, cached CI artifacts keyed by commit)
      needs re-pinning.
- [ ] Audit for forks and mirrors outside this coordination (GitHub forks,
      local clones on machines not covered by the announcement, backup
      systems that snapshot `.git` directories). Each one still has the full
      pre-rewrite history with the original secrets and is not fixed by this
      procedure — document which ones are known to exist and whether they can
      be deleted, and treat any that cannot be reached as permanent residual
      exposure, same as the values already accepted as compromised.
- [ ] Update `.claude/known-bugs.md` § B10 (or whatever entry number the
      companion plan landed under) with the date this purge actually ran, so
      the "remaining, tracked separately" note there stops being open.

## What this does not fix

- **Forks and mirrors not under this coordination.** There is no way to force
  a fork to rewrite its own history; the best available action is asking known
  fork owners to re-fork after this runs, and accepting that any fork nobody
  is aware of remains a permanent exposure of the pre-rotation secret values.
- **`hsm.pin`**, deliberately excluded from the `--replace-text` list above
  (see "Secret values in scope" item 3).
- **Any secret value not on the list above.** If a future audit finds another
  duplicated literal this sweep missed, it needs its own `--replace-text`
  entry and its own re-run of this whole procedure — a partial purge that
  leaves one value behind provides close to zero of the intended benefit,
  since anyone who has the pre-purge mirror still has everything.
