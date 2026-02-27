# SudoWP Radar — Development Handoff Document
> Maintained by Claude. Updated at the end of every chat session.
> Claude Code reads this file before starting any session. Claude (claude.ai) updates it at the end of every session.

---

## Project Identity

| Field | Value |
|---|---|
| Plugin Name | SudoWP Radar |
| Plugin Slug | `sudowp-radar` |
| Local Repo Dir | `~/plugins/sudowp-radar/` |
| GitHub Repo | `https://github.com/sudo-wp/sudowp-radar` (public) |
| Namespace | `SudoWP\Radar` |
| Author | SudoWP — https://sudowp.com |
| Spec File | `RADAR-MVP-SPEC.md` (lives in repo root alongside this file) |
| Min WP | 6.9 |
| Min PHP | 8.1 |

---

## How This Workflow Operates

1. Claude Code reads `HANDOFF.md` and `RADAR-MVP-SPEC.md` at the start of every session.
2. Claude Code executes the milestone described in the Current Milestone section.
3. When the milestone is complete, Claude Code runs the GitHub sync and health check routine (see below).
4. Claude Code updates the Completed Milestones log, Current State table, and Session Log in this file.
5. Claude Code writes the Next Session Prompt at the bottom of this file.
6. G. pastes the Next Session Prompt into a new Claude Code session to continue.
7. claude.ai (this chat) updates this file and writes the Next Session Prompt when wrapping up planning sessions.

**Never skip updating this file. Never skip the GitHub sync. Both are mandatory at the end of every session.**

---

## GitHub Sync and Health Check Routine

This routine runs at the end of every Claude Code session, after all milestone work is complete and `HANDOFF.md` has been updated.

### Step 1 — Stage and commit all changes

```bash
cd ~/plugins/sudowp-radar
git add -A
git status
```

Review the staged files. Confirm no sensitive files (.env, credentials, debug logs) are included. Then commit with a structured message:

```bash
git commit -m "M[N]: [brief description]

- [bullet: what was built or changed]
- [bullet: what was fixed or verified]
- HANDOFF.md updated"
```

Example for M1:
```bash
git commit -m "M1: Initial plugin build

- All 9 PHP class files implemented and linted
- Asset stubs created (radar-admin.css, radar-admin.js)
- readme.txt and .pot file created
- HANDOFF.md updated with M1 completion status"
```

### Step 2 — Push to GitHub

```bash
git push origin main
```

If the push is rejected (non-fast-forward), do not force push. Stop and report the conflict to G. before proceeding.

### Step 3 — Health check: verify local and remote are in sync

Run these checks in order. All must pass before the session is considered complete.

```bash
# Fetch remote state without merging
git fetch origin

# Compare local HEAD to remote HEAD — output must be empty (no diff)
git diff HEAD origin/main

# Confirm commit counts match
LOCAL_COUNT=$(git rev-list --count HEAD)
REMOTE_COUNT=$(git rev-list --count origin/main)
echo "Local commits:  $LOCAL_COUNT"
echo "Remote commits: $REMOTE_COUNT"

# Confirm last commit hash matches on both sides
LOCAL_HASH=$(git rev-parse HEAD)
REMOTE_HASH=$(git rev-parse origin/main)
echo "Local HEAD:  $LOCAL_HASH"
echo "Remote HEAD: $REMOTE_HASH"

if [ "$LOCAL_HASH" = "$REMOTE_HASH" ]; then
    echo "SYNC OK: local and remote are identical"
else
    echo "SYNC FAIL: mismatch detected — do not end session until resolved"
fi
```

### Step 4 — Report sync status in session summary

At the end of every Claude Code session report, include a sync block:

```
GitHub Sync:
  Commit: M1: Initial plugin build
  Hash:   abc1234
  Status: SYNC OK — local and remote identical
```

If sync fails, report the failure and the diff before ending the session.

---

## Completed Milestones

### M0 — Architecture and Spec (claude.ai — 2026-02-27)
**Status:** COMPLETE

**What was done:**
- Full competitive analysis of Abilities Scout by Lax Mariappan vs SudoWP positioning.
- Confirmed WP 6.9 Abilities API structure: `WP_Ability`, `WP_Abilities_Registry`, `wp_register_ability()`, permission callbacks, JSON Schema I/O, REST exposure via `show_in_rest`.
- Designed SudoWP Radar concept: post-registration runtime auditor complementing Abilities Scout's pre-registration static analysis.
- Defined 5 core vulnerability rule classes for MVP: open/weak permission, no/loose input schema, REST overexposure, orphaned callback, namespace collision.
- Designed premium extension architecture via 4 WordPress filters — no core edits needed for premium layer.
- Wrote complete `RADAR-MVP-SPEC.md` with full class code, directory structure, security checklist, uninstall routine, Claude Code build instructions, and GitHub sync routine.
- Confirmed plugin slug: `sudowp-radar`. GitHub repo connected to local repo.

**Key decisions made:**
- Zero external dependencies (no Composer).
- Custom capability `radar_run_audit` — never tied to a role directly.
- Last audit report stored in user meta, not global options.
- Rate limiting via 30-second transient per user on AJAX.
- `sudowp-radar/audit` ability registered via WP Abilities API for MCP agent use — REST-disabled by default.
- Dataset class stubbed with 4 filters so premium layer plugs in without touching free plugin.
- PHP 8.1+ with `declare(strict_types=1)` throughout.
- GitHub sync and health check routine added as mandatory end-of-session step.

**Files produced:**
- `RADAR-MVP-SPEC.md` — Full plugin spec for Claude Code.
- `HANDOFF.md` — This file.

---

## Current Milestone

### M1 — Initial Build (Claude Code Session 1)
**Status:** NOT STARTED

**Goal:** Build the complete MVP plugin directory from `RADAR-MVP-SPEC.md` and push the initial commit to GitHub.

**Acceptance criteria:**
- [ ] Directory structure created exactly as specified in spec.
- [ ] All 9 PHP class files implemented with no syntax errors (`php -l` passes on each).
- [ ] `uninstall.php` implemented.
- [ ] `readme.txt` created in WordPress.org format.
- [ ] `assets/css/radar-admin.css` — minimal styles for admin page (severity badges, findings list, risk score display).
- [ ] `assets/js/radar-admin.js` — triggers AJAX audit call, renders findings sorted by severity, shows summary risk score.
- [ ] `languages/sudowp-radar.pot` — empty pot file with correct headers.
- [ ] `.gitignore` created (ignore `node_modules/`, `.DS_Store`, `*.log`, `*.orig`, `.env`).
- [ ] Zero `error_log()`, `var_dump()`, or `print_r()` calls.
- [ ] Zero hardcoded English strings outside `__()` or `esc_html_e()` wrappers.
- [ ] No external HTTP calls anywhere in plugin code.
- [ ] GitHub sync routine completed — local and remote confirmed identical.
- [ ] `HANDOFF.md` updated with M1 completion status and sync report before session ends.

**What Claude Code must NOT do:**
- Do not add Composer or any external dependencies.
- Do not modify `RADAR-MVP-SPEC.md` — it is a reference document, not a build artifact.
- Do not register any `wp_ajax_nopriv_` hooks.
- Do not store audit findings in `wp_options` or any global option. User meta only.
- Do not expose `sudowp-radar/audit` via REST (`show_in_rest` must remain `false`).
- Do not force push to GitHub under any circumstances.

---

## Current State

### Plugin Build Status
| Component | Status | Notes |
|---|---|---|
| Directory structure | Not started | Awaiting M1 |
| `sudowp-radar.php` (main file) | Not started | |
| `class-radar-loader.php` | Not started | |
| `class-radar-capabilities.php` | Not started | |
| `class-radar-finding.php` | Not started | |
| `class-radar-scanner.php` | Not started | |
| `class-radar-rule-engine.php` | Not started | |
| `class-radar-dataset.php` | Not started | |
| `class-radar-auditor.php` | Not started | |
| `class-radar-report.php` | Not started | |
| `class-radar-ajax.php` | Not started | |
| `class-radar-abilities.php` | Not started | |
| `class-radar-admin.php` | Not started | |
| `uninstall.php` | Not started | |
| `radar-admin.css` | Not started | |
| `radar-admin.js` | Not started | |
| `readme.txt` | Not started | |
| `sudowp-radar.pot` | Not started | |
| `.gitignore` | Not started | |
| GitHub sync | Not started | Awaiting M1 completion |

### Known Open Questions (Resolve in M1)
- WP 6.9 Abilities API method name for retrieving all abilities from `WP_Abilities_Registry` must be verified at runtime — spec uses `get_all()` as the assumed method name. Claude Code must confirm or adjust before implementing `class-radar-scanner.php`.
- `WP_Ability` property names (`name`, `label`, `description`, `category`, `input_schema`, `output_schema`, `execute_callback`, `permission_callback`, `meta`) must be verified against the actual WP 6.9 source before `class-radar-scanner.php` is finalized.

### GitHub Sync Status
| Field | Value |
|---|---|
| Last sync | Never — awaiting M1 |
| Last commit hash | — |
| Sync result | — |

---

## Milestone Roadmap

| # | Milestone | Session | Status |
|---|---|---|---|
| M0 | Architecture and Spec | claude.ai | COMPLETE |
| M1 | Initial Build + first GitHub push | Claude Code 1 | NOT STARTED |
| M2 | WP 6.9 API verification and QA | Claude Code 2 | NOT STARTED |
| M3 | JS findings renderer and admin UI polish | Claude Code 3 | NOT STARTED |
| M4 | PHP unit test scaffold (WP test suite) | Claude Code 4 | NOT STARTED |
| M5 | Dataset stub integration test and premium filter docs | Claude Code 5 | NOT STARTED |
| M6 | WordPress.org submission prep | claude.ai | NOT STARTED |

---

## SudoWP Style and Constraints (Apply to All Sessions)

- Never use em dashes in any written content or code comments.
- Never use emojis anywhere.
- Technical accuracy is non-negotiable. Verify WP API method names against source before using.
- No external dependencies. Plugin must be zero-dependency.
- Security first: every public-facing surface gets a capability check and nonce before processing.
- All output in PHP templates uses `esc_html()`, `esc_attr()`, `esc_url()`, or `wp_kses()`.
- All user input is sanitized with the most specific WP sanitization function available.
- Strings are internationalised from line one.
- GitHub sync and health check is mandatory at the end of every Claude Code session.

---

## Reference Links

| Resource | URL |
|---|---|
| WP Abilities API docs | https://developer.wordpress.org/apis/abilities/ |
| WP Abilities API getting started | https://developer.wordpress.org/apis/abilities-api/getting-started/ |
| Abilities Scout (Lax Mariappan) | https://github.com/laxmariappan/abilities-scout |
| SudoWP | https://sudowp.com |
| SudoWP GitHub org | https://github.com/sudo-wp |
| SudoWP Radar GitHub repo | https://github.com/sudo-wp/sudowp-radar |
| Patchstack (vulnerability reference) | https://patchstack.com |
| WordPress security API docs | https://developer.wordpress.org/apis/security/ |

---

## Session Log

| Date | Session Type | Milestone | GitHub Sync |
|---|---|---|---|
| 2026-02-27 | claude.ai planning | M0 complete — spec, handoff, GitHub sync routine added | N/A |

---

## Next Session Prompt

> Copy everything between the triple-backtick fences and paste it as your first message to Claude Code.

```
Read HANDOFF.md and RADAR-MVP-SPEC.md from the repo root before doing anything else.

You are building the SudoWP Radar WordPress plugin.
This is Milestone 1 (M1): Initial Build.

Your job:

1. Read HANDOFF.md fully. Note the M1 acceptance criteria, the open questions in Current State, and the GitHub Sync and Health Check Routine section.
2. Read RADAR-MVP-SPEC.md fully. This is your build spec. Do not modify it.
3. Verify WP 6.9 Abilities API method names (WP_Abilities_Registry::get_all() and WP_Ability property names) by fetching https://developer.wordpress.org/apis/abilities-api/getting-started/ before writing class-radar-scanner.php. Adjust method names in the code if the docs show different names than the spec assumes.
4. Build every file listed in the M1 acceptance criteria in HANDOFF.md. Use the exact filenames — class-radar-*.php throughout.
5. Create a .gitignore in the repo root ignoring: node_modules/, .DS_Store, *.log, *.orig, .env.
6. Run php -l on every .php file you create. Fix all syntax errors before proceeding.
7. Confirm zero error_log(), var_dump(), or print_r() calls exist in any file.
8. Confirm zero hardcoded English strings exist outside __() or esc_html_e() wrappers.
9. Run the GitHub Sync and Health Check Routine from HANDOFF.md. Report the full sync output.
10. Update HANDOFF.md:
    - Mark M1 COMPLETE in Completed Milestones with a summary of what was built.
    - Update every row in the Current State build status table.
    - Fill in the GitHub Sync Status table with the commit hash and sync result.
    - Add a row to the Session Log.
    - Write the Next Session Prompt for M2.

Do not proceed to M2 work. Complete M1 fully, run the sync, update HANDOFF.md, then stop and report.
```
