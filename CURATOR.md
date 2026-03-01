# SudoWP Radar — Content Curator Log

## Purpose

This document is the central log for articles, posts, GitHub issues, and other external content evaluated for relevance to SudoWP Radar and the broader SudoWP initiative.

Content is reviewed against five criteria:
1. **Abilities API** — Changes, clarifications, or new patterns affecting how SudoWP Radar reads or audits registered abilities.
2. **WP Security Primitives** — New or updated capability checks, nonce patterns, REST permission handling that could become audit rules.
3. **Threat Intelligence** — New vulnerability classes in the WP AI, agent, or MCP attack surface.
4. **WordPress.org Policy** — Submission requirements, plugin review standards, guideline changes.
5. **Competitive Landscape** — Updates to Wordfence, Patchstack, Abilities Scout, or adjacent tools.

Items that do not meet any of the five criteria but show longer-term potential are logged in the [Future Feature Backlog](#future-feature-backlog) section.

---

## Evaluation Record

Items are logged in reverse chronological order (newest first).

---
<!--
ENTRY TEMPLATE — copy and fill for each new item:

### [YYYY-MM-DD] Title or short description
- **Source:** LinkedIn | GitHub | Make.WordPress | WordPress.org | External
- **URL:** 
- **Author:** 
- **Criteria match:** Abilities API | WP Security Primitives | Threat Intelligence | WP.org Policy | Competitive Landscape | None
- **Verdict:** Current scope | Future feature | Out of scope
- **Milestone relevance:** M1 | M2 | M3 | M4 | M5 | M6 | Post-MVP | N/A
- **Component:** Scanner | Rule_Engine | Admin UI | MCP Integration | Premium Filters | N/A
- **Summary:**
  One to three sentences. Verdict-first. What does this mean for SudoWP Radar specifically.
- **Action:**
  None | Added to HANDOFF.md | Created GitHub issue | Flagged for [brand]
-->

---

### 2026-02-04 — From Abilities to AI Agents: Introducing the WordPress MCP Adapter
- **Source:** WordPress Developer Blog
- **URL:** https://developer.wordpress.org/news/2026/02/from-abilities-to-ai-agents-introducing-the-wordpress-mcp-adapter/
- **Author:** Jonathan Bossenger (@psykro)
- **Criteria match:** Abilities API, Threat Intelligence, Competitive Landscape
- **Verdict:** Current scope + Future feature
- **Milestone relevance:** M5, Post-MVP
- **Component:** MCP Integration, Scanner, Rule_Engine
- **Summary:**
  This is the official documentation for the WordPress MCP Adapter — the bridge that maps registered Abilities to MCP tools. Three critical findings for SudoWP Radar. First, the `meta.mcp.public` flag on ability registration is a new attack surface vector: any ability with this flag set and a weak permission callback is directly callable by an AI agent via MCP, which makes the existing REST Overexposure rule (Rule 3) directly applicable and should be extended to specifically flag `meta.mcp.public: true` combined with weak permissions as its own finding. Second, the adapter exposes three meta-abilities (`mcp-adapter/discover-abilities`, `mcp-adapter/get-ability-info`, `mcp-adapter/execute-ability`) that allow agents to enumerate and call all public abilities on a site — this is an enumeration vector SudoWP Radar should be aware of when auditing sites with the adapter installed. Third, the article confirms `wp_register_ability_args` as a hookable filter that can modify registration arguments post-registration, which is a namespace collision surface Radar should monitor. The security best practices section explicitly calls out `__return_true` as dangerous for destructive operations — direct validation of SudoWP Radar Rule 1.
- **Action:** Added to HANDOFF.md — Curator Flags table. M5 dataset stub session should include an `mcp.public + weak permission` combined rule candidate.

---

### 2026-02-20 — WordPress 7.0 Beta 1
- **Source:** WordPress.org News
- **URL:** https://wordpress.org/news/2026/02/wordpress-7-0-beta-1/
- **Author:** Amy Kamala
- **Criteria match:** Abilities API, WP Security Primitives
- **Verdict:** Future feature
- **Milestone relevance:** Post-MVP
- **Component:** Scanner, Rule_Engine
- **Summary:**
  WordPress 7.0 (final release April 9, 2026) introduces two items directly relevant to SudoWP Radar's architecture. The Client Side Abilities API introduces a parallel client-side registry for abilities running in the browser — a new attack surface that the current PHP-only Scanner does not cover. The Web Client AI API (a core-level AI model interface with Abilities API integration) adds another execution path for registered abilities beyond MCP. Neither changes current MVP scope — SudoWP Radar targets the server-side registry built for WP 6.9 — but both expand the auditable surface for a future major version. The plugin's minimum WP version will need evaluation once 7.0 reaches stable.
- **Action:** None for current milestones. Logged in backlog.

---

## Future Feature Backlog

Items logged here did not fit current SudoWP Radar MVP scope but have longer-term potential. Each entry notes the most relevant SudoWP brand or product surface.

---

### 2026-02-20 — Client Side Abilities API (WordPress 7.0)
- **Source URL:** https://wordpress.org/news/2026/02/wordpress-7-0-beta-1/
- **Relevant brand/product:** SudoWP Radar (v2 scope)
- **Why it matters (future):**
  WordPress 7.0 introduces a browser-side ability registry parallel to the server-side PHP registry. A future Radar version could audit client-side ability registrations for the same vulnerability classes (open permissions, no schema, orphaned callbacks) — covering a surface that is currently invisible to any existing security tool.

### 2026-02-20 — Web Client AI API (WordPress 7.0)
- **Source URL:** https://wordpress.org/news/2026/02/wordpress-7-0-beta-1/
- **Relevant brand/product:** SudoWP Radar (v2 scope), AmIHacked.com
- **Why it matters (future):**
  WordPress 7.0 ships core-level AI model access with Abilities API integration. This creates a new execution path for registered abilities that bypasses both REST and MCP transport — worth auditing for permission and schema weaknesses in a future Radar version.

### 2026-02-04 — MCP Adapter Enumeration Surface
- **Source URL:** https://developer.wordpress.org/news/2026/02/from-abilities-to-ai-agents-introducing-the-wordpress-mcp-adapter/
- **Relevant brand/product:** SudoWP Radar (Post-MVP premium rule), AmIHacked.com
- **Why it matters (future):**
  The MCP Adapter's three meta-abilities allow any connected AI agent to enumerate all public abilities on a site. A premium Radar rule could detect when these meta-abilities are active and cross-reference exposed abilities against known-weak permission patterns, flagging sites with both the adapter installed and unguarded abilities.

---

## Curation Session Log

A lightweight index of curation sessions for traceability.

| Date | Items reviewed | Items kept | Items to HANDOFF.md | Session notes |
|------|---------------|------------|---------------------|---------------|
| 2026-03-01 | 2 | 2 | 1 | MCP Adapter post (dev blog) + WP 7.0 Beta 1 (wp.org news). MCP Adapter entry flagged to HANDOFF.md for M5. |
