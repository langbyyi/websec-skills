---
name: source-code-exposure
description: >-
  Source control and artifact exposure (.git, .svn, .hg, backups, .env). Use when recon finds VCS paths, 403 on hidden dirs, or backup/config leaks during authorized testing.
---

# SKILL: Insecure Source Code Management

> **AI LOAD INSTRUCTION**: This skill covers detection and recovery of exposed version-control metadata, common backup artifacts, and related misconfigurations. Use only in **authorized** assessments. Treat recovered credentials and URLs as sensitive; do not exfiltrate real data beyond scope. For broad discovery workflow, cross-load [recon-for-sec](../recon-and-methodology/SKILL.md) and [recon-and-methodology](../recon-and-methodology/SKILL.md) when those skills exist in the workspace.

## QUICK START

High-value paths to probe first (GET or HEAD, respect rate limits):

```http
/.git/HEAD
/.git/config
/.svn/entries
/.svn/wc.db
/.hg/requires
/.bzr/README
/.DS_Store
/.env
```

**Routing hint**: Quick-scan these paths; for a complete reconnaissance workflow, load methodology from `recon-for-sec` and `recon-and-methodology` skills first.

---

## 1. GIT EXPOSURE

### Detection

- **`/.git/HEAD`** — valid repo often returns plain text like:

```text
ref: refs/heads/main
```

- **`/.git/config`** — may expose `remote.origin.url`, user identity, or embedded credentials.
- **`/.git/index`**, **`/.git/objects/`** — partial object store access enables reconstruction with the right tools.

### 403 vs 404

- **`404`** — path likely absent or fully blocked at the edge.
- **`403` on `/.git/`** — directory may **exist** but listing is denied; still try direct file URLs:

```http
/.git/HEAD
/.git/config
/.git/logs/HEAD
/.git/refs/heads/main
```

A **403 on the directory** plus **200 on `HEAD`** strongly indicates exposure.

### Recovery tools (open source)

- **`arthaud/git-dumper`** — dumps reachable `.git` tree when individual files are fetchable.
- **`internetwache/GitTools`** — Dumper, Extractor, Finder modules for partial/corrupt dumps.
- **`WangYihang/GitHacker`** — alternative recovery when standard dumpers miss edge cases.

### Key files to prioritize

| Path | Why it matters |
|------|----------------|
| `.git/config` | Remotes, credentials, hooks paths |
| `.git/logs/HEAD` | Commit history, reflog-style leakage |
| `.git/refs/heads/*` | Branch tips, commit SHAs |
| `.git/packed-refs` | Packed branch/tag refs |
| `.git/objects/**` | Object blobs for reconstruction |

---

## 2. SVN EXPOSURE

### Detection

- **SVN before 1.7**: **`/.svn/entries`** — XML or text metadata listing paths and revisions.
- **SVN ≥ 1.7**: **`/.svn/wc.db`** — SQLite working copy database (`PRAGMA table_info` after download).

Example probe:

```http
GET /.svn/entries HTTP/1.1
GET /.svn/wc.db HTTP/1.1
```

### Recovery

- **`anantshri/svn-extractor`** — automated extraction from exposed `.svn`.
- **Manual**: download `wc.db`, query with `sqlite3` for file paths and checksums, then request **`/.svn/pristine/`** blobs if exposed.

---

## 3. MERCURIAL EXPOSURE

### Detection

- **`/.hg/requires`** — small text file listing repository features; confirms Mercurial metadata.

```http
GET /.hg/requires HTTP/1.1
GET /.hg/store/ HTTP/1.1
```

### Recovery

- **`sahildhar/mercurial_source_code_dumper`** — dumps repository when store paths are reachable.

---

## 4. OTHER LEAKS

### Bazaar (Bzr)

- Probe **`/.bzr/README`** and **`/.bzr/branch-format`** for Bazaar metadata.

### macOS `.DS_Store`

- **`/.DS_Store`** can encode directory and filename listings.
- Tools: **`gehaxelt/ds-store`**, **`lijiejie/ds_store_exp`** — parse `.DS_Store` offline.

### Backup and config artifacts

Probe (adjust for app root and naming conventions):

```text
/.env
/backup.zip
/backup.tar.gz
/wwwroot.rar
/backup.sql
/config.php.bak
/.config.php.swp
```

### Web server misconfiguration signal (example: NGINX)

- **`location /.git { deny all; }`** — may return **403** for `/.git/` while still allowing or denying specific subpaths depending on rules.
- **403 on a protected location** can **confirm the route exists**; always distinguish from **404** on non-existent paths.

---

## DECISION TREE

1. **Probe `/.git/HEAD`** → `ref: refs/heads/` pattern? → run **git-dumper / GitTools / GitHacker**; review `config` and `logs/HEAD` for secrets.
2. **Else probe `/.svn/wc.db` or `entries`** → success? → **svn-extractor** or manual `wc.db` + pristine recovery.
3. **Else probe `/.hg/requires`** → success? → **mercurial dumper**.
4. **Else probe `/.bzr/README`** → Bazaar tooling or manual path walk.
5. **Parallel**: fetch **`/.DS_Store`**, **`/.env`**, common **backup extensions** on app root and parent paths.
6. **Interpret status codes**: **403 on directory** + **200 on specific files** → treat as **high priority** for file-by-file extraction.

---

## TESTING CHECKLIST

- [ ] Test .git exposure: probe `/.git/HEAD`, `/.git/config`, `/.git/logs/HEAD`
- [ ] Distinguish 403 (directory blocked but may exist) from 404 (absent); try direct file URLs
- [ ] Test .svn exposure: `/.svn/entries` (pre-1.7) and `/.svn/wc.db` (1.7+)
- [ ] Test .hg exposure: `/.hg/requires` and `/.hg/store/`
- [ ] Test .bzr exposure: `/.bzr/README` and `/.bzr/branch-format`
- [ ] Test .DS_Store exposure for directory listing disclosure
- [ ] Test .env and config file exposure: `.env`, `config.json`, `config.yaml`, `credentials.json`
- [ ] Test backup file patterns: `.bak`, `.sql`, `.zip`, `.tar.gz`, `.swp`, `~` extensions
- [ ] Test API documentation exposure: swagger-ui.html, api-docs, graphql, phpinfo.php
- [ ] Test debug endpoints: /debug/, /server-status, /nginx_status
- [ ] If .git confirmed: run git-dumper/GitTools/GitHacker for repository reconstruction
- [ ] If .svn confirmed: run svn-extractor or download wc.db for SQLite analysis
- [ ] Review recovered config files and commit history for hardcoded secrets and credentials

## MCP TOOLS

| Tool | Use Case |
|------|----------|
| `http_framework_test` | Send crafted requests to probe .git/HEAD, .svn/entries, .hg/requires and other VCS paths |
| `http_repeater` | Replay requests to verify 403 vs 200 responses and test directory-level access controls |
| `browser_agent_inspect` | Browser inspection to verify exposed VCS metadata and backup file accessibility |
| `nuclei_scan` | Automated scanning with exposure templates for .git, .svn, .env, and backup files |
| `katana_crawl` | Web crawling to discover exposed VCS directories and backup artifacts during recon |

---

## RELATED ROUTING

- From **[recon-for-sec](../recon-and-methodology/SKILL.md)** — scope-safe discovery, crawling, and fingerprinting before deep VCS tests.
- From **[recon-and-methodology](../recon-and-methodology/SKILL.md)** — structured methodology and evidence handling.

**Note**: Combine with reconnaissance skills — first define scope and rate, then perform targeted VCS/backup verification.
