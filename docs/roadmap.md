# DeltaAudit development roadmap

This is the working backlog for the prototype.

## 1. Immediate quality-of-life fixes

### 1.1 Latest-result aggregation

Status: mostly done.

- Generate `reports/llm-results-latest.json` automatically.
- Generate `reports/findings-latest.json` automatically.
- Base `report.md` on latest result per chunk, not raw append-only JSONL.
- Show old failed retries separately as history, not as current status.

### 1.2 LLM preflight / doctor mode

Status: started as `tools/llm_doctor.py`; not yet wired into `delta_audit.py`.

- Verify base URL is reachable.
- Verify API key works.
- Verify model name works.
- Verify model returns visible content, not reasoning-only output.
- Verify model can return parseable JSON.
- Report `finish_reason`, `content_len`, `reasoning_len`, token usage, and failure reason.

Target command:

```bash
delta-audit doctor
```

Current standalone test:

```bash
python3 tools/llm_doctor.py
```

### 1.3 Resume behavior

Status: partially done.

Done:

- `--retry-failed` skips latest OK chunks and retries latest failed/invalid chunks.
- Append-only JSONL history remains intact.
- Latest-result files are regenerated.

Still needed:

- Warn if `--chunk-chars` differs from previous run.
- Warn if `--repo`, `--since`, `--focus`, `--review`, `--risk-mode`, or `--intent-from-readme` differs from previous config.
- Add `--resume-strict`.
- Add `--resume-allow-config-change`.

### 1.4 Static-pattern cleanup

- Do not flag JavaScript regex `.exec(...)` as Node process execution.
- Separate environment variable names from actual leaked secret values.
- Separate localhost network calls from external network calls.
- Separate expected benchmark/data-provider/model-provider calls from suspicious downloads.
- Add pattern categories and severity.

### 1.5 Clean final summary command

- Read an existing audit directory and summarize it.
- No repo re-scan needed.
- Possible commands:

```bash
delta-audit summarize /tmp/some-audit
delta-audit findings /tmp/some-audit
```

## 2. Better scan planning and base detection

- Add `plan` / dry-run mode.
- Improve fork-base discovery.
- Add compare-candidate mode for forks with multiple possible upstreams.
- Print generated recommended commands.
- Classify scan size as small / medium / large / huge.

## 3. Better reports and interpretation

- Split report into hard-risk, supply-chain, runtime, web/UI, credential, network, operational, false-positive, and manual-review sections.
- Add verdict language:
  - hard-risk signal
  - confidence
  - recommended action
- Normalize duplicate findings.
- Generate manual review checklists.
- Add machine-readable `report.json`.

## 4. Runtime subset automation

- Recommend runtime subsets from static hits and high-value paths.
- Add subset scan mode.
- Add include/exclude path and glob options.
- Add surface presets such as `webui`, `secrets`, `server`, `ci`, and `model-tools`.

## 5. LLM robustness improvements

- Add reasoning-aware handling.
- Detect `reasoning_exhausted` explicitly.
- Improve JSON recovery.
- Add automatic retry policy.
- Add model profiles.
- Track token/time accounting.

## 6. Static analysis improvements

- Categorize findings:
  - `process.shell`
  - `process.debugger`
  - `network.localhost`
  - `network.external-download`
  - `network.api-provider`
  - `secret.env-reference`
  - `secret.literal-looking`
  - `persistence.cron`
  - `persistence.systemd`
  - `crypto.miner`
  - `ci.supply-chain`
  - `web.exposure`
- Reduce false positives.
- Add literal secret detection with redaction.
- Add URL/domain inventory.
- Add script risk inventory.

## 7. GitHub / Git integration

- Accept GitHub repo URLs and PR URLs.
- Auto-clone to temp directories.
- Add PR mode.
- Improve fork mode.
- Add upstream-candidate detection.
- Add safe temp workspace handling.

## 8. Packaging and project structure

- Move from single script to package layout:
  - `src/delta_audit/cli.py`
  - `src/delta_audit/git.py`
  - `src/delta_audit/static_scan.py`
  - `src/delta_audit/llm.py`
  - `src/delta_audit/report.py`
- Add `pyproject.toml`.
- Add CLI command `delta-audit`.
- Keep `delta_audit.py` usable until migration is stable.
- Add examples and docs.

## 9. Service / product direction

- Batch mode from YAML.
- Machine-readable scorecard.
- Single-file HTML reports.
- Audit cache keyed by patch/config/model profile.
- Service-safe redaction mode.

## 10. Future extension: model artifact hard-risk audit

- GGUF scanner:
  - SHA256
  - metadata inventory
  - tensor sanity
  - suspicious metadata strings
  - chat template inspection
  - tokenizer metadata inspection
- Runtime network watch helper.
- Keep this about hard risks only, not alignment/politics/model behavior.

## Recommended implementation order

1. Latest-result aggregation.
2. LLM doctor / preflight.
3. Reasoning-exhausted detection.
4. Compact hard-mode prompt.
5. Compact intent summary.
6. Rescore existing findings.
7. Static pattern cleanup.
8. Fork-base / plan automation.
9. Better report structure.
10. Runtime subset automation.
11. Package / CLI polish.
12. PR / GitHub URL mode.
13. Batch / service reports.
14. GGUF artifact hard-risk scanner.
