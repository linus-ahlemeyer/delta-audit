# DeltaAudit

Changed-code security triage for forks, PRs, and fast-moving repositories.

DeltaAudit extracts the relevant code delta, runs static suspicious-pattern checks, optionally reviews chunks with an OpenAI-compatible local or cloud LLM, and writes resumable JSONL and Markdown reports.

## Current status

DeltaAudit is an early prototype. It is useful for triage, but it is not proof of safety and does not replace manual review.

## What it is for

DeltaAudit helps answer questions like:

- What changed in this fork compared with its upstream base?
- Which changed files touch build scripts, CI, shell execution, credentials, network calls, or runtime-sensitive code?
- Are there obvious hard-risk patterns such as unexpected process execution, suspicious downloads, persistence mechanisms, or credential handling?
- Can a local or cloud LLM summarize changed-code risk in a resumable way?

## Threat model

DeltaAudit is intended for hard-risk triage of changed code, including:

- unexpected shell or process execution
- suspicious network calls
- credential, token, or API-key handling
- build-script and CI supply-chain risk
- persistence or backdoor-like behavior
- risky runtime deltas
- web UI and local-service exposure risks

It does not evaluate model alignment, model behavior, investment quality, correctness, or whether software is bug-free.

## Basic usage

Configure an OpenAI-compatible endpoint. For a local llama.cpp server:

```bash
export AUDIT_LLM_API_KEY="local-or-your-server-key"
export AUDIT_LLM_BASE_URL="http://127.0.0.1:8080/v1"
export AUDIT_LLM_MODEL="openai/local"
export AUDIT_LLM_TEMPERATURE="0.1"
export AUDIT_LLM_MAX_TOKENS="4096"
export AUDIT_LLM_TIMEOUT="900"
```

Run a changed-code audit from a known base commit:

```bash
./delta_audit.py \
  --repo /path/to/repo \
  --mode since \
  --since <base-commit> \
  --focus control \
  --chunk-chars 4000 \
  --max-tokens 4096 \
  --timeout 900 \
  --out /tmp/delta-audit-output \
  --force
```

Run a static-only pass:

```bash
./delta_audit.py \
  --repo /path/to/repo \
  --mode since \
  --since <base-commit> \
  --focus runtime \
  --out /tmp/delta-audit-runtime-static \
  --no-llm \
  --force
```

Resume an interrupted LLM audit:

```bash
./delta_audit.py \
  --repo /path/to/repo \
  --mode since \
  --since <base-commit> \
  --focus control \
  --chunk-chars 4000 \
  --max-tokens 4096 \
  --timeout 900 \
  --out /tmp/delta-audit-output \
  --resume
```

Do not use `--force` when resuming, because it deletes the output directory.

## Focus modes

DeltaAudit can narrow the review surface:

- `--focus control` for CI, Docker, scripts, build files, dependency manifests, and other control-plane files.
- `--focus runtime` for runtime source files.
- `--focus all` for the full selected delta.

A good workflow is usually:

1. Run `control` first.
2. Run `runtime --no-llm` next.
3. Use the static findings and changed-file list to decide whether to run a targeted runtime LLM review.

## Outputs

DeltaAudit writes output under the directory passed via `--out`:

- `files/` — copied scan set
- `meta/changes.patch` — patch or pseudo-patch sent to the model
- `meta/name-status.raw.txt` — raw changed files
- `meta/name-status.filtered.txt` — filtered copied files
- `reports/static-findings.json` — static suspicious-pattern hits
- `reports/llm-results.jsonl` — append-only LLM chunk results
- `reports/report.md` — Markdown summary

For resumed runs, `llm-results.jsonl` may contain older failed records and newer successful retries. Use the latest record per chunk when interpreting results.

Example:

```bash
jq -s '
  group_by(.chunk_index)
  | map(max_by(.started_at))
  | sort_by(.chunk_index)
' /tmp/delta-audit-output/reports/llm-results.jsonl \
> /tmp/delta-audit-output/reports/llm-results-latest.json
```

## License

BSD-3-Clause.
