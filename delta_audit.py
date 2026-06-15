#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterable

EXCLUDE_DIR_NAMES = {
    ".git", "node_modules", "vendor", "build", "dist", "target", "out",
    "__pycache__", ".cache", ".venv", "venv", ".mypy_cache", ".pytest_cache",
}

BINARY_GLOBS = [
    "*.gguf", "*.bin", "*.pt", "*.pth", "*.safetensors", "*.onnx",
    "*.zip", "*.tar", "*.tar.gz", "*.tgz", "*.7z", "*.rar",
    "*.png", "*.jpg", "*.jpeg", "*.gif", "*.webp", "*.mp4", "*.mp3", "*.wav", "*.pdf",
]

CONTROL_PATTERNS = [
    ".github/", ".gitlab-ci.yml", "Dockerfile", "Makefile", "CMakeLists.txt",
    ".cmake", ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
    ".yml", ".yaml", "package.json", "package-lock.json", "pnpm-lock.yaml",
    "yarn.lock", "pyproject.toml", "setup.py", "setup.cfg", "requirements",
    "Pipfile", "Cargo.toml", "Cargo.lock", "go.mod", "go.sum",
]

RUNTIME_EXTS = {
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx",
    ".cu", ".cuh", ".metal", ".glsl", ".comp", ".py", ".js", ".ts",
    ".go", ".rs", ".java", ".kt", ".cs", ".php", ".rb",
}

SUSPICIOUS = [
    ("shell_exec_c", r"\b(system|popen|execl|execlp|execle|execv|execvp|execve)\s*\(", "C/C++ process execution"),
    ("process_py", r"\b(subprocess\.(Popen|run|call|check_call|check_output)|os\.system|os\.popen)\s*\(", "Python process execution"),
    ("node_process", r"\b(child_process|execSync|execFileSync|spawnSync|exec\s*\(|spawn\s*\()", "Node process execution"),
    ("network_tool", r"(?<![A-Za-z0-9_])(curl|wget|ncat|socat)\b", "Network transfer tool"),
    ("shell_c", r"(?<![A-Za-z0-9_])(bash|sh|zsh)\s+-c\b", "Shell interpreter with -c"),
    ("dev_tcp", r"/dev/tcp/", "Bash /dev/tcp networking"),
    ("base64_decode", r"\bbase64\s+(-d|--decode)\b", "Base64 decode"),
    ("persistence", r"\b(crontab|systemctl\s+enable|launchctl|authorized_keys|\.ssh/id_rsa|\.ssh/id_ed25519)\b", "Persistence or SSH key access"),
    ("loader_injection", r"\b(LD_PRELOAD|DYLD_INSERT_LIBRARIES)\b", "Dynamic loader injection"),
    ("ptrace_or_inject", r"\b(ptrace|process_vm_readv|process_vm_writev|CreateRemoteThread|WriteProcessMemory)\b", "Debugging/injection primitive"),
    ("miner", r"\b(xmrig|stratum\+tcp|mining_pool|cryptonight)\b", "Crypto-mining indicator"),
    ("secret_name", r"\b(AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|OPENAI_API_KEY|API_KEY|SECRET_KEY|PRIVATE_KEY)\b", "Secret/token identifier"),
    ("python_http", r"\b(requests\.get|urllib\.request\.urlopen|httpx\.get|aiohttp\.ClientSession)\s*\(", "Python HTTP request"),
    ("js_http", r"\b(fetch|axios\.get|request\s*\()\s*\(", "JavaScript HTTP request"),
]


def die(msg: str, code: int = 2) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    raise SystemExit(code)


def run(cmd: list[str], cwd: Path | None = None, check: bool = True) -> str:
    p = subprocess.run(cmd, cwd=str(cwd) if cwd else None, text=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and p.returncode != 0:
        die("Command failed:\n" + " ".join(cmd) + "\n" + p.stderr.strip())
    return p.stdout


def git(repo: Path, args: list[str], check: bool = True) -> str:
    return run(["git", *args], cwd=repo, check=check)


def is_git_repo(repo: Path) -> bool:
    return git(repo, ["rev-parse", "--is-inside-work-tree"], check=False).strip() == "true"


def add_fetch_upstream(repo: Path, url: str, branch: str) -> None:
    remotes = set(git(repo, ["remote"]).splitlines())
    if "audit-upstream" not in remotes:
        git(repo, ["remote", "add", "audit-upstream", url])
    else:
        git(repo, ["remote", "set-url", "audit-upstream", url])
    git(repo, ["fetch", "audit-upstream", branch, "--prune"])


def path_is_binary_name(path: str) -> bool:
    import fnmatch
    name = Path(path).name
    return any(fnmatch.fnmatch(name, pat) for pat in BINARY_GLOBS)


def looks_binary(path: Path) -> bool:
    try:
        data = path.read_bytes()[:8192]
    except OSError:
        return True
    return b"\0" in data


def excluded_path(rel: str, include_tests: bool) -> bool:
    parts = Path(rel).parts
    if any(part in EXCLUDE_DIR_NAMES for part in parts):
        return True
    if not include_tests and any(part in {"test", "tests"} for part in parts):
        return True
    if path_is_binary_name(rel):
        return True
    return False


def focus_ok(rel: str, focus: str) -> bool:
    if focus == "all":
        return True
    rel_slash = rel.replace(os.sep, "/")
    name = Path(rel).name
    suffix = Path(rel).suffix
    is_control = (
        rel_slash.startswith(".github/")
        or any(name == p for p in CONTROL_PATTERNS)
        or any(rel_slash.endswith(p) for p in CONTROL_PATTERNS if p.startswith("."))
        or any(p in rel_slash for p in ["requirements", "Dockerfile"])
    )
    if focus == "control":
        return is_control
    if focus == "runtime":
        return (suffix in RUNTIME_EXTS) and not is_control
    return True


def parse_name_status(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        status = parts[0]
        if status.startswith(("R", "C")) and len(parts) >= 3:
            out.append((status, parts[2]))
        elif len(parts) >= 2:
            out.append((status, parts[1]))
    return out


def determine_range(args: argparse.Namespace, repo: Path) -> tuple[str, str]:
    if args.mode == "full":
        return "", "FULL"
    if args.mode == "since":
        if not args.since:
            die("--mode since requires --since")
        dots = "..." if args.three_dot else ".."
        return args.since, f"{args.since}{dots}{args.head}"
    if args.mode == "fork":
        if not args.upstream_url:
            die("--mode fork requires --upstream-url")
        add_fetch_upstream(repo, args.upstream_url, args.upstream_branch)
        upstream_ref = f"audit-upstream/{args.upstream_branch}"
        base = git(repo, ["merge-base", upstream_ref, args.head]).strip()
        return base, f"{base}...{args.head}"
    die(f"Unknown mode: {args.mode}")


def list_files(args: argparse.Namespace, repo: Path, range_expr: str) -> list[tuple[str, str]]:
    if range_expr == "FULL":
        raw_paths = git(repo, ["ls-files"]).splitlines()
        result = []
        for rel in raw_paths:
            full = repo / rel
            if not full.is_file():
                continue
            if excluded_path(rel, args.include_tests) or not focus_ok(rel, args.focus):
                continue
            if full.stat().st_size > args.max_file_bytes or looks_binary(full):
                continue
            result.append(("FULL", rel))
        return result

    raw = git(repo, ["diff", "--name-status", "--find-renames", range_expr])
    result = []
    for status, rel in parse_name_status(raw):
        if status.startswith("D"):
            continue
        full = repo / rel
        if not full.is_file():
            continue
        if excluded_path(rel, args.include_tests) or not focus_ok(rel, args.focus):
            continue
        if full.stat().st_size > args.max_file_bytes or looks_binary(full):
            continue
        result.append((status, rel))
    return result


def copy_files(repo: Path, files: list[tuple[str, str]], out: Path) -> None:
    root = out / "files"
    root.mkdir(parents=True, exist_ok=True)
    for _, rel in files:
        src = repo / rel
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


def write_meta(args: argparse.Namespace, repo: Path, out: Path, base: str, range_expr: str, files: list[tuple[str, str]]) -> None:
    meta = out / "meta"
    meta.mkdir(parents=True, exist_ok=True)
    selected = [rel for _, rel in files]

    (meta / "base.txt").write_text(base + "\n", encoding="utf-8")
    (meta / "range.txt").write_text(range_expr + "\n", encoding="utf-8")
    cfg = vars(args).copy()
    cfg["repo"] = str(args.repo)
    cfg["out"] = str(args.out)
    (meta / "config.json").write_text(json.dumps(cfg, indent=2, default=str) + "\n", encoding="utf-8")
    (meta / "name-status.filtered.txt").write_text(
        "".join(f"{status}\t{rel}\n" for status, rel in files),
        encoding="utf-8",
    )

    if range_expr == "FULL":
        chunks = []
        for _, rel in files:
            try:
                content = (repo / rel).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            chunks.append(f"\n--- FILE: {rel} ---\n{content}\n")
        (meta / "changes.patch").write_text("".join(chunks), encoding="utf-8")
        (meta / "stat.txt").write_text(f"Full repository scan. Filtered files: {len(files)}\n", encoding="utf-8")
        return

    (meta / "name-status.raw.txt").write_text(
        git(repo, ["diff", "--name-status", "--find-renames", range_expr]),
        encoding="utf-8",
    )

    if selected:
        stat = git(repo, ["diff", "--stat", range_expr, "--", *selected])
        patch = git(repo, ["diff", "--find-renames", range_expr, "--", *selected])
    else:
        stat = ""
        patch = ""

    (meta / "stat.txt").write_text(stat, encoding="utf-8")
    (meta / "changes.patch").write_text(patch, encoding="utf-8", errors="replace")


def static_scan(out: Path) -> list[dict[str, Any]]:
    root = out / "files"
    findings: list[dict[str, Any]] = []
    if not root.exists():
        return findings
    for path in sorted(root.rglob("*")):
        if not path.is_file() or looks_binary(path):
            continue
        rel = path.relative_to(root).as_posix()
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for no, line in enumerate(lines, 1):
            for ident, rx, desc in SUSPICIOUS:
                if re.search(rx, line):
                    findings.append({
                        "pattern_id": ident,
                        "description": desc,
                        "file": rel,
                        "line": no,
                        "text": line.strip()[:500],
                    })
    return findings


def split_text(text: str, max_chars: int) -> list[str]:
    chunks: list[str] = []
    cur: list[str] = []
    cur_len = 0
    for line in text.splitlines(keepends=True):
        if cur and cur_len + len(line) > max_chars:
            chunks.append("".join(cur))
            cur = []
            cur_len = 0
        if len(line) > max_chars:
            for i in range(0, len(line), max_chars):
                part = line[i:i + max_chars]
                if cur:
                    chunks.append("".join(cur))
                    cur = []
                    cur_len = 0
                chunks.append(part)
        else:
            cur.append(line)
            cur_len += len(line)
    if cur:
        chunks.append("".join(cur))
    return chunks or [""]


def review_text(out: Path, mode: str) -> str:
    patch = (out / "meta" / "changes.patch").read_text(encoding="utf-8", errors="replace")
    if mode == "patch":
        return patch

    parts = []
    for p in sorted((out / "files").rglob("*")):
        if not p.is_file() or looks_binary(p):
            continue
        rel = p.relative_to(out / "files").as_posix()
        parts.append(f"\n--- FILE: {rel} ---\n")
        parts.append(p.read_text(encoding="utf-8", errors="replace"))
        parts.append("\n")
    files = "".join(parts)
    if mode == "files":
        return files
    return patch + "\n\n" + files


def model_name_for_api(model: str) -> str:
    return model.removeprefix("openai/")


def chat(args: argparse.Namespace, messages: list[dict[str, str]]) -> tuple[str, dict[str, Any]]:
    url = args.base_url.rstrip("/") + "/chat/completions"
    body = {
        "model": model_name_for_api(args.model),
        "messages": messages,
        "temperature": args.temperature,
        "max_tokens": args.max_tokens,
    }
    headers = {"Content-Type": "application/json"}
    if args.api_key:
        headers["Authorization"] = f"Bearer {args.api_key}"

    data = json.dumps(body).encode("utf-8")
    last = "unknown error"
    for attempt in range(args.retries + 1):
        try:
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=args.timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            parsed = json.loads(raw)
            msg = parsed.get("choices", [{}])[0].get("message", {})
            content = msg.get("content") or ""
            return content, parsed
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code}: " + e.read().decode("utf-8", errors="replace")[:1000]
        except Exception as e:
            last = repr(e)
        if attempt < args.retries:
            time.sleep(min(2 ** attempt, 10))
    raise RuntimeError(last)


def json_from_text(text: str) -> Any | None:
    t = text.strip()
    t = re.sub(r"^```(?:json)?\s*", "", t)
    t = re.sub(r"\s*```$", "", t)
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        pass
    s = t.find("{")
    e = t.rfind("}")
    if s >= 0 and e > s:
        try:
            return json.loads(t[s:e + 1])
        except json.JSONDecodeError:
            return None
    return None


def build_messages(chunk: str, idx: int, total: int, args: argparse.Namespace, static_sample: list[dict[str, Any]]) -> list[dict[str, str]]:
    system = (
        "You are a cautious supply-chain security reviewer. Audit repository code or git diff chunks. "
        "Focus only on security-relevant behavior: hidden network calls, credential access, shell/process execution, "
        "persistence, build/install script abuse, unexpected downloads, exfiltration, backdoors, dependency confusion, "
        "and code that weakens authentication or safety boundaries. Do not flag ordinary implementation complexity. "
        "Return JSON only."
    )
    schema = {
        "chunk_index": idx,
        "chunk_total": total,
        "risk": "none|low|medium|high|critical",
        "summary": "short summary",
        "findings": [
            {
                "risk": "low|medium|high|critical",
                "file": "path if known",
                "line_or_hunk": "line/hunk if known",
                "title": "short title",
                "evidence": "specific evidence",
                "why_it_matters": "impact",
                "recommended_review": "next manual check",
            }
        ],
        "benign_notes": ["short notes"],
    }
    user = (
        f"Audit context: mode={args.mode}, focus={args.focus}, repo={args.repo}\n"
        f"Static pattern sample:\n{json.dumps(static_sample[:40], indent=2)}\n\n"
        f"Return JSON matching this schema:\n{json.dumps(schema, indent=2)}\n\n"
        f"Audit chunk {idx}/{total}:\n\n{chunk}"
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def load_done(results_path: Path) -> set[int]:
    done: set[int] = set()
    if not results_path.exists():
        return done
    for line in results_path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("ok") and isinstance(rec.get("chunk_index"), int):
            done.add(rec["chunk_index"])
    return done


def llm_review(args: argparse.Namespace, out: Path, static_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    text = review_text(out, args.review)
    chunks = split_text(text, args.chunk_chars)
    chunks_dir = out / "llm_chunks"
    chunks_dir.mkdir(parents=True, exist_ok=True)
    reports = out / "reports"
    results_path = reports / "llm-results.jsonl"
    raw_dir = reports / "llm-raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    done = load_done(results_path) if args.resume else set()
    mode = "a" if args.resume else "w"
    records: list[dict[str, Any]] = []

    with results_path.open(mode, encoding="utf-8") as f:
        for idx, chunk in enumerate(chunks, 1):
            if idx < args.start_chunk:
                continue
            if args.max_chunks and idx >= args.start_chunk + args.max_chunks:
                break
            chunk_path = chunks_dir / f"chunk-{idx:04d}.txt"
            chunk_path.write_text(chunk, encoding="utf-8")
            if idx in done:
                print(f"LLM chunk {idx}/{len(chunks)}: skipped by --resume", file=sys.stderr)
                continue

            started = time.time()
            rec: dict[str, Any] = {
                "chunk_index": idx,
                "chunk_total": len(chunks),
                "chunk_file": str(chunk_path),
                "started_at": started,
            }
            try:
                content, raw = chat(args, build_messages(chunk, idx, len(chunks), args, static_findings))
                parsed = json_from_text(content)
                raw_path = raw_dir / f"chunk-{idx:04d}.response.json"
                raw_path.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")
                rec.update({
                    "ok": parsed is not None,
                    "elapsed_s": round(time.time() - started, 2),
                    "parsed": parsed,
                    "raw_content": None if parsed is not None else content[:5000],
                    "usage": raw.get("usage"),
                })
            except Exception as e:
                rec.update({
                    "ok": False,
                    "elapsed_s": round(time.time() - started, 2),
                    "error": repr(e),
                })

            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            f.flush()
            records.append(rec)
            print(f"LLM chunk {idx}/{len(chunks)}: {'ok' if rec.get('ok') else 'failed'} ({rec['elapsed_s']}s)", file=sys.stderr)

    return records


def risk_summary(llm_records: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    order = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    inv = {v: k for k, v in order.items()}
    max_risk = 0
    findings: list[dict[str, Any]] = []
    for rec in llm_records:
        parsed = rec.get("parsed")
        if not isinstance(parsed, dict):
            continue
        max_risk = max(max_risk, order.get(str(parsed.get("risk", "none")).lower(), 0))
        for finding in parsed.get("findings", []) or []:
            if isinstance(finding, dict):
                findings.append(finding)
                max_risk = max(max_risk, order.get(str(finding.get("risk", "none")).lower(), 0))
    return inv[max_risk], findings


def write_report(args: argparse.Namespace, out: Path, base: str, range_expr: str, files: list[tuple[str, str]],
                 static_findings: list[dict[str, Any]], llm_records: list[dict[str, Any]]) -> None:
    reports = out / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "static-findings.json").write_text(json.dumps(static_findings, indent=2) + "\n", encoding="utf-8")

    ok = sum(1 for r in llm_records if r.get("ok"))
    bad = len(llm_records) - ok
    risk, llm_findings = risk_summary(llm_records)

    md: list[str] = []
    md.append("# Fork Audit Report\n\n")
    md.append("## Scope\n")
    md.append(f"- Repository: `{args.repo}`\n")
    md.append(f"- Mode: `{args.mode}`\n")
    md.append(f"- Focus: `{args.focus}`\n")
    md.append(f"- Base: `{base or 'N/A'}`\n")
    md.append(f"- Range: `{range_expr}`\n")
    md.append(f"- Filtered files copied: **{len(files)}**\n")
    md.append(f"- Output directory: `{out}`\n\n")

    md.append("## Automated verdict\n")
    md.append(f"- Static suspicious-pattern hits: **{len(static_findings)}**\n")
    if args.no_llm:
        md.append("- LLM review: **disabled**\n")
    else:
        md.append(f"- LLM chunks OK: **{ok}**\n")
        md.append(f"- LLM chunks failed/invalid: **{bad}**\n")
        md.append(f"- Highest LLM risk: **{risk}**\n")
    md.append("\n> This is triage, not proof of safety. Manually review scripts, workflows, build files, and any high-risk findings.\n\n")

    md.append("## Static findings sample\n")
    if static_findings:
        for item in static_findings[:100]:
            text = str(item.get("text", "")).replace("\n", " ")[:500]
            md.append(f"- `{item.get('file')}:{item.get('line')}` **{item.get('pattern_id')}** — {text}\n")
        if len(static_findings) > 100:
            md.append(f"- ... {len(static_findings) - 100} more in `reports/static-findings.json`\n")
    else:
        md.append("No static suspicious-pattern hits.\n")

    md.append("\n## LLM findings\n")
    if args.no_llm:
        md.append("LLM review disabled.\n")
    elif llm_findings:
        for item in llm_findings:
            md.append(f"- **{item.get('risk', 'unknown')}** `{item.get('file', '?')}` — {item.get('title', '')}\n")
            if item.get("evidence"):
                md.append(f"  - Evidence: {item.get('evidence')}\n")
            if item.get("recommended_review"):
                md.append(f"  - Review: {item.get('recommended_review')}\n")
    else:
        md.append("No meaningful LLM findings were parsed. Check `reports/llm-results.jsonl` for failures.\n")

    md.append("\n## Useful files\n")
    md.append("- `meta/changes.patch`\n")
    md.append("- `meta/name-status.raw.txt`\n")
    md.append("- `meta/name-status.filtered.txt`\n")
    md.append("- `files/`\n")
    md.append("- `reports/static-findings.json`\n")
    md.append("- `reports/llm-results.jsonl`\n")
    (reports / "report.md").write_text("".join(md), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Generic repository/fork diff security triage with optional OpenAI-compatible LLM review.")
    p.add_argument("--repo", required=True, type=Path)
    p.add_argument("--mode", choices=["full", "since", "fork"], default="fork")
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--upstream-url")
    p.add_argument("--upstream-branch", default="master")
    p.add_argument("--since")
    p.add_argument("--head", default="HEAD")
    p.add_argument("--three-dot", action="store_true", help="Use A...HEAD for --mode since instead of A..HEAD")

    p.add_argument("--focus", choices=["all", "control", "runtime"], default="all")
    p.add_argument("--review", choices=["patch", "files", "both"], default="patch")
    p.add_argument("--include-tests", action="store_true")
    p.add_argument("--max-file-bytes", type=int, default=2_000_000)
    p.add_argument("--chunk-chars", type=int, default=12_000)
    p.add_argument("--max-chunks", type=int, default=0)
    p.add_argument("--start-chunk", type=int, default=1)

    p.add_argument("--no-llm", action="store_true")
    p.add_argument("--resume", action="store_true")
    p.add_argument("--force", action="store_true")

    p.add_argument("--api-key", default=os.environ.get("AUDIT_LLM_API_KEY", "local"))
    p.add_argument("--base-url", default=os.environ.get("AUDIT_LLM_BASE_URL", "http://127.0.0.1:8080/v1"))
    p.add_argument("--model", default=os.environ.get("AUDIT_LLM_MODEL", "openai/local"))
    p.add_argument("--temperature", type=float, default=float(os.environ.get("AUDIT_LLM_TEMPERATURE", "0.1")))
    p.add_argument("--max-tokens", type=int, default=int(os.environ.get("AUDIT_LLM_MAX_TOKENS", "1024")))
    p.add_argument("--timeout", type=int, default=int(os.environ.get("AUDIT_LLM_TIMEOUT", "600")))
    p.add_argument("--retries", type=int, default=int(os.environ.get("AUDIT_LLM_RETRIES", "0")))
    return p.parse_args()


def main() -> int:
    args = parse_args()
    args.repo = args.repo.expanduser().resolve()
    args.out = args.out.expanduser().resolve()

    if not is_git_repo(args.repo):
        die(f"Not a git repository: {args.repo}")

    if args.out.exists():
        if args.force:
            shutil.rmtree(args.out)
        elif not args.resume:
            die(f"Output directory exists: {args.out}\nUse --resume or --force.")
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "reports").mkdir(parents=True, exist_ok=True)

    base, range_expr = determine_range(args, args.repo)
    files = list_files(args, args.repo, range_expr)
    copy_files(args.repo, files, args.out)
    write_meta(args, args.repo, args.out, base, range_expr, files)
    static_findings = static_scan(args.out)

    llm_records: list[dict[str, Any]] = []
    if not args.no_llm:
        llm_records = llm_review(args, args.out, static_findings)

    write_report(args, args.out, base, range_expr, files, static_findings, llm_records)

    print("Audit complete")
    print(f"Output: {args.out}")
    print(f"Report: {args.out / 'reports' / 'report.md'}")
    print(f"Files copied: {len(files)}")
    print(f"Static findings: {len(static_findings)}")
    if not args.no_llm:
        ok = sum(1 for r in llm_records if r.get("ok"))
        print(f"LLM chunks valid: {ok}/{len(llm_records)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
