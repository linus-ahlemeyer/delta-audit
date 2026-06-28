#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import time
import urllib.error
import urllib.request
from typing import Any


def model_name_for_api(model: str) -> str:
    return model.removeprefix("openai/")


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


def response_stats(raw: dict[str, Any] | None, content: str = "") -> dict[str, Any]:
    msg: dict[str, Any] = {}
    choice: dict[str, Any] = {}
    if isinstance(raw, dict):
        choices = raw.get("choices") or []
        if choices and isinstance(choices[0], dict):
            choice = choices[0]
            maybe_msg = choice.get("message")
            if isinstance(maybe_msg, dict):
                msg = maybe_msg
    final_content = content if content is not None else (msg.get("content") or "")
    reasoning = msg.get("reasoning_content") or ""
    return {
        "finish_reason": choice.get("finish_reason"),
        "content_len": len(final_content or ""),
        "reasoning_len": len(reasoning or ""),
        "usage": raw.get("usage") if isinstance(raw, dict) else None,
    }


def classify_failure(content: str, raw: dict[str, Any] | None, parsed: Any | None, error: str | None = None) -> str | None:
    if error:
        return "exception"
    if parsed is not None:
        return None
    stats = response_stats(raw, content)
    finish_reason = stats.get("finish_reason")
    content_len = int(stats.get("content_len") or 0)
    reasoning_len = int(stats.get("reasoning_len") or 0)
    stripped = (content or "").strip()
    if finish_reason == "length" and content_len == 0 and reasoning_len > 0:
        return "reasoning_exhausted"
    if finish_reason == "length" and content_len > 0:
        return "truncated_json"
    if content_len == 0 and reasoning_len > 0:
        return "reasoning_only"
    if content_len == 0:
        return "empty_content"
    if stripped.startswith("```json") or stripped.startswith("{"):
        return "invalid_or_partial_json"
    return "parse_failed"


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
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=args.timeout) as resp:
        raw_text = resp.read().decode("utf-8", errors="replace")
    raw = json.loads(raw_text)
    msg = raw.get("choices", [{}])[0].get("message", {})
    return msg.get("content") or "", raw


def doctor_messages() -> list[dict[str, str]]:
    return [
        {"role": "system", "content": "Return exactly one compact JSON object. Do not use markdown fences."},
        {"role": "user", "content": 'Return this JSON and nothing else: {"ok":true,"message":"doctor"}'},
    ]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Preflight-check an OpenAI-compatible LLM endpoint for DeltaAudit.")
    p.add_argument("--api-key", default=os.environ.get("AUDIT_LLM_API_KEY", "local"))
    p.add_argument("--base-url", default=os.environ.get("AUDIT_LLM_BASE_URL", "http://127.0.0.1:8080/v1"))
    p.add_argument("--model", default=os.environ.get("AUDIT_LLM_MODEL", "openai/local"))
    p.add_argument("--temperature", type=float, default=float(os.environ.get("AUDIT_LLM_TEMPERATURE", "0.1")))
    p.add_argument("--max-tokens", type=int, default=int(os.environ.get("AUDIT_DOCTOR_MAX_TOKENS", "512")))
    p.add_argument("--timeout", type=int, default=int(os.environ.get("AUDIT_LLM_TIMEOUT", "120")))
    return p.parse_args()


def main() -> int:
    args = parse_args()
    started = time.time()
    result: dict[str, Any] = {
        "ok": False,
        "base_url": args.base_url,
        "model": model_name_for_api(args.model),
        "max_tokens": args.max_tokens,
    }
    try:
        content, raw = chat(args, doctor_messages())
        parsed = json_from_text(content)
        stats = response_stats(raw, content)
        result.update(stats)
        result["parsed"] = parsed
        result["raw_content"] = content[:2000]
        result["json_ok"] = isinstance(parsed, dict)
        result["failure_reason"] = classify_failure(content, raw, parsed)
        result["ok"] = bool(result["json_ok"] and parsed and parsed.get("ok") is True)
        if result["failure_reason"] == "reasoning_exhausted":
            result["recommendation"] = (
                "Model spent the output budget in reasoning_content. Use a non-reasoning model, "
                "disable reasoning if supported by your server, or use compact prompts and smaller chunks."
            )
        elif not result["json_ok"]:
            result["recommendation"] = "Model did not return parseable JSON. Use stricter prompting or a less reasoning-heavy model."
        else:
            result["recommendation"] = "Doctor passed."
    except urllib.error.HTTPError as e:
        result["error"] = f"HTTP {e.code}: " + e.read().decode("utf-8", errors="replace")[:1000]
        result["failure_reason"] = "http_error"
        result["recommendation"] = "Check API key, model name, and server auth settings."
    except Exception as e:
        result["error"] = repr(e)
        result["failure_reason"] = "exception"
        result["recommendation"] = "Check base URL, server availability, API key, and model name."
    result["elapsed_s"] = round(time.time() - started, 2)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
