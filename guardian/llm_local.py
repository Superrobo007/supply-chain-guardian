"""Local-GPU backend: runs the Guardian's agents on an open-weights model served by Ollama
(https://ollama.com) on your own machine — NVIDIA (CUDA) on Windows/Linux, Apple Silicon (Metal) on macOS.

  ollama pull qwen2.5:7b          # ~4.7 GB; good tool-calling for its size (8 GB RAM/VRAM is enough)
  set GUARDIAN_LLM=ollama          (PowerShell: $env:GUARDIAN_LLM="ollama";  bash: export GUARDIAN_LLM=ollama)
  optional: GUARDIAN_OLLAMA_MODEL=qwen2.5:14b   GUARDIAN_OLLAMA_URL=http://localhost:11434

Uses Ollama's native REST API (/api/chat) with tool calling and JSON-schema constrained output ("format").
Small local models are weaker at multi-step tool use than frontier models, so the loop is two-phase:
  phase 1: up to N tool-calling turns to gather evidence;  phase 2: one schema-constrained call for the verdict.
The same hallucination controls (evidence-ID checks, Skeptic, closed action space) apply unchanged.
"""
from __future__ import annotations

import json
import os
import urllib.request

URL = os.environ.get("GUARDIAN_OLLAMA_URL", "http://localhost:11434").rstrip("/")
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # local server: never use a proxy
MODEL = os.environ.get("GUARDIAN_OLLAMA_MODEL", "qwen2.5:7b")


def _chat(messages: list[dict], tools: list[dict] | None = None, fmt: dict | None = None, timeout: int = 600) -> dict:
    body = {"model": MODEL, "messages": messages, "stream": False, "options": {"temperature": 0, "num_ctx": 16384}}
    if tools:
        body["tools"] = tools
    if fmt:
        body["format"] = fmt
    req = urllib.request.Request(f"{URL}/api/chat", data=json.dumps(body).encode(),
                                 headers={"content-type": "application/json"})
    with _OPENER.open(req, timeout=timeout) as r:   # localhost only; no proxy/TLS needed
        return json.loads(r.read().decode("utf-8"))["message"]


def available() -> bool:
    try:
        with _OPENER.open(f"{URL}/api/tags", timeout=3) as r:
            names = [m["name"] for m in json.loads(r.read().decode("utf-8")).get("models", [])]
        return any(n == MODEL or n.split(":")[0] == MODEL.split(":")[0] for n in names)
    except Exception:
        return False


def to_ollama_tools(claude_tools: list[dict]) -> list[dict]:
    return [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                              "parameters": t["input_schema"]}}
            for t in claude_tools if t["name"] != "submit_assessment"]


def structured(system: str, user: str, schema_model):
    """One JSON-schema-constrained completion -> validated pydantic object."""
    msg = _chat([{"role": "system", "content": system}, {"role": "user", "content": user}],
                fmt=schema_model.model_json_schema())
    return schema_model.model_validate_json(msg.get("content") or "{}")


def investigate(f_json: str, tb, system: str, claude_tools: list[dict], assessment_model, max_tool_turns: int = 5):
    tools = to_ollama_tools(claude_tools)
    messages = [{"role": "system", "content": system + "\nWhen you have enough evidence, reply with the word DONE."},
                {"role": "user", "content": "Investigate this finding:\n" + f_json}]
    for _ in range(max_tool_turns):
        msg = _chat(messages, tools=tools)
        messages.append({"role": "assistant", "content": msg.get("content", ""),
                         **({"tool_calls": msg["tool_calls"]} if msg.get("tool_calls") else {})})
        calls = msg.get("tool_calls") or []
        if not calls:
            break
        for call in calls:
            fn = call.get("function", {})
            args = fn.get("arguments") or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            res = tb.dispatch(fn.get("name", ""), args)
            messages.append({"role": "tool", "tool_name": fn.get("name", ""),
                             "content": "<untrusted_data>" + json.dumps(res, default=str)[:12000] + "</untrusted_data>"})
    messages.append({"role": "user", "content": "Now give your final assessment as JSON matching the schema. "
                                                "Cite only evidence IDs (E-xxxx) that appeared above."})
    msg = _chat(messages, fmt=assessment_model.model_json_schema())
    return assessment_model.model_validate_json(msg.get("content") or "{}")
