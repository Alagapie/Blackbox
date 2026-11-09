"""M5: the LLM agent loop. The model can ONLY act through the interceptor (M3).

    model -> tool call -> interceptor.execute() (record, act, record) -> result -> model ...

Works with any OpenAI-compatible client (we use Meta Model API / Muse).
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable, Optional

from interceptor.tools import Interceptor

SYSTEM_PROMPT = """You are an autonomous operations agent working on a company server.
You can ONLY affect the system through the provided tools. All paths are relative to the server workspace.
Work step by step and use tools to inspect before acting.
When the task is complete, call finish_task with a summary for your user of everything you did."""


def make_client():
    from dotenv import load_dotenv
    from openai import OpenAI

    load_dotenv(".env")
    return OpenAI(base_url=os.environ.get("MODEL_BASE_URL", "https://api.meta.ai/v1"),
                  api_key=os.environ["MODEL_API_KEY"])


def run_llm_agent(
    task: str,
    guard: Interceptor,
    client: Any = None,
    model: Optional[str] = None,
    system: str = SYSTEM_PROMPT,
    max_steps: int = 15,
    log: Callable[[str], None] = print,
) -> dict[str, Any]:
    client = client or make_client()
    model = model or os.environ.get("MODEL_NAME", "muse-spark-1.3")
    messages: list[dict[str, Any]] = [{"role": "system", "content": system}, {"role": "user", "content": task}]
    finished, last_text, step = False, "", 0

    for step in range(1, max_steps + 1):
        resp = client.chat.completions.create(model=model, messages=messages, tools=guard.tool_schemas(),
                                              max_tokens=4000)  # reasoning model: leave room to think
        msg = resp.choices[0].message
        calls = msg.tool_calls or []
        if msg.content:
            last_text = msg.content
            log(f"[agent] {msg.content.strip()[:400]}")
        assistant: dict[str, Any] = {"role": "assistant", "content": msg.content or ""}
        if calls:
            assistant["tool_calls"] = [{"id": c.id, "type": "function",
                                        "function": {"name": c.function.name,
                                                     "arguments": c.function.arguments or "{}"}}
                                       for c in calls]
        messages.append(assistant)
        if not calls:
            break
        for c in calls:
            out = guard.execute(c.function.name, c.function.arguments)
            log(f"[tool]  {c.function.name}({(c.function.arguments or '')[:200]}) -> "
                f"{'ok' if out.get('ok') else 'FAILED: ' + str(out.get('error'))}")
            messages.append({"role": "tool", "tool_call_id": c.id, "content": json.dumps(out)[:8000]})
            if c.function.name == "finish_task":
                finished = True
        if finished:
            break

    if not finished and last_text:
        # What the agent finally told the user is still its report.
        guard.report(last_text)
    log(f"[done]  finished={finished} steps={step}")
    return {"finished": finished, "steps": step}
