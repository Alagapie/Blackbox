"""Check that the Meta Model API key works, and that each model supports tool calling.

Tool calling is required: our agent (M5) acts ONLY through the interceptor's
tools (M3), so the model must be able to request a tool instead of just talking.

Usage:
    .venv\\Scripts\\python scripts\\check_llm.py                      # models from .env + muse-wonder-1.0
    .venv\\Scripts\\python scripts\\check_llm.py muse-spark-1.3       # specific model(s)

The key is read from .env and never printed.
"""

from __future__ import annotations

import json
import os
import sys

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

TOOLS = [{
    "type": "function",
    "function": {
        "name": "delete_file",
        "description": "Delete a file at the given path.",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "File path"}},
            "required": ["path"],
        },
    },
}]


def main() -> int:
    key = os.environ.get("MODEL_API_KEY", "")
    if not key or key.startswith("paste-"):
        print("No key found. Copy .env.example to .env and set MODEL_API_KEY.")
        return 1
    print(f"Key loaded ({len(key)} characters, starts with {key[:4]}...)")
    client = OpenAI(base_url=os.environ.get("MODEL_BASE_URL", "https://api.meta.ai/v1"), api_key=key)

    print("\n[1] Models available to this key:")
    try:
        ids = sorted(m.id for m in client.models.list())
        print("   " + ("\n   ".join(ids) if ids else "(none listed)"))
    except Exception as e:  # listing may not be supported; not fatal
        print(f"   could not list models: {type(e).__name__}: {e}")

    models = sys.argv[1:] or list(dict.fromkeys([os.environ.get("MODEL_NAME", "muse-spark-1.3"), "muse-wonder-1.0"]))
    ok_all = True
    for model in models:
        print(f"\n=== {model} ===")
        try:
            r = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": "Reply with exactly: BLACKBOX OK"}],
                max_tokens=2000,  # thinking models reason (~270 tokens) before answering
            )
            print(f"[2] plain chat : {r.choices[0].message.content!r}")
        except Exception as e:
            print(f"[2] plain chat : FAILED {type(e).__name__}: {e}")
            ok_all = False
            continue
        try:
            r = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": "Use your tool to delete the file /tmp/old.txt"}],
                tools=TOOLS,
                max_tokens=2000,  # only tool_choice="auto" is supported by Meta
            )
            calls = r.choices[0].message.tool_calls or []
            if calls:
                c = calls[0].function
                print(f"[3] tool call  : OK -> {c.name}({json.loads(c.arguments)})")
            else:
                print(f"[3] tool call  : model answered in text instead: {r.choices[0].message.content!r}")
                ok_all = False
        except Exception as e:
            print(f"[3] tool call  : FAILED {type(e).__name__}: {e}")
            ok_all = False
    return 0 if ok_all else 2


if __name__ == "__main__":
    sys.exit(main())
