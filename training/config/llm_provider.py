"""
llm_provider.py
---------------
One call signature, two backends: a local model through Ollama, or Claude.

WHY LOCAL IS THE RIGHT DEFAULT HERE
This is forensic work. A capture contains internal addressing, service
layout, and sometimes payload-adjacent metadata from a network the
investigator is responsible for. Sending that to a third party is a
disclosure decision, and it is one the tool should not make silently. Local
inference keeps the evidence on the machine that holds it, which also
removes a chain-of-custody question before anyone has to answer it.

Cost and rate limits are secondary benefits. The disclosure argument is the
one that matters.

WHAT A 3B MODEL COSTS YOU
qwen2.5:3b at Q4_K_M is small. The whole design of phase 14 rests on the
model doing one thing reliably -- rewriting retrieved text without inventing
anything -- and instruction adherence is exactly what degrades first at this
size. Expect it to be weakest on:

  - saying "not covered by the available documentation" instead of filling
    a gap from its own knowledge
  - keeping citations attached to the right section
  - not converting a log-odds contribution into a percentage

None of that is a reason to avoid local inference. It is a reason to
MEASURE it, which is what scripts_other/eval_reports.py does: it runs the same
prompts through both backends and scores them on those three failures. Run
it before trusting either. If 3b fails the grounding checks, the fix is a
larger local model (qwen2.5:7b, 14b) rather than a remote one -- the
disclosure argument does not change.

CONTEXT BUDGET
qwen2.5:3b has a 32,768-token window and degrades well before filling it. A
NIST section plus SHAP output plus capture facts can approach that, so
`fit_context` trims the retrieved documents -- never the detection, never
the instructions -- and says what it dropped.

Usage:
  from config.llm_provider import get_provider
  llm = get_provider("ollama")          # or "anthropic"
  text, usage = llm.complete(system=..., cached=..., user=...)
"""
import os
import sys
import json
import time
from pathlib import Path

# Local defaults. Override per call or with the environment.
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:3b")

# Claude, when the user explicitly opts in to sending evidence off the machine.
ANTHROPIC_REASONING = "claude-opus-5"
ANTHROPIC_SUMMARY = "claude-sonnet-5"

# Rough characters-per-token for English prose. Only used to decide when to
# trim; the real count comes back in `usage` after the call.
CHARS_PER_TOKEN = 3.6


def approx_tokens(text):
    return int(len(text or "") / CHARS_PER_TOKEN)


def fit_context(cached, user, limit_tokens, reserve_output=2000):
    """Trim retrieved documents to fit, never the detection or instructions.

    Returns (cached, note). `note` is None when nothing was dropped, and
    otherwise says what was cut -- which belongs in the report, because a
    recommendation written from half a playbook is not the same answer.
    """
    budget = limit_tokens - reserve_output - approx_tokens(user) - 400
    if budget <= 0:
        return "", ("Context budget exhausted by the detection alone; no "
                    "documentation was supplied to the model.")
    if approx_tokens(cached) <= budget:
        return cached, None
    keep = int(budget * CHARS_PER_TOKEN)
    dropped = approx_tokens(cached) - budget
    return (cached[:keep],
            f"Documentation truncated to fit the context window: about "
            f"{dropped:,} tokens were dropped from the end. Treat any "
            f"guidance as partial.")


def bundled_path(*parts):
    """Resolve a data file in both a source checkout and a frozen build.

    PyInstaller unpacks bundled data to a temporary directory and points
    sys._MEIPASS at it. Without this, every path that works in development
    breaks in the shipped executable -- and breaks at run time, not build
    time, which is the worst moment to find out.
    """
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
    return base.joinpath(*parts)


class LlamaCppProvider:
    """A GGUF model read directly, with no server process.

    WHY THIS EXISTS ALONGSIDE OLLAMA
    Ollama is a separate Go server. PyInstaller bundles Python, so it cannot
    package Ollama -- a build that uses it ships an executable that silently
    requires the user to install and run something else. llama-cpp-python is
    a wheel with the inference engine compiled in, so PyInstaller can bundle
    it and the application becomes one executable plus a model file beside
    it.

    Develop against Ollama (faster to swap models), ship with this. The
    weights are identical: point `model_path` at the same GGUF. Ollama keeps
    its copy in a content-addressed blob store, so extract it once:

        cp ~/.ollama/models/blobs/sha256-5ee4f07c* deploy/qwen2.5-3b-q4.gguf

    INSTALLING WITHOUT A COMPILER
    The source build needs a C++ toolchain. Prebuilt CPU wheels avoid that:

        pip install llama-cpp-python --prefer-binary \\
            --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cpu

    THE MODEL IS LOADED ONCE
    Loading 1.93 GB takes seconds. The instance holds it, so construct the
    provider at application start and keep it -- never per request. That is
    also why this class is not picklable and must not be put in deploy/:
    what gets shipped is the GGUF file, not a serialised object.
    """

    name = "llamacpp"

    def __init__(self, model_path=None, context=8192, threads=None,
                 gpu_layers=0):
        # 8192 rather than the full 32768: KV cache memory grows with the
        # window, and a context this size already fits a NIST section plus a
        # finding. fit_context() trims to whatever is set here.
        self.model_path = Path(model_path or bundled_path(
            "deploy", "qwen2.5-3b-q4.gguf"))
        self.context, self.threads, self.gpu_layers = (context, threads,
                                                       gpu_layers)
        self.model = str(self.model_path.name)
        self._llm = None

    def available(self):
        try:
            import llama_cpp  # noqa: F401
        except ImportError:
            return False, ("llama-cpp-python is not installed -- see the "
                           "class docstring for the prebuilt-wheel command")
        if not self.model_path.is_file():
            return False, f"no GGUF at {self.model_path}"
        size = self.model_path.stat().st_size / 1e9
        return True, f"{self.model_path.name} ({size:.2f} GB)"

    def _load(self):
        if self._llm is None:
            from llama_cpp import Llama
            self._llm = Llama(
                model_path=str(self.model_path),
                n_ctx=self.context,
                n_threads=self.threads,          # None -> all cores
                n_gpu_layers=self.gpu_layers,    # 0 -> CPU only, portable
                seed=42,
                verbose=False,
            )
        return self._llm

    def complete(self, system, user, cached=None, max_tokens=2000,
                 temperature=0.2, retries=1, schema=None):
        llm = self._load()
        merged = system if not cached else f"{system}\n\n{cached}"
        merged, note = fit_context(merged, user, self.context, max_tokens)

        # create_chat_completion applies the chat template embedded in the
        # GGUF, so the prompt is formatted the way the model was tuned --
        # hand-rolling ChatML markers here would silently degrade output.
        kw = {}
        if schema:
            # Same guarantee as Ollama's `format`, expressed the way
            # llama-cpp takes it: a grammar compiled from the schema.
            kw["response_format"] = {"type": "json_object", "schema": schema}
        out = llm.create_chat_completion(
            messages=[{"role": "system", "content": merged},
                      {"role": "user", "content": user}],
            max_tokens=max_tokens,
            temperature=temperature,
            **kw,
        )
        usage = out.get("usage", {})
        return out["choices"][0]["message"]["content"], {
            "provider": self.name, "model": self.model,
            "input": usage.get("prompt_tokens", 0),
            "output": usage.get("completion_tokens", 0),
            "context_note": note,
        }


class OllamaProvider:
    """A local model over Ollama's HTTP API.

    Uses `requests` rather than the `ollama` package -- one endpoint, one
    POST, no reason to add a dependency for it.
    """

    name = "ollama"

    def __init__(self, model=OLLAMA_MODEL, url=OLLAMA_URL, context=32768):
        self.model, self.url, self.context = model, url, context

    def available(self):
        import requests
        try:
            r = requests.get(f"{self.url}/api/tags", timeout=5)
            names = [m["name"] for m in r.json().get("models", [])]
            return self.model in names, names
        except Exception as e:
            return False, str(e)

    def complete(self, system, user, cached=None, max_tokens=2000,
                 temperature=0.2, retries=2, schema=None):
        import requests

        # Ollama has no API-level cache control -- it keeps its own KV cache
        # for a repeated prefix. Putting the stable documents first in the
        # system message is what lets that work, so the split phase 14 makes
        # for Claude's cache_control helps here too, for a different reason.
        merged = system if not cached else f"{system}\n\n{cached}"
        merged, note = fit_context(merged, user, self.context, max_tokens)

        payload = {
            "model": self.model,
            "messages": [{"role": "system", "content": merged},
                         {"role": "user", "content": user}],
            "stream": False,
            "options": {
                # Low temperature: this task is rewriting retrieved text, not
                # composing. Creativity here shows up as invention.
                "temperature": temperature,
                "num_ctx": self.context,
                "num_predict": max_tokens,
                "seed": 42,
            },
        }
        if schema:
            # Ollama constrains generation to the schema, so the model cannot
            # emit an action without a source and a quote -- there is no
            # shape in the grammar for one.
            payload["format"] = schema
        last = None
        for attempt in range(retries + 1):
            try:
                r = requests.post(f"{self.url}/api/chat", json=payload,
                                  timeout=600)
                r.raise_for_status()
                d = r.json()
                return d["message"]["content"], {
                    "provider": self.name, "model": self.model,
                    "input": d.get("prompt_eval_count", 0),
                    "output": d.get("eval_count", 0),
                    "seconds": round(d.get("total_duration", 0) / 1e9, 2),
                    "context_note": note,
                }
            except Exception as e:
                last = e
                time.sleep(2 ** attempt)
        raise RuntimeError(
            f"Ollama did not answer after {retries + 1} attempts: {last}. "
            f"Is it running? `ollama serve`, then `ollama pull {self.model}`.")


class AnthropicProvider:
    """Claude. Sends the capture's derived data off the machine -- an
    explicit choice, never the default."""

    name = "anthropic"

    def __init__(self, model=ANTHROPIC_REASONING, context=200_000):
        self.model, self.context = model, context

    def available(self):
        try:
            import anthropic  # noqa: F401
        except ImportError:
            return False, "the anthropic package is not installed"
        if not (os.environ.get("ANTHROPIC_API_KEY")
                or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
            return False, ("no API key in the environment (an `ant auth "
                           "login` profile also works)")
        return True, self.model

    def complete(self, system, user, cached=None, max_tokens=16000,
                 temperature=None, retries=3, schema=None):
        import anthropic
        client = anthropic.Anthropic()

        blocks = [{"type": "text", "text": system}]
        if cached:
            # Stable across every detection of a class, so it earns a cache
            # breakpoint; the varying detection stays in messages.
            blocks.append({"type": "text", "text": cached,
                           "cache_control": {"type": "ephemeral"}})

        last = None
        for attempt in range(retries):
            try:
                oc = {"effort": "high"}
                if schema:
                    oc["format"] = {"type": "json_schema", "schema": schema}
                resp = client.messages.create(
                    model=self.model, max_tokens=max_tokens,
                    thinking={"type": "adaptive"},
                    output_config=oc,
                    system=blocks,
                    messages=[{"role": "user", "content": user}],
                )
                break
            except anthropic.RateLimitError as e:
                last = e
                time.sleep(int(e.response.headers.get("retry-after",
                                                      2 ** attempt)))
            except anthropic.APIStatusError as e:
                if e.status_code >= 500:
                    last = e
                    time.sleep(2 ** attempt)
                else:
                    raise
            except anthropic.APIConnectionError as e:
                last = e
                time.sleep(2 ** attempt)
        else:
            raise last

        if resp.stop_reason == "refusal":
            cat = getattr(resp.stop_details, "category", "unknown")
            return None, {"provider": self.name, "model": self.model,
                          "error": f"declined ({cat})"}

        return ("".join(b.text for b in resp.content if b.type == "text"),
                {"provider": self.name, "model": self.model,
                 "input": resp.usage.input_tokens,
                 "output": resp.usage.output_tokens,
                 "cache_read": getattr(resp.usage,
                                       "cache_read_input_tokens", 0),
                 "context_note": None})


def get_provider(name="ollama", **kw):
    """ollama for development, llamacpp for a packaged build, anthropic to
    deliberately send derived data off the machine."""
    if name == "ollama":
        return OllamaProvider(**kw)
    if name == "llamacpp":
        return LlamaCppProvider(**kw)
    if name == "anthropic":
        return AnthropicProvider(**kw)
    raise ValueError(f"unknown provider {name!r}; use 'ollama', 'llamacpp' "
                     f"or 'anthropic'")


if __name__ == "__main__":
    for n in ("ollama", "llamacpp", "anthropic"):
        p = get_provider(n)
        ok, detail = p.available()
        print(f"{n:<12}{'READY' if ok else 'not available':<16}{detail}")
    print()
    p = get_provider("ollama")
    if p.available()[0]:
        txt, usage = p.complete(
            system="Answer in one short sentence. Never invent facts.",
            user="A network flow lasted 4.2 seconds with 3 packets sent and "
                 "0 returned. Describe it plainly.",
            max_tokens=120)
        print("sample:", txt.strip()[:200])
        print("usage :", usage)
