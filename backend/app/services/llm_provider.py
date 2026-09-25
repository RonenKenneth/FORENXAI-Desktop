"""
llm_provider.py
---------------
The local Qwen instance, loaded once.

ON SPEED
Generation dominates the recommendation panel: retrieval is ~100 ms and a
generation is over two minutes on this machine. Two things decide that
number, and only one of them is a setting here.

  1. Whether llama-cpp-python was built with CUDA. It was not -- the wheel
     installed here ships ggml-cpu.dll and no ggml-cuda.dll, and
     llama_cpp.llama_supports_gpu_offload() returns False. n_gpu_layers is
     therefore ignored, silently. Installing a CUDA wheel is the single
     largest available speedup and it is a deployment decision, not a code
     one:

         pip install --force-reinstall --no-cache-dir \
           --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cu124 \
           llama-cpp-python

     Check it took with llama_cpp.llama_supports_gpu_offload(), then set
     N_GPU_LAYERS below to -1.

  2. Prompt length. Prefill measured at ~76 tokens/second on this CPU, so a
     3,200-token prompt costs ~42 s before the first output token. Cutting
     prompt tokens is worth more than any threading change.

Thread count was measured rather than assumed: 4 and 8 threads were within
a percent of each other (76.4 and 77.2 tok/s prefill) and 12 was distinctly
worse (54.4 tok/s) through oversubscription on a 12-logical-core machine.
The default below follows physical cores and caps at 8.
"""
import os
from threading import Lock

from llama_cpp import Llama

from app.utils.runtime_paths import (
    get_llm_model_path,
)


# Ignored unless the installed wheel has CUDA support; see the note above.
# -1 offloads every layer.
N_GPU_LAYERS = 0

CONTEXT_TOKENS = 4096


def _thread_count() -> int:
    """Physical cores, capped at 8. Measured, not guessed -- see above."""
    logical = os.cpu_count() or 4

    return max(1, min(8, logical // 2))


_llm = None
_llm_lock = Lock()

# One generation at a time. A llama.cpp context is not re-entrant: two
# threads generating on it at once -- two analyses reaching the
# recommendation stage together -- corrupt its state and abort the whole
# backend (GGML_ASSERT / segmentation fault, reproduced). Callers hold this
# around every call to the model; a second request waits its turn.
generation_lock = Lock()


def get_llm() -> Llama:
    global _llm

    if _llm is not None:
        return _llm

    with _llm_lock:

        if _llm is not None:
            return _llm

        model_path = get_llm_model_path()

        if not model_path.exists():
            raise FileNotFoundError(
                f"Qwen model not found: {model_path}"
            )

        print(
            "[FORENXAI] Loading Qwen model...",
            flush=True
        )

        threads = _thread_count()

        _llm = Llama(
            model_path=str(model_path),
            n_ctx=CONTEXT_TOKENS,
            n_threads=threads,
            n_gpu_layers=N_GPU_LAYERS,
            verbose=False
        )

        try:
            from llama_cpp import llama_supports_gpu_offload
            gpu_capable = bool(llama_supports_gpu_offload())
        except Exception:                            # noqa: BLE001
            gpu_capable = False

        print(
            f"[FORENXAI] Qwen model loaded "
            f"({threads} threads, "
            f"{CONTEXT_TOKENS} ctx, "
            + (
                f"{N_GPU_LAYERS} GPU layers)"
                if gpu_capable
                else "CPU only -- this wheel has no CUDA support)"
            ),
            flush=True
        )

        return _llm