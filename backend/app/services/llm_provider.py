from threading import Lock

from llama_cpp import Llama

from app.utils.runtime_paths import (
    get_llm_model_path,
)


_llm = None
_llm_lock = Lock()


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

        _llm = Llama(
            model_path=str(model_path),
            n_ctx=4096,
            n_threads=4,
            verbose=False
        )

        print(
            "[FORENXAI] Qwen model loaded.",
            flush=True
        )

        return _llm