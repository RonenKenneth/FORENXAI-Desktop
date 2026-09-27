from threading import Lock

from llama_cpp import Llama

from app.services.logging_service import (
    logger,
)

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

            logger.error(
                "Qwen model file not found | Model path: %s",
                model_path,
            )

            raise FileNotFoundError(
                f"Qwen model not found: {model_path}"
            )

        print(
            "[FORENXAI] Loading Qwen model...",
            flush=True
        )

        logger.info(
            "Qwen model loading started | Model path: %s",
            model_path,
        )

        try:

            _llm = Llama(
                model_path=str(model_path),
                n_ctx=4096,
                n_threads=4,
                verbose=False
            )

        except Exception as error:

            logger.exception(
                "Qwen model loading failed | Model path: %s | "
                "Error: %s: %s",
                model_path,
                type(error).__name__,
                error,
            )

            raise

        print(
            "[FORENXAI] Qwen model loaded.",
            flush=True
        )

        logger.info(
            "Qwen model loaded successfully | Model path: %s | "
            "Context: 4096 | Threads: 4",
            model_path,
        )

        return _llm