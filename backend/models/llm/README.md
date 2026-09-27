# Language model (not stored in Git)

The backend narrates results with a local Qwen 2.5 3B model, 4-bit quantised, in GGUF format.

| | |
|---|---|
| File name | `qwen2.5-3b-q4.gguf` |
| Location | `backend/models/llm/qwen2.5-3b-q4.gguf` |
| Size | 1,929,903,008 bytes (about 1.8 GiB) |
| SHA-256 | `5ee4f07cdb9beadbbb293e85803c569b01bd37ed059d2715faa7bb405f31caa6` |

The file is too large for a normal Git push (GitHub rejects files over 100 MB) and `.gitignore` excludes `*.gguf`.
Copy the file from the team share, then check it:

```
cd backend
python verify_bundle.py --llm
```

or directly with `sha256sum backend/models/llm/qwen2.5-3b-q4.gguf`. The application works without the model:
the panels still render, only the narration is skipped.
