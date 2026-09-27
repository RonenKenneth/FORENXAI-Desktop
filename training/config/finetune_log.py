"""
finetune_log.py
---------------
Records every panel generation as a candidate training pair.

WHY LOG NOW RATHER THAN LATER
Fine-tuning needs (prompt, good output) pairs. The prompts already exist --
phase 14 builds them on every run. What does not exist is the good output,
and the only way to get it is for a person to correct a real one. That
correction is cheapest at the moment you are already reading the output to
see whether it is any good.

So: every --call run appends what the model actually produced, marked
unreviewed. You correct the ones that are wrong. Export drops everything
still unreviewed, because an uncorrected output is the model's current
behaviour and training on it teaches nothing.

THE TWO FAILURES WORTH CORRECTING FIRST
The eval already found them, and they are the whole reason to fine-tune:

  reliability   a class with F1 0.6703 described as "strong model
                confidence" instead of hedged
  ambiguity     Slowloris predicted without naming DoS, when every flow in
                the group had DoS as runner-up

Correct those two patterns and leave the rest alone. A hundred examples
concentrated on two failures beats a thousand spread thin.

FORMAT
JSONL, one record per line, messages in the shape every LoRA trainer reads
(axolotl, unsloth, llama-factory). Extra keys sit outside `messages` and are
stripped on export.

Usage:
  from config.finetune_log import log_pair
  log_pair(panel, provider, model, context={"class": "Slowloris"})
"""
import json
from pathlib import Path
from datetime import datetime

PROJECT = Path(__file__).resolve().parent.parent
PAIRS = PROJECT / "results" / "finetune" / "pairs.jsonl"


def log_pair(panel, provider, model, system, context=None):
    """Append one generation as an unreviewed candidate.

    Never overwrites and never deduplicates: two runs of the same panel that
    produced different text are two data points, and which one you correct
    is a judgement you make while reading them.
    """
    if not panel.get("narrative"):
        return None                      # nothing generated, nothing to learn

    PAIRS.parent.mkdir(parents=True, exist_ok=True)
    user = ((panel.get("cached_context") or "") + "\n\n"
            + panel["prompt"]).strip()
    record = {
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
            {"role": "assistant", "content": panel["narrative"]},
        ],
        # Everything below is metadata, stripped on export.
        "panel": panel["panel"],
        "provider": provider,
        "model": model,
        "logged_at": datetime.now().isoformat(timespec="seconds"),
        "reviewed": False,
        # Put the corrected text here. Leaving it null means "the model's
        # output was fine" only if you also set reviewed to true; otherwise
        # the record is simply not exported.
        "assistant_corrected": None,
        "correction_reason": None,
        "context": context or {},
    }
    with open(PAIRS, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    return record


def read_all(path=PAIRS):
    if not Path(path).is_file():
        return []
    out = []
    for i, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError as e:
            raise ValueError(f"{path}:{i} is not valid JSON -- {e}") from e
    return out
