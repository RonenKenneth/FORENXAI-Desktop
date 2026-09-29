"""
doc_tree.py
-----------
Vectorless retrieval INSIDE a knowledge document, after knowledge_map.py has
already chosen which documents to open.

WHY A SECOND RETRIEVAL STAGE
knowledge_map.py answers "which playbook" exactly -- the classifier named the
class, so the file is known. It does not answer "which section of it". Today
the whole file goes into the prompt, and when the placeholders are replaced
with real NIST SP 800-61r3 sections the file will be long enough that
fit_context() starts cutting it blind, from the end, with no idea what it
dropped. Choosing the sections deliberately is what this module adds.

THE TREE IS PARSED, NOT GENERATED
PageIndex builds its tree with an LLM because a PDF has no machine-readable
structure. Markdown does: `##` IS the tree. Parsing it is deterministic, free,
and cannot invent a section that is not in the file -- so the LLM is spent on
the one step that actually needs judgement (which sections answer this), never
on describing what the document contains.

  PageIndex notebook           this
  -------------------------    ----------------------------------
  GPT-4o reads the PDF         re.finditer over `#` headings
  cloud doc_id + polling       nothing to upload, nothing to cache
  node summary from an LLM     first sentence of the section
  LLM picks node_ids           LLM picks node_ids   <- the same step
  trusts the ids returned      ids validated against the tree

That last row matters. A model asked for `["0003","0007"]` will occasionally
return `"0042"`, or a section title, or a page number. An id that is not in
the tree is dropped, and if nothing survives the whole document is used --
retrieval degrades to today's behaviour rather than to an empty prompt.

Usage:
    forest = build_forest({"incident_response/denial_of_service.md": text})
    sel    = search("Slowloris, 165 flows, containment", forest, llm)
    docs   = render_selection(forest, sel["node_list"])
"""
import re
import json

# `#` through `######` at the start of a line. Fenced code blocks are not a
# concern here: the knowledge corpus is prose, and a `#` inside a fence would
# only ever add a spurious section, never lose a real one.
HEADING = re.compile(r"^(#{1,6})[ \t]+(.+?)[ \t]*$", re.M)

# What the model is allowed to return. Ollama and llama.cpp both constrain
# generation to this, so there is no shape in the grammar for an answer
# without a node list.
TREE_SEARCH_SCHEMA = {
    "type": "object",
    "properties": {
        "thinking": {"type": "string",
                     "description": "Which sections are relevant and why."},
        "node_list": {"type": "array", "items": {"type": "string"},
                      "description": "node_id values copied exactly from the "
                                     "tree. Never invent one."},
    },
    "required": ["thinking", "node_list"],
}

# Section 6 of the crash course -- domain expertise as prompt text rather than
# a fine-tuned embedding model. These are the routing rules a responder
# applies without thinking about it, written down so a 3B model can apply them
# too. Edit them when the corpus changes; nothing has to be re-indexed.
RETRIEVAL_RULES = """\
- containment, blocking, rate limiting, timeouts   -> the Containment section
- "is this real", baselines, triage, what to record -> Detection and analysis
- restore, roll back, reopen, after the incident   -> Eradication and recovery
- slow-rate versus high-rate, Slowloris versus DoS -> any section that
  distinguishes the sub-types, plus both mitigation sections
- false positives, authorised scanners, monitoring probes, health checks
  -> whichever section names them
Prefer a specific subsection over its parent. Return the parent only when the
answer genuinely spans all of its children. Two or three sections is usually
right; returning everything defeats the purpose."""


def _summary(body, limit=150):
    """First real sentence of a section -- the node summary, for free.

    PageIndex pays an LLM call per node for this. The opening sentence of a
    procedure section says what the section is for, which is all the tree
    search needs to route on.
    """
    for line in (body or "").splitlines():
        line = line.strip().lstrip("> ").strip()
        if line and not line.startswith(("#", "|", "-", "*", "```")):
            return line[:limit]
    return ""


def build_tree(text, path, next_id=1):
    """One document -> nested nodes. Returns (nodes, next_free_id).

    A node's `text` is its own body only; children carry theirs. Selecting a
    parent pulls the subtree back together in render_selection().
    """
    marks = list(HEADING.finditer(text or ""))
    if not marks:
        # No headings: the file is one section. Still addressable, still
        # citable, just not subdividable.
        return ([{"node_id": f"{next_id:04d}", "title": path, "path": path,
                  "level": 1, "summary": _summary(text), "text": text or "",
                  "nodes": []}], next_id + 1)

    flat = []
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        flat.append((len(m.group(1)), m.group(2).strip(),
                     text[m.end():end].strip()))

    root, stack = [], []
    for level, title, body in flat:
        node = {"node_id": f"{next_id:04d}", "title": title, "path": path,
                "level": level, "summary": _summary(body), "text": body,
                "nodes": []}
        next_id += 1
        while stack and stack[-1]["level"] >= level:
            stack.pop()
        (stack[-1]["nodes"] if stack else root).append(node)
        stack.append(node)
    return root, next_id


def build_forest(documents):
    """{path: text} -> one node list spanning every document.

    Ids are unique across the whole forest, so the tree search picks sections
    from several playbooks in one call -- which is exactly what an ambiguous
    pair needs.
    """
    forest, next_id = [], 1
    for path, text in documents.items():
        nodes, next_id = build_tree(text, path, next_id)
        forest.extend(nodes)
    return forest


def walk(nodes):
    for n in nodes:
        yield n
        yield from walk(n["nodes"])


def compress(nodes):
    """Titles and summaries only -- what the model reasons over.

    Sending full section text here would cost more than sending the whole
    document, which is the thing this module exists to avoid.
    """
    return [{"node_id": n["node_id"], "source": n["path"],
             "title": n["title"], "summary": n["summary"],
             **({"children": compress(n["nodes"])} if n["nodes"] else {})}
            for n in nodes]


def _prune(forest, ids):
    """Selected ids, minus any whose ancestor is also selected.

    render_selection() emits a node's whole subtree, so keeping both a parent
    and its child would print the child twice and pay for it twice.
    """
    ids = list(dict.fromkeys(ids))
    sel, keep = set(ids), []

    def rec(nodes, under_selection):
        for n in nodes:
            hit = n["node_id"] in sel
            if hit and not under_selection:
                keep.append(n)
            rec(n["nodes"], under_selection or hit)

    rec(forest, False)
    rank = {i: k for k, i in enumerate(ids)}
    return sorted(keep, key=lambda n: rank[n["node_id"]])


def search(query, forest, llm, rules=RETRIEVAL_RULES, system=None,
           always=()):
    """LLM tree search. Returns the selection plus what it took to get it.

    `node_list` only ever contains ids that exist in `forest`. Everything the
    model returned is kept in `rejected` so a reviewer can see whether it was
    inventing ids, which is the failure this stage would otherwise hide.

    `always` is a list of title substrings that are included whether the model
    picked them or not. Measured reason: qwen2.5:3b selected the slow-rate/
    high-rate section on one run of an ambiguous Slowloris finding and skipped
    it on the next, from the same query. A dropped section is an omission
    rather than an invention -- verification still blocks unsourced actions --
    but on an ambiguous pair the omission is the difference between naming two
    candidate sub-types and presenting one. Where the pipeline already knows
    deterministically that a section is required, it should not be asking a
    3B model to remember.
    """
    tree = compress(forest)
    prompt = f"""Below is the section structure of the response documentation
that applies to this detection. Decide which sections an investigator needs
to read to act on it.

SITUATION
{query}

SECTIONS
{json.dumps(tree, indent=1)}

ROUTING RULES
{rules}

Copy `node_id` values exactly as they appear above. Never write an id that is
not in the list. If nothing above is relevant, return an empty node_list."""

    text, usage = llm.complete(
        system=(system or "You select documentation sections. You do not "
                          "answer the question and you do not invent ids."),
        user=prompt, max_tokens=600, schema=TREE_SEARCH_SCHEMA)

    valid = {n["node_id"] for n in walk(forest)}
    try:
        payload = json.loads(text or "{}")
    except json.JSONDecodeError:
        payload = {}
    returned = [str(x).strip() for x in (payload.get("node_list") or [])]
    node_list = [i for i in returned if i in valid]

    forced = [n["node_id"] for n in walk(forest)
              if any(s.lower() in n["title"].lower() for s in always)
              and n["node_id"] not in node_list]
    node_list += forced

    return {"thinking": payload.get("thinking", ""),
            "node_list": _prune(forest, node_list),
            "returned": returned,
            "rejected": [i for i in returned if i not in valid],
            "forced": forced,
            "fell_back": not node_list,
            "usage": usage}


def render_selection(forest, nodes, fallback_documents=None):
    """Selected nodes -> ({path: text shown}, rendered block).

    The returned mapping is what verify_claims() checks quotes against, so it
    must be exactly what the model was shown -- never the full document. A
    quote from a section that was not selected is not a quote from the
    evidence.

    `fallback_documents` is used when the tree search found nothing, so a bad
    search degrades to today's whole-document behaviour rather than to a
    prompt with no documentation in it.
    """
    if not nodes:
        docs = dict(fallback_documents or {})
        block = "\n\n".join(f"=== {p} ===\n{t}" for p, t in docs.items())
        return docs, block

    shown, parts = {}, []
    for n in nodes:
        body = _subtree_text(n)
        shown[n["path"]] = (shown.get(n["path"], "") + "\n\n" + body).strip()
        parts.append(f"=== {n['path']} > {n['title']} ===\n{body}")
    return shown, "\n\n".join(parts)


def _subtree_text(node):
    """A node's own body plus every descendant, headings included.

    Selecting a parent has to give the model the parent's children, or a
    quote the investigator can see in the file would fail verification.
    """
    out = [node["text"]] if node["text"] else []
    for c in node["nodes"]:
        out.append("#" * c["level"] + " " + c["title"])
        out.append(_subtree_text(c))
    return "\n\n".join(p for p in out if p).strip()


def demo():
    """Self-check: parse, nest, compress, validate, prune, render."""
    doc = """# Denial of service - response

Intro line.

## 4.1 Detection and analysis

Record the source addresses and the request rate.

## 4.2 Containment

Apply rate limiting at the perimeter for the identified source addresses.

### 4.2.1 Timeouts

Increase the connection timeout floor.
"""
    forest = build_forest({"a.md": doc})
    ids = [n["node_id"] for n in walk(forest)]
    assert ids == ["0001", "0002", "0003", "0004"], ids
    assert forest[0]["title"] == "Denial of service - response"
    assert [c["title"] for c in forest[0]["nodes"]] == [
        "4.1 Detection and analysis", "4.2 Containment"], "nesting"
    assert forest[0]["nodes"][1]["nodes"][0]["title"] == "4.2.1 Timeouts", \
        "H3 must nest under its H2"
    assert forest[0]["nodes"][0]["summary"].startswith("Record the source")

    # A parent pulls its children in, so a quote from 4.2.1 verifies even
    # when only 4.2 was selected.
    sel = [n for n in walk(forest) if n["node_id"] == "0003"]
    shown, block = render_selection(forest, sel)
    assert "Increase the connection timeout floor." in shown["a.md"]
    assert "4.2.1 Timeouts" in block

    # Selecting parent and child must not duplicate the child.
    both = _prune(forest, ["0003", "0004"])
    assert [n["node_id"] for n in both] == ["0003"], [n["node_id"] for n in both]

    # No headings at all -> one node, still citable.
    plain = build_forest({"b.md": "just prose, no headings"})
    assert len(plain) == 1 and plain[0]["text"] == "just prose, no headings"

    # Nothing selected -> fall back to whole documents, never to empty.
    shown, block = render_selection(forest, [], {"a.md": doc})
    assert shown == {"a.md": doc} and "=== a.md ===" in block

    # Two documents share one id space.
    two = build_forest({"a.md": doc, "b.md": "# T\n\nbody"})
    assert len({n["node_id"] for n in walk(two)}) == len(list(walk(two)))
    print("doc_tree self-check passed")


if __name__ == "__main__":
    demo()
