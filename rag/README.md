# Retrieval (RAG) assets

Used by the pipeline's report scripts (14 and 15). The C# and FastAPI application does not read these files.

| Path | Contents |
|---|---|
| `knowledge/` | 31 files: incident-response playbooks, attack profiles, the SHAP caveats file, the 74-feature glossary, the dataset scope note and INDEX.md |
| `config/knowledge_map.py` | Class-to-document lookup for the 16 classes and the ambiguous-pair rules. It finds `knowledge/` at `../knowledge` |
| `_sources/manifest.json` | Registers every cited source document |
| `_sources/SHA256SUMS.txt` | SHA-256 of the 88 files in the source archive |

The source archive itself (26 PDFs, HTML pages and text caches, about 98.7 MiB) is not in Git. It holds third-party publications. Copy the archive to `rag/_sources/`, then check it:

```
cd rag/_sources
sha256sum -c SHA256SUMS.txt
```

Check that the class map finds its corpus:

```
python rag/config/knowledge_map.py     # expect: 33/33 knowledge files present
```
