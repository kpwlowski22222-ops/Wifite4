# Multi-part archives (large project assets)

GitHub rejects individual files larger than **100 MB**. Large local trees
(`models/`, `data/finetune/`, `toolboxes/`, …) are therefore shipped as
**zstd-compressed tar streams split into ≤90 MB parts**.

## Layout

| Archive prefix | Restores to | Notes |
|----------------|-------------|--------|
| `models.tar.zst.part_*` | `models/` | Finetuned weights / local model artifacts |
| `data-finetune.tar.zst.part_*` | `data/finetune/` | Finetune workspace under `data/` |
| `toolboxes.tar.zst.part_*` | `toolboxes/` | Cloned third-party tool repos (~GB) |
| `wordlists.tar.zst` | `wordlists/` | Small; single file |
| `datasets.tar.zst` | `datasets/` | Small; single file |

Checksums (when present): `MANIFEST.sha256`.

## Restore (Linux)

Needs `tar`, `zstd`, and enough free disk for the expanded tree.

```bash
# From the repository root:

# Single-file archives
zstd -d -c archives/wordlists.tar.zst | tar -xf -
zstd -d -c archives/datasets.tar.zst  | tar -xf -

# Multi-part streams (concat → decompress → extract)
cat archives/models.tar.zst.part_*        | zstd -d | tar -xf -
cat archives/data-finetune.tar.zst.part_* | zstd -d | tar -xf -
cat archives/toolboxes.tar.zst.part_*     | zstd -d | tar -xf -
```

Optional integrity check:

```bash
cd archives && sha256sum -c MANIFEST.sha256
```

## Rebuild without archives

If you prefer not to download multi-GB archives:

```bash
# Toolboxes: clone from catalog (see scripts)
python scripts/fetch_toolboxes.py --all --limit 15
python scripts/prepare_toolboxes.py --all

# Models: pull via Ollama / Hugging Face (see README)
ollama pull qwen2.5-coder:14b
# or: python scripts/model_downloader.py pull
```

## Recreate archives (maintainers)

```bash
# Example: models → 90 MiB parts
tar -C . -cf - models | zstd -T0 -3 | split -b 90M - archives/models.tar.zst.part_

# Refresh checksums
cd archives && sha256sum * > MANIFEST.sha256
```

## What is **not** archived

| Path | Why |
|------|-----|
| `.venv/` | Reinstall with `pip install -r requirements.txt` |
| `workspace/` | Local finetune scratch (often multi-10 GB) |
| `.claude/worktrees/` | Agent worktrees — local only |
| `.env`, `client_secret_*.json`, `*.pem` | Secrets — never commit |
| Live `Kismet-*.kismet` captures | Operator machine noise |

Parts are intended for **Git LFS** tracking so the Git history stays small.
