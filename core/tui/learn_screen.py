#!/usr/bin/env python3
"""Learn screen — fine-tune planners on simulated polymorphic targets."""
from __future__ import annotations

from typing import List

from core.tui.base_screen import BaseScreen
from core.learn.domains import LEARN_MODES, get_mode


class LearnScreen(BaseScreen):
    def __init__(self, stdscr, parent_callback, activity_log: List[str], **kwargs):
        super().__init__(stdscr, parent_callback, activity_log, **kwargs)
        self.title = "Learn — simulate · plan · fine-tune · MemOS memory"
        self._build_menu()

    def _build_menu(self) -> None:
        items = []
        for key, meta in LEARN_MODES.items():
            items.append((meta["label"], lambda k=key: self.start_learn(k)))
        items.extend([
            ("View saved adapters / datasets", self.view_adapters),
            ("MemOS long-term memory stats", self.memos_stats),
            ("Search MemOS skills (L2)", self.memos_search_skills),
            ("Back to Main Menu", self.parent_callback),
        ])
        self.menu_items = items
        self.primary_items = list(items)

    def start_learn(self, mode_key: str) -> None:
        mode = get_mode(mode_key)
        self.activity_log.append(f"=== Learn: {mode.get('label')} ===")
        self.activity_log.append(f"[i] Goal: {mode.get('goal')}")
        self.activity_log.append(
            "[i] Pipeline: polymorphic sim targets → Ollama/AI plans → "
            "SFT jsonl → optional QLoRA → MemOS L1/L2/L3 memory"
        )
        n_raw = self.get_input(
            "How many simulated targets? [3]"
        ).strip()
        try:
            n = int(n_raw) if n_raw else 3
        except ValueError:
            n = 3
        n = max(1, min(n, 8))
        heavy = self.get_input(
            "Run GPU QLoRA now? needs torch+VRAM [y/N]"
        ).strip().lower() in ("y", "yes", "1")
        if heavy:
            import os
            os.environ["KFIOSA_LEARN_HEAVY"] = "1"
        self.activity_log.append(
            f"[*] Starting learn session mode={mode_key} targets={n} "
            f"heavy_ft={heavy}…"
        )

        def _run():
            try:
                from core.learn.session import run_learn_session
                res = run_learn_session(
                    mode_key,
                    n_targets=n,
                    run_finetune=True,
                    epochs=1,
                    ai_backend=self.ai_backend,
                    on_event=lambda m: self.activity_log.append(m),
                )
                if res.get("ok"):
                    self.activity_log.append(
                        f"[+] Learn done: samples={res.get('n_samples')} "
                        f"jsonl={res.get('jsonl')}"
                    )
                    ft = res.get("finetune") or {}
                    self.activity_log.append(
                        f"[i] Fine-tune: ok={ft.get('ok')} mode={ft.get('mode')} "
                        f"{ft.get('note') or ft.get('adapter_dir') or ''}"
                    )
                    self.activity_log.append(
                        f"[i] MemOS cube={res.get('memos_cube')} "
                        f"registry={res.get('registry')}"
                    )
                    for p in (res.get("plans") or [])[:5]:
                        self.activity_log.append(
                            f"  · sim={p.get('sim')} steps={p.get('steps')} "
                            f"src={p.get('source')}"
                        )
                else:
                    self.activity_log.append(f"[!] Learn failed: {res.get('error')}")
            except Exception as e:
                self.activity_log.append(f"[!] Learn error: {e}")

        self._spawn(_run)

    def view_adapters(self) -> None:
        self.activity_log.append("=== Saved learn adapters / datasets ===")
        try:
            from core.learn.session import list_saved_adapters, learn_data_dir
            from core.learn.domains import LEARN_MODES
            reg = list_saved_adapters()
            adapters = reg.get("adapters") or {}
            if not adapters:
                self.activity_log.append("[i] No learn sessions yet — pick a mode above.")
            for key, meta in adapters.items():
                self.activity_log.append(
                    f"[+] {key}: samples_session={meta.get('n_samples_session')} "
                    f"last={meta.get('last_session')} "
                    f"ft={((meta.get('finetune') or {}).get('mode'))}"
                )
                self.activity_log.append(
                    f"    train={meta.get('train_jsonl')}"
                )
            for key in LEARN_MODES:
                d = learn_data_dir(key)
                roll = d / "train.jsonl"
                if roll.is_file():
                    n = sum(1 for _ in open(roll, encoding="utf-8") if _.strip())
                    self.activity_log.append(f"[i] {key} rolling train.jsonl lines={n}")
        except Exception as e:
            self.activity_log.append(f"[!] {e}")

    def memos_stats(self) -> None:
        self.activity_log.append("=== MemOS long-term memory (local) ===")
        try:
            from core.memory.memos_ltm import stats, list_cubes
            st = stats()
            self.activity_log.append(
                f"[i] total={st.get('total')} cubes={st.get('cubes')} "
                f"db={st.get('db')}"
            )
            self.activity_log.append(
                f"[i] layers={st.get('by_layer')} "
                f"(inspired by {st.get('memos_project')})"
            )
            for c in list_cubes()[:12]:
                self.activity_log.append(
                    f"  · cube={c.get('cube_id')} domain={c.get('domain')} "
                    f"name={c.get('name')}"
                )
            import os
            if (os.environ.get("MEMOS_URL") or "").strip():
                self.activity_log.append(
                    f"[i] Remote MemOS URL set: {os.environ.get('MEMOS_URL')}"
                )
            else:
                self.activity_log.append(
                    "[i] Local-only. Optional: MEMOS_URL + MEMOS_API_KEY "
                    "for MemTensor cloud/self-host push."
                )
        except Exception as e:
            self.activity_log.append(f"[!] memos stats: {e}")

    def memos_search_skills(self) -> None:
        q = self.get_input("Search MemOS skills/traces (e.g. wifi deauth)").strip()
        if not q:
            return
        try:
            from core.memory.memos_ltm import search_memory
            r = search_memory(q, layer="", limit=8)
            self.activity_log.append(
                f"=== MemOS search '{q}' count={r.get('count')} ==="
            )
            for row in r.get("results") or []:
                self.activity_log.append(
                    f"  [{row.get('layer')}] {row.get('kind')} "
                    f"{(row.get('content') or '')[:100]}"
                )
        except Exception as e:
            self.activity_log.append(f"[!] search: {e}")
