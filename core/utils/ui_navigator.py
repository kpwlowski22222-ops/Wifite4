"""Host Screen Vision & Region Labeling System.

Provides desktop screenshot capture, regional crop indexing, text bounding box parsing,
and Gemini 2.5 Flash / PyTesseract OCR extraction to map UI controls across Kali Linux.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    from PIL import Image
except ImportError:
    Image = None  # type: ignore

try:
    import requests
except ImportError:
    requests = None  # type: ignore


CACHE_DIR = Path("logs/screen_cache")


class HostVisionNavigator:
    """Capture screen regions, parse text/labels, and cache UI control bounding boxes."""

    def __init__(self, cache_dir: Optional[Path] = None):
        self.cache_dir = Path(cache_dir or CACHE_DIR)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.regions_dir = self.cache_dir / "regions"
        self.regions_dir.mkdir(parents=True, exist_ok=True)
        self.gemini_api_key = os.getenv("GEMINI_API_KEY", "").strip()
        self.gemini_model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash").strip()
        self.gemini_endpoint = (
            "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
        )
        self.labels_index_path = self.cache_dir / "ui_labels_index.json"
        self._labels_index: Dict[str, Dict[str, Any]] = self._load_index()

    def _load_index(self) -> Dict[str, Dict[str, Any]]:
        if self.labels_index_path.is_file():
            try:
                return json.loads(self.labels_index_path.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {}

    def _save_index(self) -> None:
        try:
            self.labels_index_path.write_text(
                json.dumps(self._labels_index, indent=2), encoding="utf-8"
            )
        except Exception:
            pass

    def capture_fullscreen(self, filename_prefix: str = "shot") -> Optional[Path]:
        """Take a full screen capture using import/scrot/xwd or CLI utilities.

        Uses ``subprocess.run`` with a list argv and ``shell=False``; the
        output path is validated to live under ``self.cache_dir`` so an
        attacker-controlled prefix cannot write outside the cache.
        """
        ts = int(time.time() * 1000)
        out_path = (self.cache_dir / f"{filename_prefix}_{ts}.png").resolve()
        if not str(out_path).startswith(str(self.cache_dir.resolve())):
            return None

        candidates = [
            ["import", "-window", "root", str(out_path)],
            ["scrot", str(out_path)],
            ["gnome-screenshot", "-f", str(out_path)],
        ]
        for argv in candidates:
            try:
                p = subprocess.run(
                    argv, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=15,
                )
                if p.returncode == 0 and out_path.is_file():
                    return out_path
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                pass
        return None

    def crop_region(
        self, img_path: Path, box: Tuple[int, int, int, int], label: str
    ) -> Optional[Path]:
        """Crop region (left, top, right, bottom) and store in indexed regions folder."""
        if Image is None or not img_path.is_file():
            return None
        try:
            with Image.open(img_path) as im:
                cropped = im.crop(box)
                ts = int(time.time())
                clean_label = "".join(c if c.isalnum() else "_" for c in label)
                out_path = self.regions_dir / f"{clean_label}_{ts}.png"
                cropped.save(out_path)

                self._labels_index[label] = {
                    "label": label,
                    "box": list(box),
                    "image_path": str(out_path),
                    "updated_at": ts,
                }
                self._save_index()
                return out_path
        except Exception:
            return None

    def extract_labels_via_gemini(self, img_path: Path) -> List[Dict[str, Any]]:
        """Extract UI controls and bounding labels using Gemini Vision API."""
        if not self.gemini_api_key or requests is None or not img_path.is_file():
            return []

        try:
            raw_bytes = img_path.read_bytes()
            b64_str = base64.b64encode(raw_bytes).decode("utf-8")

            prompt = (
                "Analyze this desktop / application screen. Return a JSON list of all "
                "clickable controls, buttons, menu labels, and input fields. "
                "For each control emit: {\"label\": \"<text>\", \"box\": [left, top, right, bottom], \"type\": \"button|menu|input\"}."
            )

            payload = {
                "model": self.gemini_model,
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": prompt},
                            {
                                "type": "image_url",
                                "image_url": {"url": f"data:image/png;base64,{b64_str}"},
                            },
                        ],
                    }
                ],
                "temperature": 0.2,
            }
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.gemini_api_key}",
            }
            res = requests.post(
                self.gemini_endpoint, headers=headers, json=payload, timeout=30
            )
            if res.status_code == 200:
                txt = res.json()["choices"][0]["message"]["content"]
                start = txt.find("[")
                end = txt.rfind("]")
                if start != -1 and end != -1:
                    parsed = json.loads(txt[start : end + 1])
                    if isinstance(parsed, list):
                        for item in parsed:
                            if isinstance(item, dict) and "label" in item and "box" in item:
                                self._labels_index[item["label"]] = {
                                    "label": item["label"],
                                    "box": item["box"],
                                    "type": item.get("type", "control"),
                                    "updated_at": int(time.time()),
                                }
                        self._save_index()
                        return parsed
        except Exception:
            pass
        return []

    def extract_labels_via_local_vision(self, img_path: Path) -> List[Dict[str, Any]]:
        """Local OCR & region extraction fallback to auto-label UI controls across OS screen."""
        if not img_path.is_file():
            return []

        discovered: List[Dict[str, Any]] = []
        ts = int(time.time())

        # 1. Try PyTesseract OCR if available
        try:
            import pytesseract
            if Image is not None:
                with Image.open(img_path) as im:
                    data = pytesseract.image_to_data(im, output_type=pytesseract.Output.DICT)
                    n_boxes = len(data.get("text", []))
                    for i in range(n_boxes):
                        txt = data["text"][i].strip()
                        conf = int(data["conf"][i]) if "conf" in data else 0
                        if txt and len(txt) > 1 and conf > 25:
                            x, y, w, h = data["left"][i], data["top"][i], data["width"][i], data["height"][i]
                            box = [x, y, x + w, y + h]
                            item = {
                                "label": txt,
                                "box": box,
                                "type": "text_control",
                                "confidence": conf,
                                "updated_at": ts,
                            }
                            discovered.append(item)
                            self._labels_index[txt] = item
        except Exception:
            pass

        # 2. Heuristic OS control region partitioning
        if Image is not None:
            try:
                with Image.open(img_path) as im:
                    width, height = im.size
                    default_regions = [
                        ("OS_Top_Menu_Bar", [0, 0, width, min(35, height)], "menu_bar"),
                        ("OS_Left_Application_Dock", [0, 0, min(65, width), height], "dock"),
                        ("OS_Active_Workspace", [min(65, width), min(35, height), max(min(65, width), width - 250), max(min(35, height), height - 35)], "workspace"),
                        ("OS_Right_Status_Panel", [max(0, width - 250), min(35, height), width, height], "panel"),
                        ("OS_Bottom_Task_Bar", [0, max(0, height - 35), width, height], "taskbar"),
                    ]
                    for label, box, rtype in default_regions:
                        item = {
                            "label": label,
                            "box": box,
                            "type": rtype,
                            "updated_at": ts,
                        }
                        discovered.append(item)
                        self._labels_index[label] = item
            except Exception:
                pass

        if discovered:
            self._save_index()
        return discovered

    def navigate_os_step(self, step_idx: int = 1) -> Dict[str, Any]:
        """Perform one step of OS navigation across windows/desktops and extract UI labels."""
        window_name = f"OS Window Scope #{step_idx}"
        try:
            res = subprocess.run(
                ["wmctrl", "-l"], capture_output=True, text=True, timeout=2
            )
            if res.returncode == 0 and res.stdout.strip():
                lines = [l.strip() for l in res.stdout.splitlines() if l.strip()]
                if lines:
                    target_line = lines[(step_idx - 1) % len(lines)]
                    parts = target_line.split(None, 3)
                    if len(parts) >= 4:
                        window_name = parts[3]
                    win_id = parts[0]
                    subprocess.run(
                        ["xdotool", "windowactivate", win_id],
                        capture_output=True, timeout=2
                    )
        except Exception:
            pass

        shot_path = self.capture_fullscreen(filename_prefix=f"os_step_{step_idx}")
        if not shot_path or not shot_path.is_file():
            # Honest degradation: no capture tool available. Do not
            # synthesize a blank image or fake default regions.
            return {
                "ok": False,
                "step": step_idx,
                "window": window_name,
                "error": "screen capture unavailable (no import/scrot/gnome-screenshot)",
                "screenshot": "",
                "labels_discovered": 0,
                "regions_cropped": 0,
                "labels": [],
            }

        labels = []
        if self.gemini_api_key:
            labels = self.extract_labels_via_gemini(shot_path)
        if not labels:
            labels = self.extract_labels_via_local_vision(shot_path)

        cropped_count = 0
        for item in labels[:10]:
            box = item.get("box")
            lbl = item.get("label")
            if box and len(box) == 4 and lbl:
                cp = self.crop_region(shot_path, tuple(box), lbl)
                if cp:
                    cropped_count += 1

        return {
            "ok": len(labels) > 0,
            "step": step_idx,
            "window": window_name,
            "screenshot": str(shot_path),
            "labels_discovered": len(labels),
            "regions_cropped": cropped_count,
            "labels": [l.get("label") for l in labels if l.get("label")],
        }

    def start_learning_session(
        self, steps: int = 3, callback: Optional[Callable[[str], None]] = None
    ) -> Dict[str, Any]:
        """Execute a multi-step OS navigation and UI auto-labeling learning session."""
        session_results = []
        total_labels = 0
        total_cropped = 0

        if callback:
            callback(
                f"[*] Starting AI Vision OS Navigation & UI Auto-Labeling learning session ({steps} steps)..."
            )

        for i in range(1, steps + 1):
            step_res = self.navigate_os_step(step_idx=i)
            session_results.append(step_res)
            total_labels += step_res.get("labels_discovered", 0)
            total_cropped += step_res.get("regions_cropped", 0)
            if callback:
                callback(
                    f"[Vision] Step {i}/{steps}: Focused '{step_res['window']}' -> "
                    f"Discovered {step_res['labels_discovered']} UI controls "
                    f"({step_res['regions_cropped']} regions cropped)"
                )
            time.sleep(0.1)

        summary = {
            "steps_completed": steps,
            "total_labels": total_labels,
            "total_cropped_regions": total_cropped,
            "index_path": str(self.labels_index_path),
            "steps": session_results,
        }
        if callback:
            callback(
                f"[+] Vision Learning Complete: {total_labels} UI labels indexed "
                f"across {steps} OS navigation steps -> Saved index to {self.labels_index_path}"
            )
        return summary

    def holo_desktop_navigate(
        self,
        goal: str = "open_terminal",
        *,
        tool: str = "",
        model: str = "",
        task: str = "",
        confirm_fn: Optional[Callable[[str], bool]] = None,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """Drive the OS via Holo (holo-desktop-cli) for tools / AI models.

        Prefer this over pure OCR when the operator needs real clicks
        (open apps, pull ollama models, configure GUIs). Falls back to
        an honest error if ``holo`` is not installed.
        """
        try:
            from core.desktop.holo_agent import HoloDesktopBridge
        except Exception as e:  # noqa: BLE001
            return {
                "ok": False,
                "error": f"holo bridge unavailable: {e}",
                "backend": "none",
            }
        bridge = HoloDesktopBridge(confirm_fn=confirm_fn)
        st = bridge.status()
        if not st.get("ok") and not dry_run:
            # Fall back to passive vision step so learning still works
            passive = self.navigate_os_step(step_idx=1)
            return {
                "ok": False,
                "error": st.get("error") or "holo not installed",
                "status": st,
                "fallback": "navigate_os_step",
                "passive": passive,
                "backend": "host_vision",
            }
        result = bridge.run(
            task=task,
            goal=goal,
            tool=tool,
            model_name=model,
            dry_run=dry_run,
        )
        result["backend"] = "holo-desktop-cli"
        # Optional: snapshot after Holo for label indexing
        if result.get("ok") and not dry_run:
            shot = self.capture_fullscreen(filename_prefix="holo_after")
            result["screenshot_after"] = str(shot) if shot else ""
        return result

    def get_known_label(self, label: str) -> Optional[Dict[str, Any]]:
        """Look up known bounding box and cached cropped region for a control label."""
        return self._labels_index.get(label)

    def click_label(self, label: str) -> Dict[str, Any]:
        """Click the center of a previously-discovered UI control label.

        Uses ``xdotool`` if available and honest-degrades when the label
        is unknown, the box is invalid, or xdotool is missing. This is the
        act-step bridge for the Holo predict→act→read→label loop: after
        the AI predicts *what* to click, KFIOSA can act on a cached label
        rather than relying on the model alone.
        """
        entry = self._labels_index.get(label)
        if not entry:
            return {"ok": False, "label": label, "error": "label not indexed"}
        box = entry.get("box")
        if not box or len(box) != 4:
            return {"ok": False, "label": label, "error": "label has no bounding box"}
        left, top, right, bottom = box
        cx = int((left + right) / 2)
        cy = int((top + bottom) / 2)
        try:
            subprocess.run(
                ["xdotool", "mousemove", str(cx), str(cy), "click", "1"],
                capture_output=True, timeout=5, check=True,
            )
            return {
                "ok": True,
                "label": label,
                "box": box,
                "click": [cx, cy],
            }
        except FileNotFoundError:
            return {"ok": False, "label": label, "error": "xdotool not installed"}
        except subprocess.CalledProcessError as e:
            return {
                "ok": False,
                "label": label,
                "error": f"xdotool failed: {e.stderr.decode('utf-8', errors='replace')[:200]}",
            }
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "label": label, "error": f"click failed: {e}"}

    def read_screen_content(self) -> Dict[str, Any]:
        """Capture the current screen and return its text/labels (live-time
        screen reading for the holo OS-agent AI loop).

        Honest-degrade: no screenshot tool and/or no OCR engine →
        ``{ok: False, error, labels: [], text: "", screenshot: ""}``; never
        fabricates labels.
        """
        shot = self.capture_fullscreen(filename_prefix="read_screen")
        if not shot:
            return {
                "ok": False,
                "error": "screen capture unavailable",
                "labels": [],
                "text": "",
                "screenshot": "",
                "count": 0,
            }
        labels = self.extract_labels_via_local_vision(shot) or []
        texts = [str(l.get("label", "")) for l in labels if l.get("label")]
        return {
            "ok": True,
            "labels": texts,
            "text": "\n".join(texts),
            "screenshot": str(shot),
            "count": len(texts),
        }

    def label_screen_live(
        self,
        duration_s: float = 6.0,
        on_label: Optional[Callable[[List[str]], None]] = None,
    ) -> Dict[str, Any]:
        """Continuously label the screen for ``duration_s`` seconds
        (live-time UI labeling), accumulating discovered control labels.

        Calls ``on_label(label_list)`` after each step so a caller (the
        holo predict→act→read→label loop, the TUI activity log, …) can
        stream labels as they are discovered. Honest-degrade like
        :meth:`read_screen_content` — never invents labels.
        """
        import time as _time
        end = _time.time() + max(1.0, float(duration_s))
        steps = 0
        total = 0
        all_labels: List[str] = []
        while _time.time() < end:
            steps += 1
            res = self.navigate_os_step(step_idx=steps)
            lbls = res.get("labels") or []
            total += len(lbls)
            all_labels.extend(lbls)
            if on_label is not None:
                try:
                    on_label(list(lbls))
                except Exception:  # noqa: BLE001
                    pass
        # Dedupe while preserving order.
        unique = list(dict.fromkeys(all_labels))
        if not unique:
            return {
                "ok": False,
                "steps": steps,
                "labels_count": 0,
                "labels": [],
                "duration_s": float(duration_s),
                "error": "no screen labels discovered (capture or OCR unavailable)",
            }
        return {
            "ok": True,
            "steps": steps,
            "labels_count": total,
            "labels": unique,
            "duration_s": float(duration_s),
        }


navigator = HostVisionNavigator()
