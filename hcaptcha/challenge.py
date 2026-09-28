"""
Visual challenge solver — probes multiple hcaptcha-challenger API versions.

Current APIs seen in the wild:
  v0.13+   : AgentV(page, AgentConfig) / AgentT / Malenia  (Playwright-driven)
  legacy   : BinaryClassifier / SpatialPointClassifier      (functional, image-only)

For request-based solving we prefer the functional classifiers since we
already have the image bytes — no Playwright page required.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from loguru import logger

from hcaptcha.errors import ChallengeSolveError


class ChallengeSolver:
    def __init__(self, tmp_dir: Path = Path("./tmp_challenges")):
        self.tmp_dir = tmp_dir
        self.tmp_dir.mkdir(exist_ok=True)
        self._hc = None
        self._install()

    def _install(self) -> None:
        try:
            import hcaptcha_challenger as hc
            self._hc = hc
            # current API: install(upgrade=False, clip=True)
            # legacy API: install()
            try:
                hc.install(upgrade=False, clip=True)
            except TypeError:
                hc.install()
            logger.info("hcaptcha-challenger models ready")
        except Exception as exc:
            logger.warning(f"model install skipped: {exc}")
            self._hc = None

    # ── public ────────────────────────────────────────────────
    def solve_binary(self, paths: List[Path], prompt: str) -> List[int]:
        """Return 0-based indices of images matching `prompt`."""
        solver = self._classifier("BinaryClassifier")
        try:
            result = solver.solve(prompt, [str(p) for p in paths])
        except TypeError:
            result = solver.solve(prompt=prompt, images=[str(p) for p in paths])
        # normalise to list of ints
        if isinstance(result, list):
            return [i for i, v in enumerate(result) if v] \
                   if all(isinstance(v, bool) for v in result) else result
        return []

    def solve_area_select(self, path: Path, prompt: str) -> List[Dict[str, Any]]:
        solver = self._classifier("SpatialPointClassifier")
        try:
            result = solver.solve(prompt, str(path))
        except TypeError:
            result = solver.solve(prompt=prompt, image=str(path))
        return self._normalise_coords(result)

    def solve_drag_drop(self, path: Path, prompt: str) -> List[Dict[str, Any]]:
        # hcaptcha-challenger handles this via the multimodal agent; fall back
        # to the area-select classifier for point-style drops.
        return self.solve_area_select(path, prompt)

    # ── internals ─────────────────────────────────────────────
    def _classifier(self, name: str):
        if self._hc is None:
            raise ChallengeSolveError("hcaptcha-challenger not installed")
        cls = getattr(self._hc, name, None)
        if cls is None:
            raise ChallengeSolveError(f"classifier {name} not available")
        return cls()

    @staticmethod
    def _normalise_coords(result) -> List[Dict[str, Any]]:
        if not result:
            return []
        if isinstance(result, list) and result and isinstance(result[0], dict):
            return result
        # list of (x, y) tuples
        return [
            {"entity_name": f"e{i}", "entity_type": "default",
             "entity_coords": [int(pt[0]), int(pt[1])]}
            for i, pt in enumerate(result)
        ]