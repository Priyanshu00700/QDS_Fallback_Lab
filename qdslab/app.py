"""FastAPI server: serves the single-page UI and runs scenarios.

  GET  /              the web interface (static/index.html)
  GET  /api/status    defaults, attack catalogue, which Bell-pair backends are available
  POST /api/run       run one scenario in one mode
  POST /api/compare   run the same scenario in plain, QDS-only and hybrid mode
The server keeps no state: the browser holds the list of users and sends the cast with every request.
"""
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from . import __version__, attacks, backends, engine
from .config import DEFAULTS, MODE_NAMES, MODES, ROLES

INDEX = Path(__file__).resolve().parent.parent / "static" / "index.html"

app = FastAPI(title="QDS + Entanglement Fallback Lab", version=__version__)


class Attacker(BaseModel):
    name: str
    primary: str = "pass"
    backup: str = "pass"
    tap_entanglement: bool = False
    forged_text: str = ""


class Scenario(BaseModel):
    message: str = "Meet at the lab at 5pm"
    mode: str = "hybrid"
    sender: str
    receiver: str
    validator: Optional[str] = None
    attacker: Optional[Attacker] = None
    settings: Dict[str, Any] = {}


def _plain(model: Scenario) -> dict:
    return model.model_dump() if hasattr(model, "model_dump") else model.dict()


@app.get("/", response_class=HTMLResponse)
def index():
    if not INDEX.exists():
        raise HTTPException(500, f"UI file missing: {INDEX}. Re-extract the project folder.")
    return HTMLResponse(INDEX.read_text(encoding="utf-8"))


@app.get("/api/status")
def status():
    return {"version": __version__, "defaults": DEFAULTS, "modes": MODE_NAMES, "roles": list(ROLES),
            "attacks": {"primary": attacks.PRIMARY, "backup": attacks.BACKUP},
            "backends": backends.available_backends()}


@app.post("/api/run")
def run(s: Scenario):
    try:
        return engine.run_scenario(_plain(s))
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.post("/api/compare")
def compare(s: Scenario):
    try:
        return {"results": engine.compare(_plain(s)), "order": list(MODES)}
    except ValueError as exc:
        raise HTTPException(400, str(exc))
