"""Version info, update check against GitHub and self-update requests.

The running image knows which git tree of the project folder it was built from
(APP_TREE, set by update.sh). GitHub exposes the tree SHA of that folder on the
branch, so "update available" is an exact comparison, unaffected by commits to
other folders of the repository.

The container cannot rebuild itself. It drops a request file into the data
volume; a systemd path unit on the host (installed by install.sh) notices it
and runs update.sh, which writes its progress back into the same volume.
"""

import json
import os
import time
from pathlib import Path
from typing import Any

import httpx

from .config import settings

VERSION_FILE = Path(__file__).resolve().parent.parent / "VERSION"
REQUEST_FILE = settings.data_dir / "update.request"
STATUS_FILE = settings.data_dir / "update.status"
LOG_FILE = settings.data_dir / "update.log"
UPDATER_MARKER = settings.data_dir / "updater.enabled"

CHECK_TTL = 1800  # GitHub allows 60 unauthenticated requests per hour per IP
STALE_AFTER = 1800  # an update that has not finished in 30 minutes is considered dead


class UpdateError(Exception):
    pass


def current_version() -> dict[str, Any]:
    version = VERSION_FILE.read_text().strip() if VERSION_FILE.exists() else "dev"
    return {
        "version": version,
        "tree": os.getenv("APP_TREE", ""),
        "commit": os.getenv("APP_COMMIT", ""),
        "commit_date": os.getenv("APP_COMMIT_DATE", ""),
        "built_at": os.getenv("APP_BUILT_AT", ""),
        "repo": settings.update_repo,
        "branch": settings.update_branch,
        "path": settings.update_path,
        "updater": UPDATER_MARKER.exists(),
    }


class UpdateChecker:
    def __init__(self):
        self._cache: dict[str, Any] | None = None
        self._at = 0.0

    async def check(self, force: bool = False) -> dict[str, Any]:
        if not force and self._cache and time.time() - self._at < CHECK_TTL:
            return self._cache
        current = current_version()
        result: dict[str, Any] = {"checked_at": int(time.time()), "current": current, "error": None,
                                  "latest_version": None, "latest_tree": None, "commits": [],
                                  "update_available": False}
        try:
            result.update(await self._fetch_latest(current))
        except (httpx.HTTPError, UpdateError, ValueError, KeyError) as exc:
            result["error"] = f"Не удалось проверить обновления: {exc}"
        self._cache, self._at = result, time.time()
        return result

    @staticmethod
    async def _fetch_latest(current: dict[str, Any]) -> dict[str, Any]:
        repo, branch, path = settings.update_repo, settings.update_branch, settings.update_path.strip("/")
        parent, _, name = path.rpartition("/")
        async with httpx.AsyncClient(timeout=15, headers={"User-Agent": "vpn-admin-updater",
                                                          "Accept": "application/vnd.github+json"}) as http:
            listing = await http.get(f"https://api.github.com/repos/{repo}/contents/{parent}", params={"ref": branch})
            if listing.status_code != 200:
                raise UpdateError(f"GitHub ответил {listing.status_code}")
            entry = next((e for e in listing.json() if e.get("name") == name and e.get("type") == "dir"), None)
            if not entry:
                raise UpdateError(f"в {repo}@{branch} нет папки {path}")
            latest_tree = entry["sha"]

            version_resp = await http.get(f"https://raw.githubusercontent.com/{repo}/{branch}/{path}/VERSION")
            latest_version = version_resp.text.strip() if version_resp.status_code == 200 else None

            commits_resp = await http.get(f"https://api.github.com/repos/{repo}/commits",
                                          params={"sha": branch, "path": path, "per_page": 20})
            commits = []
            if commits_resp.status_code == 200:
                for c in commits_resp.json():
                    date = c["commit"]["committer"]["date"]
                    if current["commit_date"] and date <= current["commit_date"]:
                        break  # ISO-8601 UTC strings compare chronologically
                    commits.append({"sha": c["sha"][:7], "date": date, "url": c.get("html_url"),
                                    "message": c["commit"]["message"].splitlines()[0]})

        if current["tree"]:
            available = latest_tree != current["tree"]
        else:  # built outside git: fall back to the version string
            available = bool(latest_version) and latest_version != current["version"]
        return {"latest_version": latest_version, "latest_tree": latest_tree,
                "commits": commits if available else [], "update_available": available}


checker = UpdateChecker()


def _write_json(path: Path, data: dict) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False))
    tmp.replace(path)


def read_status() -> dict[str, Any]:
    status: dict[str, Any] = {"state": "idle"}
    if STATUS_FILE.exists():
        try:
            status = json.loads(STATUS_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            status = {"state": "unknown"}
    if REQUEST_FILE.exists() and status.get("state") != "running":
        status["state"] = "queued"
    since = status.get("started_at") or status.get("requested_at") or 0
    if status.get("state") in ("queued", "running") and time.time() - since > STALE_AFTER:
        status["state"] = "stale"
    log_tail = ""
    if LOG_FILE.exists():
        log_tail = "\n".join(LOG_FILE.read_text(errors="replace").splitlines()[-80:])
    return {**status, "log": log_tail}


def request_update(username: str) -> dict[str, Any]:
    if not UPDATER_MARKER.exists():
        raise UpdateError("Автообновление не настроено на сервере: запустите install.sh из новой версии "
                          "или обновите вручную командой update.sh")
    if read_status().get("state") in ("queued", "running"):
        raise UpdateError("Обновление уже выполняется")
    _write_json(REQUEST_FILE, {"requested_at": int(time.time()), "by": username})
    _write_json(STATUS_FILE, {"state": "queued", "requested_at": int(time.time())})
    return read_status()
