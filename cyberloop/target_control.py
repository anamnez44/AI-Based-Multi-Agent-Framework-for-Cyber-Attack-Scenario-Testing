"""Control plane of the target: enable or disable defenses at runtime.

This is lab tooling, not part of the attack surface. The Defender uses it to deploy defenses
and the orchestrator uses it to reset the target before each run.
"""

from collections.abc import Iterable

import httpx


class TargetControl:
    def __init__(self, client: httpx.Client):
        self.client = client

    def reset(self) -> None:
        self.client.post("/admin/reset").raise_for_status()

    def active(self) -> list[str]:
        response = self.client.get("/admin/defenses")
        response.raise_for_status()
        return response.json()["active"]

    def set_active(self, defenses: Iterable[str]) -> list[str]:
        response = self.client.post("/admin/defenses", json={"active": sorted(set(defenses))})
        response.raise_for_status()
        return response.json()["active"]
