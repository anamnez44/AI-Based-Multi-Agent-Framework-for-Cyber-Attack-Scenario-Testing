"""Deliberately vulnerable web application: the system under test for the closed loop.

Runs in its own container and never imports the framework. Defenses are toggled at runtime
through the /admin control plane, which is a lab harness and not part of the attack surface.
"""

from .app import create_app
from .defenses import ALL_DEFENSES

__all__ = ["create_app", "ALL_DEFENSES"]
