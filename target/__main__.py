"""Run the target: python -m target (host and port come from TARGET_HOST / TARGET_PORT)."""

import os

from .app import create_app

if __name__ == "__main__":
    create_app().run(
        host=os.environ.get("TARGET_HOST", "0.0.0.0"),
        port=int(os.environ.get("TARGET_PORT", "8080")),
    )
