"""Azure Functions Python v2 root discovery shim.

Azure Functions discovers a root-level ``FunctionApp`` instance from
``function_app.py``. The implementation lives in ``app.function_app`` and is
re-exported here for runtime discovery.
"""

from app.function_app import app

__all__ = ["app"]
