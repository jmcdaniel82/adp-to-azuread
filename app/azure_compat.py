"""Azure Functions compatibility import.

Allows local unit tests/imports without azure-functions installed while keeping
runtime behavior unchanged in Azure.
"""

from __future__ import annotations

from typing import Any

try:
    import azure.functions as _func
except ModuleNotFoundError:

    class _DummyAuthLevel:
        FUNCTION = "function"

    class _DummyDecoratorApp:
        def function_name(self, *args, **kwargs):
            def _decorator(fn):
                return fn

            return _decorator

        def route(self, *args, **kwargs):
            def _decorator(fn):
                return fn

            return _decorator

        def schedule(self, *args, **kwargs):
            def _decorator(fn):
                return fn

            return _decorator

    class _DummyHttpResponse:
        def __init__(self, body=None, status_code=200, mimetype=None):
            self.body = body
            self.status_code = status_code
            self.mimetype = mimetype

    class _DummyModule:
        AuthLevel = _DummyAuthLevel
        FunctionApp = _DummyDecoratorApp
        HttpRequest = object
        HttpResponse = _DummyHttpResponse
        TimerRequest = object

    func: Any = _DummyModule()
else:
    func = _func
