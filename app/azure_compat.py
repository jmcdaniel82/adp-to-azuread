"""Azure Functions compatibility import.

Allows local unit tests/imports without azure-functions installed while keeping
runtime behavior unchanged in Azure.
"""

from __future__ import annotations

try:
    import azure.functions as func  # type: ignore
except ModuleNotFoundError:

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
        FunctionApp = _DummyDecoratorApp
        HttpRequest = object
        HttpResponse = _DummyHttpResponse
        TimerRequest = object

    func = _DummyModule()
