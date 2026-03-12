from typing import Any

try:
    from inspect_ai.tracing import Trace
except ImportError:
    Trace = Any

try:
    import phoenix as px
except (ImportError, SyntaxError):
    px = None


def launch_phoenix_app():
    if px is not None:
        px.launch_app()


class PhoenixTraceLogger:
    def log(self, trace: Trace):
        if px is None:
            return
        span = px.start_span("re_bench_eval")
        span.log(trace.to_dict())
        span.end()