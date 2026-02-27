import phoenix as px
from inspect_ai.tracing import Trace

px.launch_app()

class PhoenixTraceLogger:
    def log(self, trace: Trace):
        span = px.start_span("re_bench_eval")
        span.log(trace.to_dict())
        span.end()