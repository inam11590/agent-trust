"""Low-cardinality metrics and secret-safe JSON logging."""

from collections import Counter, defaultdict
from contextvars import ContextVar
from datetime import datetime, timezone
import json
import logging
from threading import Lock

request_id_context: ContextVar[str] = ContextVar("request_id", default="-")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        value = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "service": "agenttrust-api",
            "request_id": getattr(record, "request_id", request_id_context.get()),
            "message": record.getMessage(),
        }
        for key in ("route", "method", "status_code", "duration_ms", "event"):
            item = getattr(record, key, None)
            if item is not None: value[key] = item
        if record.exc_info: value["exception"] = record.exc_info[0].__name__
        return json.dumps(value, separators=(",", ":"), ensure_ascii=True)


def configure_logging(level: str) -> None:
    handler = logging.StreamHandler(); handler.setFormatter(JsonFormatter())
    root = logging.getLogger(); root.handlers.clear(); root.addHandler(handler); root.setLevel(level)
    # HTTP client access lines can include webhook URL query parameters.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


class Metrics:
    def __init__(self):
        self._lock = Lock(); self.requests = Counter(); self.duration = defaultdict(float)
        self.authorizations = Counter(); self.events = Counter()
    def http(self, method: str, route: str, status: int, seconds: float) -> None:
        # Route templates and status classes keep labels bounded.
        key = (method, route, f"{status // 100}xx")
        with self._lock: self.requests[key] += 1; self.duration[key] += seconds
    def authorization(self, decision: str) -> None:
        with self._lock: self.authorizations[decision] += 1
    def event(self, name: str) -> None:
        with self._lock: self.events[name] += 1
    def render(self) -> str:
        lines = ["# HELP agenttrust_http_requests_total HTTP requests.", "# TYPE agenttrust_http_requests_total counter"]
        with self._lock:
            for (method, route, status), count in sorted(self.requests.items()):
                labels = f'method="{method}",route="{route}",status_class="{status}"'
                lines.append(f"agenttrust_http_requests_total{{{labels}}} {count}")
                lines.append(f"agenttrust_http_request_duration_seconds_sum{{{labels}}} {self.duration[(method, route, status)]:.6f}")
            lines.extend(["# HELP agenttrust_authorization_decisions_total Authorization decisions.", "# TYPE agenttrust_authorization_decisions_total counter"])
            for decision, count in sorted(self.authorizations.items()): lines.append(f'agenttrust_authorization_decisions_total{{decision="{decision}"}} {count}')
            for name, count in sorted(self.events.items()): lines.append(f'agenttrust_events_total{{event="{name}"}} {count}')
        return "\n".join(lines) + "\n"


metrics = Metrics()


def scrub_error_event(event: dict, hint: dict) -> dict:
    for key in ("request", "user", "extra", "breadcrumbs", "logentry", "message"):
        event.pop(key, None)
    for item in event.get("exception", {}).get("values", []):
        item.pop("value", None)
        for frame in item.get("stacktrace", {}).get("frames", []):
            frame.pop("vars", None)
            frame.pop("context_line", None)
            frame.pop("pre_context", None)
            frame.pop("post_context", None)
    return event
