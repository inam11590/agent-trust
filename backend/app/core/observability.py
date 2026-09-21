"""Low-cardinality metrics and secret-safe JSON logging with automated redaction."""

from collections import Counter, defaultdict
from contextvars import ContextVar
from datetime import datetime, timezone
import json
import logging
import re
from threading import Lock
from typing import Any

request_id_context: ContextVar[str] = ContextVar("request_id", default="-")
trace_id_context: ContextVar[str] = ContextVar("trace_id", default="-")
correlation_id_context: ContextVar[str] = ContextVar("correlation_id", default="-")

# Secret redaction patterns
REDACT_PATTERNS = [
    # Authorization header: Bearer <token>
    (re.compile(r'(?i)(bearer\s+)[A-Za-z0-9_\-\.]{8,}', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(?i)(authorization["\']?\s*:\s*["\']?bearer\s+)[^"\',\s]+', re.IGNORECASE), r'\1[REDACTED]'),
    # Database connection string passwords: e.g. postgresql://user:password@host
    (re.compile(r'(postgresql(?:\+[a-z0-9]+)?://[^:]+:)([^@]+)(@)', re.IGNORECASE), r'\1[REDACTED]\3'),
    # Key-value secret patterns: password=..., secret=..., token=..., api_key=..., bootstrap_token=...
    (re.compile(r'(?i)\b(password|secret|token|api_key|apikey|private_key|bootstrap_token|jwt_secret_key)\s*([:=])\s*([\'"]?)([^\s\'",\)]+)\3', re.IGNORECASE), r'\1\2\3[REDACTED]\3'),
    # Asymmetric private key blocks
    (re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----'), '[REDACTED_PRIVATE_KEY]'),
]


def redact_secrets(text: Any) -> str:
    """Scrub sensitive credentials, tokens, and private keys from log output."""
    if not isinstance(text, str):
        text = str(text)
    for pattern, replacement in REDACT_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        raw_msg = record.getMessage()
        safe_msg = redact_secrets(raw_msg)
        value = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "service": "agenttrust-api",
            "request_id": getattr(record, "request_id", request_id_context.get()),
            "trace_id": getattr(record, "trace_id", trace_id_context.get()),
            "correlation_id": getattr(record, "correlation_id", correlation_id_context.get()),
            "message": safe_msg,
        }
        for key in ("route", "method", "status_code", "duration_ms", "event"):
            item = getattr(record, key, None)
            if item is not None:
                value[key] = redact_secrets(item) if isinstance(item, str) else item
        if record.exc_info:
            value["exception"] = record.exc_info[0].__name__
        return json.dumps(value, separators=(",", ":"), ensure_ascii=True)


def configure_logging(level: str) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    # HTTP client access lines can include webhook URL query parameters.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


class Metrics:
    def __init__(self):
        self._lock = Lock()
        self.requests = Counter()
        self.duration = defaultdict(float)
        self.authorizations = Counter()
        self.events = Counter()
        self.soc_metrics = Counter()
        self.alerts_open_count = 0

    def http(self, method: str, route: str, status: int, seconds: float) -> None:
        key = (method, route, f"{status // 100}xx")
        with self._lock:
            self.requests[key] += 1
            self.duration[key] += seconds

    def authorization(self, decision: str) -> None:
        with self._lock:
            self.authorizations[decision] += 1
            self.soc_metrics["authorization_total"] += 1
            if decision.upper() == "DENIED":
                self.soc_metrics["authorization_denied_total"] += 1

    def event(self, name: str) -> None:
        with self._lock:
            self.events[name] += 1

    def record_soc(self, name: str, count: int = 1) -> None:
        with self._lock:
            self.soc_metrics[name] += count

    def set_alerts_open(self, count: int) -> None:
        with self._lock:
            self.alerts_open_count = count

    def render(self) -> str:
        lines = [
            "# HELP agenttrust_http_requests_total HTTP requests.",
            "# TYPE agenttrust_http_requests_total counter",
        ]
        with self._lock:
            for (method, route, status), count in sorted(self.requests.items()):
                labels = f'method="{method}",route="{route}",status_class="{status}"'
                lines.append(f"agenttrust_http_requests_total{{{labels}}} {count}")
                lines.append(f"agenttrust_http_request_duration_seconds_sum{{{labels}}} {self.duration[(method, route, status)]:.6f}")
            lines.extend([
                "# HELP agenttrust_authorization_decisions_total Authorization decisions.",
                "# TYPE agenttrust_authorization_decisions_total counter",
            ])
            for decision, count in sorted(self.authorizations.items()):
                lines.append(f'agenttrust_authorization_decisions_total{{decision="{decision}"}} {count}')
            for name, count in sorted(self.events.items()):
                lines.append(f'agenttrust_events_total{{event="{name}"}} {count}')

            # SOC metrics
            lines.append("# HELP agenttrust_authorization_total Total authorizations assessed.")
            lines.append("# TYPE agenttrust_authorization_total counter")
            lines.append(f"agenttrust_authorization_total {self.soc_metrics.get('authorization_total', 0)}")

            lines.append("# HELP agenttrust_authorization_denied_total Total denied authorizations.")
            lines.append("# TYPE agenttrust_authorization_denied_total counter")
            lines.append(f"agenttrust_authorization_denied_total {self.soc_metrics.get('authorization_denied_total', 0)}")

            lines.append("# HELP agenttrust_invalid_signature_total Cryptographic signature failures.")
            lines.append("# TYPE agenttrust_invalid_signature_total counter")
            lines.append(f"agenttrust_invalid_signature_total {self.soc_metrics.get('invalid_signature_total', 0)}")

            lines.append("# HELP agenttrust_replay_detected_total Replay attacks detected.")
            lines.append("# TYPE agenttrust_replay_detected_total counter")
            lines.append(f"agenttrust_replay_detected_total {self.soc_metrics.get('replay_detected_total', 0)}")

            lines.append("# HELP agenttrust_credential_failure_total Credential validation failures.")
            lines.append("# TYPE agenttrust_credential_failure_total counter")
            lines.append(f"agenttrust_credential_failure_total {self.soc_metrics.get('credential_failure_total', 0)}")

            lines.append("# HELP agenttrust_trust_violation_total Cross-org trust violations.")
            lines.append("# TYPE agenttrust_trust_violation_total counter")
            lines.append(f"agenttrust_trust_violation_total {self.soc_metrics.get('trust_violation_total', 0)}")

            lines.append("# HELP agenttrust_gateway_auth_failure_total Gateway authentication failures.")
            lines.append("# TYPE agenttrust_gateway_auth_failure_total counter")
            lines.append(f"agenttrust_gateway_auth_failure_total {self.soc_metrics.get('gateway_auth_failure_total', 0)}")

            lines.append("# HELP agenttrust_alerts_open Open security alerts count.")
            lines.append("# TYPE agenttrust_alerts_open gauge")
            lines.append(f"agenttrust_alerts_open {self.alerts_open_count}")

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
