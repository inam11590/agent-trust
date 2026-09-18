"""Run notification delivery and permission-expiry work outside API requests."""

import argparse
import logging
import signal
from threading import Event

from sqlalchemy.orm import sessionmaker

from app.core.config import Settings
from app.database.session import create_database_engine
from app.services.notification_delivery import process_notification_deliveries, process_permission_expiry_notifications, process_signing_key_expiry_notifications
from app.core.observability import configure_logging, metrics
from app.services.webhooks import process_webhook_deliveries
from app.services.agent_signing import cleanup_expired_nonces

shutdown = Event()


def run_once(settings: Settings) -> tuple[int, int, int]:
    engine = create_database_engine(settings)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    try:
        with factory() as db:
            cleanup_expired_nonces(db)
            expiry = process_permission_expiry_notifications(db, settings)
            expiry += process_signing_key_expiry_notifications(db, settings)
            deliveries = process_notification_deliveries(db, settings)
            webhooks = process_webhook_deliveries(db, settings)
            return expiry, deliveries, webhooks
    finally:
        engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="Process AgentTrust notification jobs")
    parser.add_argument("--once", action="store_true", help="Process one batch and exit")
    args = parser.parse_args()
    settings = Settings()
    configure_logging(settings.log_level)
    signal.signal(signal.SIGTERM, lambda *_: shutdown.set())
    signal.signal(signal.SIGINT, lambda *_: shutdown.set())
    while not shutdown.is_set():
        try:
            expiry, deliveries, webhooks = run_once(settings)
            logging.getLogger("agenttrust.worker").info("worker_batch_complete", extra={"event": "worker_batch"})
        except Exception:
            metrics.event("background_job_failure")
            logging.getLogger("agenttrust.worker").exception("worker_batch_failed", extra={"event": "background_job_failure"})
            if args.once:
                raise SystemExit(1) from None
        if args.once:
            return
        shutdown.wait(settings.notification_worker_poll_seconds)


if __name__ == "__main__":
    main()
