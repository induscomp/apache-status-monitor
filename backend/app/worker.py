import json
import logging
from datetime import timedelta

from apscheduler.schedulers.blocking import BlockingScheduler
from sqlalchemy import delete
from sqlalchemy.dialects.postgresql import insert

from app.analysis import retention as analysis_retention
from app.analysis import run as analyze
from app.backup import scheduled as backup
from app.collection import collect_due, retain_observations
from app.db import session_factory
from app.goaccess import collect_due as collect_goaccess
from app.goaccess import retention as retain_goaccess
from app.models import AuthSession, ComponentHeartbeat, RateBucket, now
from app.mrtg_collection import collect_due as collect_mrtg
from app.mrtg_collection import retention as retain_mrtg
from app.notifications import deliver

logging.basicConfig(level=logging.INFO, format="%(message)s")
logging.getLogger("apscheduler").setLevel(logging.WARNING)
logger = logging.getLogger("smon.worker")


def heartbeat():
    try:
        with session_factory()() as db:
            statement = insert(ComponentHeartbeat).values(name="scheduler", seen_at=now())
            db.execute(
                statement.on_conflict_do_update(
                    index_elements=[ComponentHeartbeat.name],
                    set_={"seen_at": now()},
                )
            )
            db.commit()
    except Exception as exc:
        logger.error(json.dumps({"event": "heartbeat_failed", "type": type(exc).__name__}))


def cleanup_auth():
    with session_factory()() as db:
        db.execute(delete(AuthSession).where(AuthSession.expires_at < now()))
        db.execute(
            delete(RateBucket).where(
                RateBucket.window < int((now() - timedelta(days=1)).timestamp())
            )
        )
        db.commit()


def main():
    scheduler = BlockingScheduler(
        timezone="UTC", job_defaults={"max_instances": 1, "coalesce": True}
    )
    scheduler.add_job(backup, "interval", hours=1, id="backup", next_run_time=now())
    scheduler.add_job(collect_goaccess, "interval", seconds=15, id="goaccess", next_run_time=now())
    scheduler.add_job(
        retain_goaccess, "interval", hours=1, id="goaccess-retention", next_run_time=now()
    )
    scheduler.add_job(analyze, "interval", seconds=15, id="analysis", next_run_time=now())
    scheduler.add_job(deliver, "interval", seconds=30, id="email")
    scheduler.add_job(
        analysis_retention, "interval", hours=1, id="analysis-retention", next_run_time=now()
    )
    scheduler.add_job(heartbeat, "interval", seconds=30, id="heartbeat", next_run_time=now())
    scheduler.add_job(collect_mrtg, "interval", seconds=15, id="mrtg", next_run_time=now())
    scheduler.add_job(retain_mrtg, "interval", hours=1, id="mrtg-retention", next_run_time=now())
    scheduler.add_job(collect_due, "interval", seconds=15, id="apache", next_run_time=now())
    scheduler.add_job(retain_observations, "interval", hours=1, id="retention", next_run_time=now())
    scheduler.add_job(cleanup_auth, "interval", hours=1, id="cleanup_auth")
    logger.info(
        json.dumps({"event": "scheduler_started", "collectors": "apache_status,mrtg,goaccess"})
    )
    try:
        scheduler.start()
    except KeyboardInterrupt, SystemExit:
        pass


if __name__ == "__main__":
    main()
