import json
from datetime import timedelta

import pytest
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import func, select

from app.backup import clean_row, create_daily, prune, records, restore, write_archive
from app.config import get_settings
from app.db import session_factory
from app.models import (
    ApacheObservation,
    Base,
    ComponentHeartbeat,
    NotificationConfig,
    Server,
    Service,
    now,
)


def empty(db):
    for table in reversed(Base.metadata.sorted_tables):
        db.execute(table.delete())


def populate(db):
    server = Server(name="Synthetic server")
    db.add(server)
    db.flush()
    service = Service(
        server_id=server.id,
        name="Apache",
        kind="apache_status",
        url="https://web.example.test/server-status",
    )
    db.add(service)
    db.flush()
    db.add(
        ApacheObservation(
            service_id=service.id,
            revision=1,
            status="ok",
            observed_at=now() - timedelta(days=31),
            workers=[{"client": "192.0.2.1"}],
            raw_encrypted="debug-should-never-be-in-backup",
        )
    )
    db.add(
        NotificationConfig(
            id=1,
            encrypted=get_settings()
            .cipher()
            .encrypt(json.dumps({"enabled": True}).encode())
            .decode(),
        )
    )
    db.commit()


def test_round_trip_excludes_debug_and_expired_details_disables_email(tmp_path):
    cipher = Fernet(Fernet.generate_key())
    path = tmp_path / "copy.smon"
    with session_factory()() as db:
        populate(db)
        write_archive(db, path, cipher)
        with path.open("rb") as stream:
            rows = list(records(stream, cipher))
        assert "debug-should-never" not in json.dumps([r for _, r in rows])
        assert "192.0.2.1" not in json.dumps([r for _, r in rows])
        assert b"Synthetic server" not in path.read_bytes()
        empty(db)
        db.commit()
        restore(db, path, cipher)
        db.commit()
        assert db.scalar(select(func.count()).select_from(Server)) == 1
        sample = db.scalar(select(ApacheObservation))
        assert sample.workers is None and sample.raw_encrypted is None
        config = db.get(NotificationConfig, 1)
        assert (
            json.loads(get_settings().cipher().decrypt(config.encrypted.encode()))["enabled"]
            is False
        )


def test_restore_refuses_nonempty_database(tmp_path):
    cipher = Fernet(Fernet.generate_key())
    path = tmp_path / "copy.smon"
    with session_factory()() as db:
        populate(db)
        write_archive(db, path, cipher)
        with pytest.raises(ValueError, match="empty"):
            restore(db, path, cipher)
        assert db.scalar(select(func.count()).select_from(Server)) == 1


@pytest.mark.parametrize("damage", ["truncate", "reorder", "duplicate", "wrong-key", "tamper"])
def test_damaged_archive_never_partially_restores(tmp_path, damage):
    cipher = Fernet(Fernet.generate_key())
    path = tmp_path / "copy.smon"
    with session_factory()() as db:
        populate(db)
        write_archive(db, path, cipher)
        empty(db)
        db.commit()
        lines = path.read_bytes().splitlines(keepends=True)
        if damage == "truncate":
            lines = lines[:-1]
        elif damage == "reorder":
            lines[1], lines[2] = lines[2], lines[1]
        elif damage == "duplicate":
            lines.insert(2, lines[1])
        elif damage == "wrong-key":
            cipher = Fernet(Fernet.generate_key())
        else:
            lines[1] = lines[1][:20] + b"!" + lines[1][21:]
        path.write_bytes(b"".join(lines))
        with pytest.raises((ValueError, InvalidToken)):
            restore(db, path, cipher)
        assert db.scalar(select(func.count()).select_from(Server)) == 0


def test_retention_uses_restore_time_and_strips_incident_ips():
    assert (
        clean_row("server_frames", {"observed_at": (now() - timedelta(days=91)).isoformat()}, now())
        is None
    )
    row = clean_row(
        "incidents",
        {
            "updated_at": (now() - timedelta(days=31)).isoformat(),
            "evidence": {"coincidences": {"ips": ["192.0.2.1"]}, "reference": 10},
        },
        now(),
    )
    assert row["evidence"] == {"reference": 10}


def test_rotation_and_daily_idempotence(tmp_path, monkeypatch):
    settings = get_settings()
    key = tmp_path / "key"
    key.write_bytes(Fernet.generate_key())
    directory = tmp_path / "backups"
    monkeypatch.setattr(settings, "backup_key_file", key)
    monkeypatch.setattr(settings, "backup_directory", directory)
    create_daily()
    daily = next(directory.glob("backup-daily-*.smon"))
    original = daily.read_bytes()
    create_daily()
    assert daily.read_bytes() == original
    assert len(list(directory.glob("backup-weekly-*.smon"))) == 1
    with session_factory()() as db:
        assert db.get(ComponentHeartbeat, "backup") is not None
    for day in range(1, 15):
        (directory / f"backup-daily-2020-01-{day:02d}.smon").write_bytes(b"synthetic")
    for week in range(1, 10):
        (directory / f"backup-weekly-2020-W{week:02d}.smon").write_bytes(b"synthetic")
    unrelated = directory / "operator-file.txt"
    unrelated.write_text("preserve")
    prune(directory)
    assert len(list(directory.glob("backup-daily-*.smon"))) == 7
    assert len(list(directory.glob("backup-weekly-*.smon"))) == 4
    assert unrelated.exists()


def test_wrong_application_key_refuses_restore(tmp_path, monkeypatch):
    cipher = Fernet(Fernet.generate_key())
    path = tmp_path / "copy.smon"
    with session_factory()() as db:
        populate(db)
        write_archive(db, path, cipher)
        empty(db)
        db.commit()
        key = tmp_path / "different-app-key"
        key.write_bytes(Fernet.generate_key())
        monkeypatch.setattr(get_settings(), "encryption_key_file", key)
        with pytest.raises(ValueError, match="encryption key"):
            restore(db, path, cipher)
        assert db.scalar(select(func.count()).select_from(Server)) == 0


def test_failed_verification_invalidates_availability(monkeypatch):
    from app import backup

    with session_factory()() as db:
        db.add(ComponentHeartbeat(name="backup", seen_at=now()))
        db.add(ComponentHeartbeat(name="scheduler", seen_at=now()))
        db.commit()

    def damaged():
        raise InvalidToken()

    monkeypatch.setattr(backup, "create_daily", damaged)
    backup.scheduled()
    with session_factory()() as db:
        assert db.get(ComponentHeartbeat, "backup") is None
        assert db.get(ComponentHeartbeat, "scheduler") is not None
