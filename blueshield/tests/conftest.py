import pytest
from fastapi.testclient import TestClient

from app import config
from app.services import settings_store


@pytest.fixture
def client(tmp_path, monkeypatch):
    """A TestClient wired to a throwaway SQLite DB and settings file per
    test, so API tests never touch the real data/blueshield.db.
    """
    monkeypatch.setattr(config, "DATABASE_PATH", tmp_path / "test_blueshield.db")
    monkeypatch.setattr(settings_store, "SETTINGS_PATH", tmp_path / "settings.json")

    from app.main import app

    with TestClient(app) as test_client:
        yield test_client
