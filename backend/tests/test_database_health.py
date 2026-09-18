from unittest.mock import Mock

from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from app.core.config import Settings
from app.database.session import get_db
from app.main import create_app


def test_database_health_without_credentials():
    app = create_app()
    app.state.settings = Settings(_env_file=None, postgres_user="", postgres_password="")
    with TestClient(app) as client:
        response = client.get("/health/database")
        assert client.get("/health").status_code == 200
    assert response.status_code == 503
    assert response.json() == {"detail": "Database unavailable"}


def test_database_health_hides_connection_errors():
    app = create_app()
    session = Mock()
    session.execute.side_effect = OperationalError("SELECT 1", {}, Exception("private driver details"))
    app.dependency_overrides[get_db] = lambda: session
    with TestClient(app) as client:
        response = client.get("/health/database")
    assert response.status_code == 503
    assert response.json() == {"detail": "Database unavailable"}
