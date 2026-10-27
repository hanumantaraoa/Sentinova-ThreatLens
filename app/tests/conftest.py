import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient
from app.core.database import Base, get_db
from app.main import app
from app.models.all_models import (
    User,
    UserRole,
    Indicator,
    IOCType,
    TLPMarking,
    IOCStatus,
)

# Use an isolated, low-overhead PostgreSQL database container block for automated tests
TEST_DATABASE_URL = "postgresql://postgres:postgres@postgres/threatlens_test"


@pytest.fixture(scope="session")
def db_engine():
    # Force system drops to guarantee zero persistent data leaks across execution boundaries
    engine = create_engine(TEST_DATABASE_URL)
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def db_session(db_engine):
    connection = db_engine.connect()
    transaction = connection.begin()
    Session = sessionmaker(bind=connection)
    session = Session()

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture(scope="function")
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture(scope="function")
def mock_soc_analyst(db_session):
    """Generates an operational user profile matching Priya's authorization model."""
    user = User(
        username="priya_analyst",
        hashed_password="$pbkdf2-sha256$272000$g... [Mock Hashed Content]",
        role=UserRole.SOC_ANALYST,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture(scope="function")
def static_threat_dataset(db_session):
    """Seeds predictable data profiles mapping directly to live production telemetry models."""
    ioc_1 = Indicator(
        value="185.220.101.4",
        type=IOCType.IP,
        severity_score=75,
        confidence=80,
        tlp=TLPMarking.AMBER,
        status=IOCStatus.ACTIVE,
    )
    ioc_2 = Indicator(
        value="malicious-phishing-domain.top",
        type=IOCType.DOMAIN,
        severity_score=90,
        confidence=95,
        tlp=TLPMarking.RED,
        status=IOCStatus.ACTIVE,
    )
    db_session.add_all([ioc_1, ioc_2])
    db_session.commit()
    return [ioc_1, ioc_2]
