import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    SECRET_KEY: str  # Must be a cryptographically secure random string (e.g., openssl rand -hex 32)
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    PROJECT_NAME: str = "ThreatLens"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = os.getenv(
        "SECRET_KEY", "SUPER_SECRET_SECURITY_TOKEN_CHANGE_IN_PRODUCTION"
    )
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    POSTGRES_SERVER: str = os.getenv("POSTGRES_SERVER", "localhost")
    POSTGRES_USER: str = os.getenv("POSTGRES_USER", "postgres")
    POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD", "postgres")
    POSTGRES_DB: str = os.getenv("POSTGRES_DB", "threatlens")

    @property
    def DATABASE_URL(self) -> str:
        # Explicitly declare the psycopg2 binary driver path for SQLAlchemy 2.x
        return f"postgresql+psycopg2://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_SERVER}/{self.POSTGRES_DB}"

    REDIS_HOST: str = os.getenv("REDIS_HOST", "redis")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", 6379))
    ELASTICSEARCH_HOST: str = os.getenv(
        "ELASTICSEARCH_HOST", "http://elasticsearch:9200"
    )

    class Config:
        env_file = ".env"


settings = Settings()
