import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from app.core.config import settings

logger = logging.getLogger("threatlens.database")

# -------------------------------------------------------------------------
# DATABASE ENGINE CONFIGURATION
# -------------------------------------------------------------------------
# pool_size and max_overflow are explicitly tuned to support high-throughput
# ingestion worker spikes alongside active analyst API requests (NFR-03 compliance).
engine = create_engine(
    settings.DATABASE_URL,
    pool_size=20,
    max_overflow=10,
    pool_pre_ping=True,  # Automatically recycles dead connections back-pressured by database restarts
    pool_recycle=1800,  # Prevents connection stale-outs by recycling active connections every 30 minutes
)

# -------------------------------------------------------------------------
# SESSION FACTORY DECLARATION
# -------------------------------------------------------------------------
# autocommit=False and autoflush=False guarantee explicit transaction boundaries,
# preventing dirty/partial writes during multi-feed deduplication sequences.
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# -------------------------------------------------------------------------
# DECLARATIVE BASE
# -------------------------------------------------------------------------
# Inherited by all operational tables in app/models/all_models.py to register metadata structures.
Base = declarative_base()


# -------------------------------------------------------------------------
# DEPENDENCY INJECTION CONTEXT
# -------------------------------------------------------------------------
def get_db():
    """
    Generates a thread-safe transaction session scope per request block.
    Guarantees cleanup and connection closure back into the main pool
    even if underlying application code encounters runtime exceptions.
    """
    db = SessionLocal()
    try:
        yield db
    except Exception as exc:
        logger.error(f"Database session operation crash encountered: {str(exc)}")
        db.rollback()  # Rollback pending states if transaction framework failure hits mid-flight
        raise
    finally:
        db.close()  # Safely returns the connection to the engine pool, preventing leaks
