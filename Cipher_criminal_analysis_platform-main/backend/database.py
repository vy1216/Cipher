import os
import logging
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

logger = logging.getLogger("cipher.database")
logging.basicConfig(level=logging.INFO)

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()

# Default to SQLite if DATABASE_URL is not provided or set to sqlite
if not DATABASE_URL:
    db_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "cipher.db"))
    DATABASE_URL = f"sqlite:///{db_file}"
    logger.info(f"No DATABASE_URL provided. Using SQLite at {DATABASE_URL}")
elif DATABASE_URL.startswith("postgres://"):
    # SQLAlchemy requires postgresql://
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

try:
    if DATABASE_URL.startswith("sqlite"):
        engine = create_engine(
            DATABASE_URL,
            connect_args={"check_same_thread": False}
        )
    else:
        logger.info(f"Connecting to PostgreSQL database...")
        engine = create_engine(
            DATABASE_URL,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=20
        )
        # Test connection
        with engine.connect() as conn:
            logger.info("Successfully connected to PostgreSQL database.")
except Exception as e:
    logger.warning(f"Failed to connect to primary database ({e}). Falling back to local SQLite.")
    db_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "cipher.db"))
    DATABASE_URL = f"sqlite:///{db_file}"
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False}
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
