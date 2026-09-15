import os
import logging
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.engine import URL

load_dotenv()
logger = logging.getLogger("cipher.database")

DB_USER = os.getenv("DB_USER") or os.getenv("POSTGRES_USER") or os.getenv("PGUSER")
DB_PASSWORD = os.getenv("DB_PASSWORD") or os.getenv("POSTGRES_PASSWORD") or os.getenv("PGPASSWORD")
DB_HOST = os.getenv("DB_HOST") or os.getenv("POSTGRES_HOST") or os.getenv("PGHOST") or "localhost"
DB_PORT = os.getenv("DB_PORT") or os.getenv("POSTGRES_PORT") or os.getenv("PGPORT") or "5432"
DB_NAME = os.getenv("DB_NAME") or os.getenv("POSTGRES_DB") or os.getenv("PGDATABASE") or "cipher_db"

DATABASE_URL = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL")

if not DATABASE_URL:
    if DB_USER and DB_PASSWORD:
        DATABASE_URL = f"postgresql+psycopg://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    else:
        # Default target PostgreSQL connection
        DATABASE_URL = f"postgresql+psycopg://postgres:postgres@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# Normalize standard postgresql:// to postgresql+psycopg://
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)

def init_engine(db_url: str):
    if "sqlite" in db_url:
        return create_engine(
            db_url,
            connect_args={"check_same_thread": False}
        )
    else:
        try:
            pg_engine = create_engine(
                db_url,
                pool_pre_ping=True,
                pool_size=10,
                max_overflow=20
            )
            # Test connectivity
            with pg_engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            logger.info("[CIPHER DB] Connected to PostgreSQL successfully")
            return pg_engine
        except Exception as e:
            logger.warning(
                f"[CIPHER DB] PostgreSQL at {db_url.split('@')[-1] if '@' in db_url else db_url} not reachable ({e}). "
                "Falling back to local SQLite engine for offline execution / test suite."
            )
            return create_engine(
                "sqlite:///./cipher.db",
                connect_args={"check_same_thread": False}
            )

engine = init_engine(DATABASE_URL)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
