"""
Adversum — Database Service & Async Engine
===========================================
Production-hardened SQLite (WAL mode) and PostgreSQL connection pool.
"""

from sqlmodel import SQLModel
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import event
import os
import logging
from pathlib import Path

logger = logging.getLogger("adversum.db")

DATABASE_URL = os.getenv(
    "DATABASE_URL", 
    "sqlite+aiosqlite:///adversum_local.db"
)

# Engine configuration depending on dialect
_is_sqlite = "sqlite" in DATABASE_URL

engine_kwargs = {"echo": False}
if _is_sqlite:
    # SQLite connection settings
    engine_kwargs.update({
        "connect_args": {"check_same_thread": False, "timeout": 30.0}
    })
else:
    # PostgreSQL production pooling settings
    engine_kwargs.update({
        "pool_size": int(os.getenv("DB_POOL_SIZE", "20")),
        "max_overflow": int(os.getenv("DB_MAX_OVERFLOW", "10")),
        "pool_pre_ping": True,
        "pool_recycle": 3600,
    })

engine = create_async_engine(DATABASE_URL, **engine_kwargs)

# Hook for SQLite high-concurrency WAL mode
if _is_sqlite:
    @event.listens_for(engine.sync_engine, "connect")
    def _set_sqlite_pragmas(dbapi_connection, connection_record):
        try:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA synchronous=NORMAL;")
            cursor.execute("PRAGMA busy_timeout=10000;")
            cursor.close()
        except Exception as e:
            logger.warning(f"Failed to set SQLite PRAGMAs: {e}")

# Thread-safe async session factory
async_session_factory = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)


async def create_db_and_tables():
    """Creates the tables defined in the SQLModel metadata."""
    from ..models.sql_models import Job, JobStatus, FindingModel, AuditLog, FileHash, CachedFinding
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
        await conn.run_sync(_migrate_finding_columns)


# Colonnes ajoutées après la création initiale de `findingmodel`. `create_all`
# ne modifie pas une table existante : on les ajoute explicitement (nullable,
# donc les lignes antérieures restent valides avec NULL).
_FINDING_MIGRATION_COLUMNS = (
    ("provenance", "VARCHAR"),
    ("nemotron_line", "INTEGER"),
    ("resolved_line", "INTEGER"),
    ("anchor_status", "VARCHAR"),
    ("z3_verdict", "VARCHAR"),
)


def _migrate_finding_columns(sync_conn):
    from sqlalchemy import inspect, text
    inspector = inspect(sync_conn)
    if "findingmodel" not in inspector.get_table_names():
        return
    existing = {c["name"] for c in inspector.get_columns("findingmodel")}
    for name, sql_type in _FINDING_MIGRATION_COLUMNS:
        if name not in existing:
            sync_conn.execute(text(f"ALTER TABLE findingmodel ADD COLUMN {name} {sql_type}"))
            logger.info(f"[migration] findingmodel.{name} ajoutée.")


async def get_session() -> AsyncSession:
    """Async dependency for FastAPI with automatic rollback on error."""
    async with async_session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


def get_engine():
    """Returns the global async engine."""
    return engine


async def close_db():
    """Cleanly disposes of the connection pool on application shutdown."""
    if engine:
        await engine.dispose()
        logger.info("Database connection pool disposed cleanly.")
