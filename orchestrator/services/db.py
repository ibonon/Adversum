from sqlmodel import SQLModel
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
import os
from pathlib import Path

# Provide a fallback for local testing, using SQLite to avoid needing PostgreSQL locally
DATABASE_URL = os.getenv(
    "DATABASE_URL", 
    "sqlite+aiosqlite:///adversum_local.db"
)

# Async engine - pool settings not needed for sqlite
engine = create_async_engine(DATABASE_URL, echo=False)

async def create_db_and_tables():
    """Creates the tables defined in the SQLModel metadata."""
    from ..models.sql_models import Job, JobStatus, FindingModel, AuditLog, FileHash, CachedFinding
    async with engine.begin() as conn:
        # Create all tables
        await conn.run_sync(SQLModel.metadata.create_all)

# Async dependency for FastAPI
async def get_session() -> AsyncSession:
    async_session = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    async with async_session() as session:
        yield session


def get_engine():
    """Returns the global async engine, or None if not initialized."""
    return engine

