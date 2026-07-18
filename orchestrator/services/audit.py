from sqlalchemy.ext.asyncio import AsyncSession
from ..models.sql_models import AuditLog
from .db import engine

async def log_audit(action: str, target: str, status: str, details: str = None):
    """
    Writes an entry to the Audit Log.
    Should be called via BackgroundTasks to not block Response.
    """
    try:
        async with AsyncSession(engine) as session:
            entry = AuditLog(
                action=action,
                target=target,
                status=status,
                details=details
            )
            session.add(entry)
            await session.commit()
    except Exception as e:
        # Fallback logging if DB fails
        import logging
        logging.getLogger("adversum.audit").error(f"Failed to write audit log: {e}")
