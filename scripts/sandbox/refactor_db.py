import re
import os

def refactor_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Generic imports
    content = content.replace('from sqlmodel import Session, select, delete', 'from sqlmodel import select, delete\nfrom sqlalchemy.ext.asyncio import AsyncSession')
    content = content.replace('from sqlmodel import Session, select', 'from sqlmodel import select\nfrom sqlalchemy.ext.asyncio import AsyncSession')
    content = content.replace('from sqlmodel import Session', 'from sqlalchemy.ext.asyncio import AsyncSession')
    
    # Types
    content = content.replace(' session: Session =', ' session: AsyncSession =')
    
    # Session handling
    content = content.replace('with Session(engine) as session:', 'async with AsyncSession(engine) as session:')
    content = content.replace('Session(engine)', 'AsyncSession(engine)')

    # Commit / add / delete / refresh
    content = content.replace('session.commit()', 'await session.commit()')
    # session.add() is synchronous in SQLAlchemy
    content = re.sub(r'session\.refresh\((.*?)\)', r'await session.refresh(\1)', content)
    content = re.sub(r'session\.get\((.*?)\)', r'await session.get(\1)', content)

    # FindingModel execution
    content = content.replace('session.exec(findings_query).all()', '(await session.execute(findings_query)).scalars().all()')
    content = content.replace('session.exec(select(FindingModel).where(FindingModel.job_id == id1)).all()', '(await session.execute(select(FindingModel).where(FindingModel.job_id == id1))).scalars().all()')
    content = content.replace('session.exec(select(FindingModel).where(FindingModel.job_id == id2)).all()', '(await session.execute(select(FindingModel).where(FindingModel.job_id == id2))).scalars().all()')

    # Batch fix findings
    content = content.replace('session.exec(stmt).all()', '(await session.execute(stmt)).scalars().all()')
    
    # list_audits specific fix because it uses the same stmt variable as batch fix but needs tuples
    content = content.replace('results = (await session.execute(stmt)).scalars().all()', 'results = (await session.execute(stmt)).all()')

    # One() or scalar_one()
    content = content.replace('session.exec(select(func.count(Job.id))).one()', '(await session.execute(select(func.count(Job.id)))).scalar_one()')
    content = content.replace('session.exec(select(func.count(FindingModel.id))).one()', '(await session.execute(select(func.count(FindingModel.id)))).scalar_one()')
    content = content.replace('session.exec(select(func.avg(Job.robustness_score))).one()', '(await session.execute(select(func.avg(Job.robustness_score)))).scalar_one()')
    content = content.replace('select(func.count(FindingModel.id)).where(FindingModel.job_id == job_id)\n    ).one()', 'select(func.count(FindingModel.id)).where(FindingModel.job_id == job_id)\n    )).scalar_one()')
    content = content.replace('session.exec(\n        select(func.count(FindingModel.id))', '(await session.execute(\n        select(func.count(FindingModel.id))')
    
    # activity
    content = content.replace('session.exec(activity_query).all()', '(await session.execute(activity_query)).all()')
    
    # Analysis pipeline specific
    content = content.replace('session.exec(select(FileHash)).all()', '(await session.execute(select(FileHash))).scalars().all()')
    content = content.replace('session.exec(\n                    delete(CachedFinding).where(CachedFinding.file_path.in_(changed_files))\n                )', 'await session.execute(\n                    delete(CachedFinding).where(CachedFinding.file_path.in_(changed_files))\n                )')
    content = content.replace('session.exec(\n                    select(CachedFinding).where(CachedFinding.file_path.in_(unchanged_files))\n                ).all()', '(await session.execute(\n                    select(CachedFinding).where(CachedFinding.file_path.in_(unchanged_files))\n                )).scalars().all()')
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

if __name__ == '__main__':
    base = r'C:\Users\diass\OneDrive\Desktop\AI\Soft Project\Adversum\adversum'
    refactor_file(os.path.join(base, 'api', 'main.py'))
    refactor_file(os.path.join(base, 'orchestrator', 'pipeline', 'analysis_pipeline.py'))
    print("Refactored files.")
