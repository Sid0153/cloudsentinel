from fastapi import APIRouter

from app.api import (
    about,
    audit_logs,
    auth,
    aws_accounts,
    dashboard,
    findings,
    health,
    resources,
    rules,
    sandbox,
    scans,
    users,
)

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(aws_accounts.router)
api_router.include_router(scans.router)
api_router.include_router(resources.router)
api_router.include_router(findings.router)
api_router.include_router(rules.router)
api_router.include_router(dashboard.router)
api_router.include_router(audit_logs.router)
api_router.include_router(about.router)
api_router.include_router(sandbox.router)
