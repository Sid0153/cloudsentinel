from fastapi import APIRouter

from app.api import (
    auth,
    aws_accounts,
    dashboard,
    findings,
    health,
    resources,
    rules,
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
