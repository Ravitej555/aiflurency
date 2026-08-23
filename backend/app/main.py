"""
ThreatLens AI — FastAPI Application Entry Point

Initializes the FastAPI app with:
- Structured JSON logging middleware
- CORS configuration
- Router registration
- Lifespan events (DB connection pool warm-up)
- Health & readiness endpoints
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.database import engine, Base
from app.middleware.logging import LoggingMiddleware
from app.routers import auth, users, threats


# ─────────────────────────────────────────────────────────────────────────────
# Lifespan — run once on startup / shutdown
# ─────────────────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create tables on startup (handled by Alembic in production)."""
    async with engine.begin() as conn:
        # In production, Alembic handles migrations — this is a fallback for
        # local / integration test environments.
        await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


# ─────────────────────────────────────────────────────────────────────────────
# Application Factory
# ─────────────────────────────────────────────────────────────────────────────
def create_app() -> FastAPI:
    app = FastAPI(
        title="ThreatLens AI",
        description="Cybersecurity threat intelligence platform API",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # ── Middleware ──────────────────────────────────────────────────────────
    app.add_middleware(LoggingMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Routers ─────────────────────────────────────────────────────────────
    app.include_router(auth.router,    prefix="/api/v1/auth",    tags=["Authentication"])
    app.include_router(users.router,   prefix="/api/v1/users",   tags=["Users"])
    app.include_router(threats.router, prefix="/api/v1/threats", tags=["Threats"])

    # ── Health / Readiness ──────────────────────────────────────────────────
    @app.get("/health", tags=["Ops"], summary="Liveness probe")
    async def health() -> JSONResponse:
        return JSONResponse({"status": "ok", "service": "threatlens-api"})

    @app.get("/ready", tags=["Ops"], summary="Readiness probe")
    async def ready() -> JSONResponse:
        """Verify the DB is reachable before accepting traffic."""
        try:
            async with engine.connect() as conn:
                await conn.execute(__import__("sqlalchemy").text("SELECT 1"))
            return JSONResponse({"status": "ready"})
        except Exception as exc:
            return JSONResponse({"status": "not_ready", "detail": str(exc)}, status_code=503)

    return app


app = create_app()
