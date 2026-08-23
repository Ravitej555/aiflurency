"""
ThreatLens AI — Structured JSON Logging Middleware

Emits one JSON log line per request containing:
  - timestamp, method, path, status_code, duration_ms
  - request_id (for distributed tracing correlation)
  - client IP (X-Forwarded-For aware for ALB/nginx)

All logs go to stdout so container orchestrators (ECS, CloudWatch) can collect them.
"""

import time
import uuid
import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from pythonjsonlogger import jsonlogger

from app.core.config import settings

# ── Logger Setup ─────────────────────────────────────────────────────────────
logger = logging.getLogger("threatlens.api")
logger.setLevel(getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO))

if not logger.handlers:
    handler = logging.StreamHandler()
    if settings.LOG_FORMAT == "json":
        formatter = jsonlogger.JsonFormatter(
            fmt="%(asctime)s %(name)s %(levelname)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    else:
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
        )
    handler.setFormatter(formatter)
    logger.addHandler(handler)


class LoggingMiddleware(BaseHTTPMiddleware):
    """
    Log every HTTP request/response as a single structured JSON line.

    Skips logging for /health and /ready probes to reduce noise.
    """

    SKIP_PATHS = {"/health", "/ready", "/metrics"}

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path in self.SKIP_PATHS:
            return await call_next(request)

        request_id = str(uuid.uuid4())
        start = time.perf_counter()

        # Propagate request ID for downstream tracing
        request.state.request_id = request_id

        response: Response = await call_next(request)
        duration_ms = round((time.perf_counter() - start) * 1000, 2)

        # Resolve real client IP behind ALB / reverse proxy
        client_ip = (
            request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or request.headers.get("X-Real-IP", "")
            or (request.client.host if request.client else "unknown")
        )

        log_record = {
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "query": str(request.url.query) or None,
            "status_code": response.status_code,
            "duration_ms": duration_ms,
            "client_ip": client_ip,
            "user_agent": request.headers.get("User-Agent", ""),
        }

        level = logging.WARNING if response.status_code >= 400 else logging.INFO
        logger.log(level, "request", extra=log_record)

        # Inject request ID into response headers for client-side tracing
        response.headers["X-Request-ID"] = request_id
        return response
