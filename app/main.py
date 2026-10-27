import time
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

# ADD THESE TWO IMPORTS TO OVERRIDE THE DEFAULT SWAGGER ENGINE
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html

from app.core.config import settings
from app.core.database import engine, Base

from app.api.v1.endpoints import auth, indicators, websocket
from fastapi import FastAPI
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.staticfiles import StaticFiles

# 1. Initialize DB Tables
Base.metadata.create_all(bind=engine)

# 2. Disable default automatic docs routes so we can inject our own
app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Sentinova ThreatLens — Cyber Threat Intelligence Dashboard Enterprise API Core Engine",
    version="1.0.0",
    docs_url=None,  # Set to None to deactivate default online CDN assets
    redoc_url=None,  # Set to None to deactivate default online CDN assets
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
)

# ---------------------------------------------------------
# CUSTOM LOCALIZED/MIRRORED SWAGGER ROUTING INTERFACES
# ---------------------------------------------------------
app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    return get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=app.title + " - Sentinova threatLens Documentation",
        oauth2_redirect_url=app.swagger_ui_oauth2_redirect_url,
        # Point to your local downloaded copy of the assets
        swagger_js_url="/static/swagger-ui-bundle.js",
        swagger_css_url="/static/swagger-ui.css",
    )


@app.get("/redoc", include_in_schema=False)
async def custom_redoc_html():
    """Injects a reliable alternate CDN engine for the ReDoc data manifest."""
    return get_redoc_html(
        openapi_url=app.openapi_url,
        title=app.title + " - ReDoc Architecture Ledger",
        redoc_js_url="/static/redoc.js",
    )


# ---------------------------------------------------------
# SECURITY MATRIX MIDDLEWARE & CORROSION SECURITY
# ---------------------------------------------------------
# Enforces safe communication surfaces across external or isolated dashboard UI layouts
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict to trusted web origins on production deployments
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class SecurityHardeningMiddleware(BaseHTTPMiddleware):
    """
    Applies security headers directly at the API gateway layer
    to mitigate XSS, injection vectors, and clickjacking (NFR-06 Compliance).
    """

    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        response = await call_next(request)

        process_time = (time.time() - start_time) * 1000
        response.headers["X-Process-Time-Ms"] = f"{process_time:.2f}"

        # Apply standard system baseline security controls
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers[
            "Strict-Transport-Security"
        ] = "max-age=31536000; includeSubDomains"

        # FIXED: Explicitly whitelist Cloudflare cdnjs to allow Swagger UI scripts to parse cleanly
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cloudflare.com; "
            "img-src 'self' data: https://fastapi.tiangolo.com; "
            "frame-ancestors 'none';"
        )

        return response


app.add_middleware(SecurityHardeningMiddleware)


# ---------------------------------------------------------
# UNIFORM GLOBAL ERROR MANAGEMENT ENVELOPE
# ---------------------------------------------------------
@app.exception_handler(Exception)
async def global_runtime_exception_handler(request: Request, exc: Exception):
    """
    Transforms loose systemic failures into structural, machine-readable JSON envelopes
    matching Section 10.4 Error Handling specifications.
    """
    # Track arbitrary process hashes for backend metric debugging
    correlation_id = request.headers.get("X-Correlation-ID", "UNKNOWN_SESSION_ID")

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error_code": "SYSTEMIC_RUNTIME_FAULT",
            "message": "An unhandled execution crash occurred inside the application processing layers.",
            "correlation_id": correlation_id,
        },
    )


# ---------------------------------------------------------
# SYSTEM INTEGRITY & HEALTH MONITORING ENDPOINT
# ---------------------------------------------------------
@app.get("/health", tags=["Telemetry"], status_code=status.HTTP_200_OK)
async def system_health_check():
    """
    Provides automated infrastructure health validation metrics to container orchestrators
    like Kubernetes liveness probes (NFR-10 Compliance).
    """
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "ecosystem": settings.PROJECT_NAME,
        "version": "1.0.0-Baseline",
    }


# ---------------------------------------------------------
# ROUTING CONTROLLERS PIPELINE MOUNTING
# ---------------------------------------------------------
# Versioned endpoints mapping exactly to the structural requirements matrix
app.include_router(
    auth.router,
    prefix=f"{settings.API_V1_STR}/auth",
    tags=["Authentication Operations"],
)
app.include_router(
    indicators.router,
    prefix=f"{settings.API_V1_STR}/indicators",
    tags=["Threat Intelligence Core"],
)


# Mount real-time websocket connections alongside standard REST endpoints
app.include_router(websocket.router, prefix=f"{settings.API_V1_STR}/ws")
