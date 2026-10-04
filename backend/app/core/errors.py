"""Custom exception hierarchy mapped to HTTP responses."""

from fastapi import Request, status
from fastapi.responses import JSONResponse


class NetGuardError(Exception):
    """Base class for all NetGuard errors."""

    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    code = "internal_error"

    def __init__(self, message: str = "Internal error"):
        self.message = message
        super().__init__(message)


class NotFoundError(NetGuardError):
    status_code = status.HTTP_404_NOT_FOUND
    code = "not_found"

    def __init__(self, message: str = "Resource not found"):
        super().__init__(message)


class ValidationError(NetGuardError):
    status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
    code = "validation_error"

    def __init__(self, message: str = "Invalid input"):
        super().__init__(message)


class ScanStateError(NetGuardError):
    status_code = status.HTTP_409_CONFLICT
    code = "scan_state_error"

    def __init__(self, message: str = "Scan is not in a valid state for this operation"):
        super().__init__(message)


class ExplanationServiceError(NetGuardError):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    code = "explanation_service_unavailable"

    def __init__(self, message: str = "The local AI explanation service is unavailable"):
        super().__init__(message)


class TargetNotAuthorizedError(NetGuardError):
    status_code = status.HTTP_403_FORBIDDEN
    code = "target_not_authorized"

    def __init__(self, message: str = "Target is not within authorized scope"):
        super().__init__(message)


async def netguard_error_handler(_: Request, exc: NetGuardError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": exc.code, "message": exc.message}},
    )


async def unhandled_error_handler(_: Request, exc: Exception) -> JSONResponse:
    # Log full traceback server-side; return a generic message to clients.
    from app.core.logging import get_logger

    get_logger("app.errors").exception("Unhandled exception: %s", exc)
    return JSONResponse(
        status_code=500,
        content={"error": {"code": "internal_error", "message": "Internal server error"}},
    )
