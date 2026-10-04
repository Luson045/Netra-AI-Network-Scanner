"""Shared Pydantic schemas."""

from pydantic import BaseModel, Field


class ErrorEnvelope(BaseModel):
    """Standard error response body."""

    error: ErrorBody


class ErrorBody(BaseModel):
    code: str
    message: str


class PageParams(BaseModel):
    """Common pagination query parameters."""

    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)
    page: int = Field(default=1, ge=1)

    @property
    def computed_offset(self) -> int:
        return (self.page - 1) * self.limit if self.page != 1 else self.offset
