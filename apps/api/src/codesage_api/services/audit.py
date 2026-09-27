
from __future__ import annotations

import uuid
from collections.abc import Mapping
from typing import Any

from sqlalchemy.orm import Session

from codesage_api.db.models import SecurityAuditRecord

_SENSITIVE = ("token", "secret", "password", "authorization", "cookie")


def redact(value: Any, *, key: str = "") -> Any:
    """Recursively remove credential-shaped values before they reach storage."""
    if any(part in key.lower() for part in _SENSITIVE):
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {str(k): redact(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    return value


def record(
    session: Session,
    *,
    event_type: str,
    outcome: str,
    workspace_id: uuid.UUID | None = None,
    actor_user_id: uuid.UUID | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    detail: Mapping[str, Any] | None = None,
) -> None:

    actor = str(actor_user_id) if actor_user_id is not None else "anonymous"
    resource = resource_type or "system"
    if resource_id is not None:
        resource = f"{resource}:{resource_id}"
    session.add(
        SecurityAuditRecord(
            workspace_id=workspace_id,
            event_type=event_type,
            outcome=outcome,
            actor_identity=actor,
            affected_resource=resource,
            detail=redact(detail) if detail else None,
        )
    )
