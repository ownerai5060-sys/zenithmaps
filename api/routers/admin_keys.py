"""Admin API-key management (create / list / revoke).

Protected by scope ``admin:keys``. Not a full self-service portal — operators
call these endpoints (or curl) with an admin key. Secrets are returned **only**
on create; list/revoke never echo the secret.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from api.auth import Principal
from api.errors import ApiError
from api.keystore import get_keystore
from api.oauth import get_token_store
from api.rate_limit import require_rate_limited

router = APIRouter(prefix="/admin/keys", tags=["admin"])


class CreateKeyRequest(BaseModel):
    key_id: Optional[str] = Field(
        default=None,
        description="Optional stable id; auto-generated when omitted",
    )
    scopes: list[str] = Field(default_factory=lambda: ["layers:read"])
    label: str = ""


class KeyPublic(BaseModel):
    key_id: str
    scopes: list[str]
    label: str
    created_at: float
    revoked: bool = False
    revoked_at: Optional[float] = None


class CreateKeyResponse(KeyPublic):
    secret: str = Field(
        ...,
        description="Shown once on create — store in a secret manager",
    )


class KeyListResponse(BaseModel):
    items: list[KeyPublic]
    count: int


@router.get(
    "",
    response_model=KeyListResponse,
    summary="List API keys (secrets omitted)",
)
def list_keys(
    include_revoked: bool = False,
    _principal: Principal = Depends(require_rate_limited("admin:keys")),
) -> KeyListResponse:
    stored = get_keystore().list_keys(include_revoked=include_revoked)
    items = [
        KeyPublic(
            key_id=k.key_id,
            scopes=sorted(k.scopes),
            label=k.label,
            created_at=k.created_at,
            revoked=k.revoked,
            revoked_at=k.revoked_at,
        )
        for k in stored
    ]
    return KeyListResponse(items=items, count=len(items))


@router.post(
    "",
    response_model=CreateKeyResponse,
    status_code=201,
    summary="Create an API key (secret returned once)",
)
def create_key(
    body: CreateKeyRequest,
    principal: Principal = Depends(require_rate_limited("admin:keys")),
) -> CreateKeyResponse:
    try:
        created = get_keystore().create(
            key_id=body.key_id,
            scopes=body.scopes,
            label=body.label,
        )
    except ValueError as exc:
        raise ApiError(status_code=400, code="bad_request", message=str(exc)) from exc
    except KeyError as exc:
        raise ApiError(status_code=409, code="conflict", message=str(exc)) from exc
    # Best-effort catalog/admin webhook ping (N3); never fails key create.
    try:
        from api.webhooks import notify_key_created

        notify_key_created(key_id=created.key_id, actor=principal.key_id)
    except Exception:  # noqa: BLE001
        pass
    return CreateKeyResponse(
        key_id=created.key_id,
        secret=created.secret,
        scopes=sorted(created.scopes),
        label=created.label,
        created_at=created.created_at,
        revoked=False,
    )


@router.delete(
    "/{key_id}",
    response_model=KeyPublic,
    summary="Revoke an API key",
)
def revoke_key(
    key_id: str,
    _principal: Principal = Depends(require_rate_limited("admin:keys")),
) -> KeyPublic:
    revoked = get_keystore().revoke(key_id)
    if revoked is None:
        raise ApiError(
            status_code=404,
            code="not_found",
            message=f"API key '{key_id}' was not found",
        )
    get_token_store().revoke_for_key(key_id)
    return KeyPublic(
        key_id=revoked.key_id,
        scopes=sorted(revoked.scopes),
        label=revoked.label,
        created_at=revoked.created_at,
        revoked=revoked.revoked,
        revoked_at=revoked.revoked_at,
    )
