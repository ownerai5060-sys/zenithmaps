"""Admin / operator API-key management (create / list / revoke / rotate).

Scopes (light portal RBAC):
- ``keys:read`` — list keys (operator)
- ``admin:keys`` — create, revoke, rotate, rotation policy (admin)

Secrets are returned **only** on create/rotate; list never echoes the secret.
Auth may be ``X-API-Key``, Bearer, or the portal session cookie set after
OIDC / stub login (so the browser need not paste an admin key).

Policy rotation: ``GET/PUT .../rotation-policy`` + ``POST .../rotation-policy/run``
(or cron ``python -m api.rotation_worker``).
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from api.auth import Principal
from api.errors import ApiError
from api.keystore import get_keystore
from api.oauth import get_token_store
from api.rate_limit import require_rate_limited, require_rate_limited_any
from api.rotation_policy import apply_due_rotations, get_rotation_policy_store

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
    rotated_at: float = 0.0
    revoked: bool = False
    revoked_at: Optional[float] = None


class CreateKeyResponse(KeyPublic):
    secret: str = Field(
        ...,
        description="Shown once on create — store in a secret manager",
    )


class RotateKeyResponse(KeyPublic):
    secret: str = Field(
        ...,
        description="New secret shown once — previous secret is invalidated",
    )
    previous_tokens_revoked: int = 0


class KeyListResponse(BaseModel):
    items: list[KeyPublic]
    count: int


class RotationPolicyBody(BaseModel):
    enabled: Optional[bool] = None
    max_age_days: Optional[float] = Field(
        default=None, description="Rotate secrets older than this many days"
    )
    include_key_ids: Optional[list[str]] = Field(
        default=None,
        description="When non-empty, only these key_ids are candidates",
    )
    exclude_key_ids: Optional[list[str]] = Field(
        default=None,
        description="Never rotate these key_ids (defaults exclude demo stubs)",
    )


class RotationRunBody(BaseModel):
    dry_run: bool = False
    force: bool = Field(
        default=False,
        description="Run even when policy.enabled is false",
    )
    include_secrets: bool = Field(
        default=False,
        description="Include new secrets in the response (handle carefully)",
    )


def _key_public(k: Any) -> KeyPublic:
    return KeyPublic(
        key_id=k.key_id,
        scopes=sorted(k.scopes),
        label=k.label,
        created_at=k.created_at,
        rotated_at=getattr(k, "rotated_at", 0.0) or k.created_at,
        revoked=k.revoked,
        revoked_at=k.revoked_at,
    )


@router.get(
    "",
    response_model=KeyListResponse,
    summary="List API keys (secrets omitted)",
)
def list_keys(
    include_revoked: bool = False,
    _principal: Principal = Depends(
        require_rate_limited_any("keys:read", "admin:keys")
    ),
) -> KeyListResponse:
    stored = get_keystore().list_keys(include_revoked=include_revoked)
    items = [_key_public(k) for k in stored]
    return KeyListResponse(items=items, count=len(items))


@router.get(
    "/rotation-policy",
    summary="Get scheduled key-rotation policy",
)
def get_rotation_policy(
    _principal: Principal = Depends(
        require_rate_limited_any("keys:read", "admin:keys")
    ),
) -> dict[str, Any]:
    get_rotation_policy_store().configure()
    return get_rotation_policy_store().get().to_public_dict()


@router.put(
    "/rotation-policy",
    summary="Update scheduled key-rotation policy",
)
def put_rotation_policy(
    body: RotationPolicyBody,
    _principal: Principal = Depends(require_rate_limited("admin:keys")),
) -> dict[str, Any]:
    get_rotation_policy_store().configure()
    try:
        updated = get_rotation_policy_store().update(
            enabled=body.enabled,
            max_age_days=body.max_age_days,
            include_key_ids=body.include_key_ids,
            exclude_key_ids=body.exclude_key_ids,
        )
    except ValueError as exc:
        raise ApiError(status_code=400, code="bad_request", message=str(exc)) from exc
    return updated.to_public_dict()


@router.post(
    "/rotation-policy/run",
    summary="Apply due policy rotations now (or dry-run)",
)
def run_rotation_policy(
    body: RotationRunBody | None = None,
    dry_run: bool = Query(default=False),
    force: bool = Query(default=False),
    include_secrets: bool = Query(default=False),
    _principal: Principal = Depends(require_rate_limited("admin:keys")),
) -> dict[str, Any]:
    opts = body or RotationRunBody()
    report = apply_due_rotations(
        dry_run=bool(opts.dry_run or dry_run),
        force_enabled=bool(opts.force or force),
        include_secrets=bool(opts.include_secrets or include_secrets),
    )
    return report.to_public_dict(
        include_secrets=bool(opts.include_secrets or include_secrets)
    )


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
    pub = _key_public(created)
    return CreateKeyResponse(**pub.model_dump(), secret=created.secret)


@router.post(
    "/{key_id}/rotate",
    response_model=RotateKeyResponse,
    summary="Rotate an API key secret (new secret returned once)",
)
def rotate_key(
    key_id: str,
    _principal: Principal = Depends(require_rate_limited("admin:keys")),
) -> RotateKeyResponse:
    rotated = get_keystore().rotate(key_id)
    if rotated is None:
        raise ApiError(
            status_code=404,
            code="not_found",
            message=f"API key '{key_id}' was not found or is revoked",
        )
    revoked_n = get_token_store().revoke_for_key(key_id)
    pub = _key_public(rotated)
    return RotateKeyResponse(
        **pub.model_dump(),
        secret=rotated.secret,
        previous_tokens_revoked=revoked_n,
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
    return _key_public(revoked)
