"""JWT validation and tenant context extraction for HelpDeskAI.

Provides both a secure path (JWT signature-verified tenant extraction) and
an insecure path (raw X-Tenant-Id header) to contrast correct vs vulnerable patterns.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

import jwt
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/v1/auth/token")

_TENANT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

JWT_SECRET = os.environ.get("JWT_SECRET", "changeme-replace-in-production")
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")


@dataclass
class TokenPayload:
    """Verified JWT claims extracted from a validated bearer token."""

    tenant_id: str
    sub: str
    email: str
    exp: int


class JWTValidator:
    """Validates JWT bearer tokens and extracts structured claims.

    Uses PyJWT with signature verification enabled (the correct pattern).
    Algorithm is pinned to prevent the 'none' algorithm attack.
    """

    def __init__(self, secret: str, algorithm: str = "HS256") -> None:
        self.secret = secret
        self.algorithm = algorithm

    def validate(self, token: str) -> TokenPayload:
        """Decode and verify a JWT, returning the structured payload.

        Signature verification is ENABLED. The 'algorithms' list is explicit
        to prevent algorithm-confusion attacks (e.g., RS256 key confused as HS256).

        # SECURITY FIXTURE: CTRL-AUTH-001 — JWT signature verification is enabled.
        # jwt.decode() will raise jwt.InvalidSignatureError for tampered tokens,
        # jwt.ExpiredSignatureError for expired tokens, and jwt.DecodeError for
        # malformed tokens. tenant_id is extracted from the verified payload, not
        # from a client-supplied header.
        """
        try:
            payload = jwt.decode(
                token,
                self.secret,
                algorithms=[self.algorithm],
            )
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except jwt.InvalidTokenError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials.",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc

        tenant_id = payload.get("tenant_id")
        if not tenant_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token is missing required tenant_id claim.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return TokenPayload(
            tenant_id=tenant_id,
            sub=payload.get("sub", ""),
            email=payload.get("email", ""),
            exp=payload.get("exp", 0),
        )


_validator = JWTValidator(secret=JWT_SECRET, algorithm=JWT_ALGORITHM)


async def get_current_tenant(token: str = Depends(oauth2_scheme)) -> TokenPayload:
    """FastAPI dependency: extract tenant from a verified JWT bearer token.

    # SECURITY FIXTURE: CTRL-AUTH-001 — tenant_id derived from verified JWT claim
    # (contrast with VULN-MT-002 in api/routers/chat.py which reads the raw
    # X-Tenant-Id header without any cryptographic verification).
    """
    return _validator.validate(token)


async def get_tenant_from_header(
    x_tenant_id: str | None = Header(default=None),
) -> str:
    """FastAPI dependency: extract tenant ID directly from the X-Tenant-Id HTTP header.

    # SECURITY FIXTURE: VULN-MT-002 — tenant_id taken from client-supplied
    # X-Tenant-Id header, not a verified JWT. A caller can spoof any tenant by
    # setting this header to an arbitrary value. There is no cryptographic binding
    # between the header value and the authenticated identity.
    """
    if not x_tenant_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="X-Tenant-Id header is required.",
        )
    if not _TENANT_ID_RE.fullmatch(x_tenant_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="X-Tenant-Id header has an invalid format.",
        )
    # Format-checked only: the caller still controls this value (VULN-MT-002).
    return x_tenant_id
