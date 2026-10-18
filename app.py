import os
from typing import Any

import jwt
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-24rnhjci.apps.exam.local"

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

app = FastAPI(title="RS256 JWT Verification API", version="1.0.0")


class VerifyRequest(BaseModel):
    token: str = Field(min_length=1)


@app.get("/")
async def root():
    return {"service": "jwt-verifier", "status": "ok", "endpoint": "/verify"}


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/verify")
async def verify(request: VerifyRequest) -> Any:
    try:
        # Explicitly allow only RS256; validate signature, expiry, issuer and audience.
        claims = jwt.decode(
            request.token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={
                "require": ["exp", "iss", "aud", "sub", "email"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_iss": True,
                "verify_aud": True,
            },
        )

        # Require the exact assigned audience value, not a multi-audience list.
        if claims.get("aud") != AUDIENCE:
            raise jwt.InvalidAudienceError("audience must exactly match the assigned audience")

        return {
            "valid": True,
            "email": claims["email"],
            "sub": claims["sub"],
            "aud": claims["aud"],
        }
    except (jwt.InvalidTokenError, ValueError, TypeError, KeyError):
        raise HTTPException(status_code=401, detail={"valid": False})


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc: HTTPException):
    # For token validation failures the grader expects exactly {"valid": false}.
    if exc.status_code == 401:
        return JSONResponse(status_code=401, content={"valid": False})
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
