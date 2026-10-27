from datetime import datetime, timedelta

import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .clock import utcnow
from .config import get_settings
from .db import get_db
from .models import Person

_bearer = HTTPBearer(auto_error=False)
ALGORITHM = "HS256"


def create_access_token(person_id: int, now: datetime) -> tuple[str, int]:
    ttl = timedelta(minutes=get_settings().access_token_ttl_minutes)
    claims = {"sub": str(person_id), "iat": now, "exp": now + ttl}
    return jwt.encode(claims, get_settings().jwt_secret, algorithm=ALGORITHM), int(ttl.total_seconds())


def get_now() -> datetime:
    return utcnow()


def current_person(request: Request, creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
                   db: Session = Depends(get_db)) -> Person:
    """Resolve the caller from the bearer token. Every route that touches personal data depends on this."""
    unauthorised = HTTPException(401, "not authenticated", headers={"WWW-Authenticate": "Bearer"})
    if creds is None:
        raise unauthorised
    try:
        claims = jwt.decode(creds.credentials, get_settings().jwt_secret, algorithms=[ALGORITHM],
                            options={"require": ["exp", "sub", "iat"]})
        person = db.get(Person, int(claims["sub"]))
    except (jwt.PyJWTError, ValueError):
        raise unauthorised
    if person is None:  # e.g. account erased; old tokens stop working
        raise unauthorised
    request.state.person_id = person.id
    return person
