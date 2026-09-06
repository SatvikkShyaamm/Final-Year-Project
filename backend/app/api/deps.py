"""
Shared FastAPI dependencies.

`get_db` is re-exported here (rather than importing app.core.database
directly in every endpoint) so that Module 2 can later add
`get_current_user` / `get_current_admin` dependencies in exactly one place,
and every endpoint module already imports its DB/session deps from here.
"""
from app.core.database import get_db  # noqa: F401

# Placeholder for Module 2:
# def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User: ...
