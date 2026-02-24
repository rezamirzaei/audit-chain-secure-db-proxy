from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AuthUser


class UserService:
    def __init__(self, session: Session):
        self.session = session

    def get_by_username(self, username: str) -> AuthUser | None:
        return self.session.execute(select(AuthUser).where(AuthUser.username == username)).scalar_one_or_none()

    def get_by_id(self, user_id: int) -> AuthUser | None:
        return self.session.execute(select(AuthUser).where(AuthUser.id == user_id)).scalar_one_or_none()

