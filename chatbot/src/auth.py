from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from models import Group, Permission, User
from security import hash_password

# Django-style permission codenames, and the sqladmin actions each one unlocks.
PERMISSION_ACTIONS: dict[str, tuple[str, ...]] = {
    "view": ("list", "details", "export"),
    "add": ("create",),
    "change": ("edit",),
    "delete": ("delete",),
}


def get_user_by_email(session: Session, email: str) -> User | None:
    stmt = (
        select(User)
        .where(func.lower(User.email) == email.strip().lower())
        .options(
            selectinload(User.user_permissions),
            selectinload(User.groups).selectinload(Group.permissions),
        )
    )
    return session.scalars(stmt).first()


def get_user_grants(user: User) -> set[tuple[str, str]]:
    """The (view identity, sqladmin action) pairs this user may perform."""
    if user.is_superuser:
        return {("*", "*")}
    permissions = {*user.user_permissions, *(p for g in user.groups for p in g.permissions)}
    return {
        (p.identity, action)
        for p in permissions
        for action in PERMISSION_ACTIONS.get(p.codename, ())
    }


def sync_permissions(session: Session, views: list[tuple[str, str]]) -> None:
    """Make sure a view/add/change/delete permission exists for every (identity, label) view."""
    existing = set(session.execute(select(Permission.identity, Permission.codename)).all())
    for identity, label in views:
        for codename in PERMISSION_ACTIONS:
            if (identity, codename) not in existing:
                session.add(
                    Permission(identity=identity, codename=codename, name=f"Can {codename} {label}")
                )
    session.commit()


def create_user(
    session: Session,
    email: str,
    password: str,
    username: str | None = None,
    is_staff: bool = False,
    is_superuser: bool = False,
) -> User:
    if get_user_by_email(session, email):
        raise ValueError(f"A user with email {email} already exists")
    user = User(
        email=email.strip().lower(),
        username=username or email.split("@")[0],
        hashed_password=hash_password(password),
        is_staff=is_staff or is_superuser,
        is_superuser=is_superuser,
    )
    session.add(user)
    session.commit()
    return user
