import hashlib
import hmac
from datetime import datetime, timezone
from pathlib import Path

from sqladmin import Admin, ModelView
from sqladmin.authentication import AuthenticationBackend
from sqladmin.authorization import GrantsAuthorizationBackend
from sqladmin.filters import BooleanFilter
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from wtforms import PasswordField

from auth import get_user_by_email, get_user_grants, sync_permissions
from config import settings
from database import SessionLocal
from models import Conversation, Group, Message, Permission, User
from security import DUMMY_HASH, hash_password, verify_password

SECRET_KEY = settings.secret_key.get_secret_value()
TEMPLATES_DIR = Path(__file__).parent / "templates"
MIN_PASSWORD_LENGTH = 8

# Fields on User that only a superuser may change, so staff can't grant themselves access
SUPERUSER_ONLY_FIELDS = ("is_staff", "is_superuser", "groups", "user_permissions")


def current_user(request: Request) -> User | None:
    return getattr(request.state, "admin_user", None)


def _session_hash(user: User) -> str:
    # Changes whenever the password does, which logs out every existing session
    return hmac.new(SECRET_KEY.encode(), (user.hashed_password or "").encode(), hashlib.sha256).hexdigest()


def _check_credentials(email: str, password: str) -> tuple[int, str] | None:
    with SessionLocal() as session:
        user = get_user_by_email(session, email)
        if user is None:
            verify_password(password, DUMMY_HASH)  # same timing as a real check
            return None
        if not (verify_password(password, user.hashed_password) and user.is_active and user.is_staff):
            return None
        user.last_login = datetime.now(timezone.utc)
        session.commit()
        return user.id, _session_hash(user)


def _load_user(user_id: int) -> User | None:
    with SessionLocal() as session:
        stmt = (
            select(User)
            .where(User.id == user_id)
            .options(
                selectinload(User.user_permissions),
                selectinload(User.groups).selectinload(Group.permissions),
            )
        )
        return session.scalars(stmt).first()


class AdminAuth(AuthenticationBackend):
    async def login(self, request: Request) -> bool:
        form = await request.form()
        email = str(form.get("email", "")).strip().lower()
        password = str(form.get("password", ""))
        result = await run_in_threadpool(_check_credentials, email, password)
        if result is None:
            return False
        user_id, auth_hash = result
        request.session.clear()
        request.session.update({"user_id": user_id, "auth_hash": auth_hash})
        return True

    async def logout(self, request: Request) -> bool:
        request.session.clear()
        return True

    async def authenticate(self, request: Request) -> bool:
        user_id = request.session.get("user_id")
        if not user_id:
            return False
        user = await run_in_threadpool(_load_user, user_id)
        valid = (
            user is not None
            and user.is_active
            and user.is_staff
            and hmac.compare_digest(request.session.get("auth_hash", ""), _session_hash(user))
        )
        if not valid:
            request.session.clear()
            return False
        request.state.admin_user = user
        request.state.admin_grants = get_user_grants(user)
        return True

    async def get_user_id(self, request: Request):
        return request.session.get("user_id")


class PermissionAuthorization(GrantsAuthorizationBackend):
    async def get_grants(self, request: Request) -> set[tuple[str, str]]:
        return getattr(request.state, "admin_grants", set())


class SuperuserOnlyMixin:
    """Views that only superusers can see - no permissions are created for them."""

    def is_accessible(self, request: Request) -> bool:
        user = current_user(request)
        return bool(user and user.is_superuser)


class UserAdmin(ModelView, model=User):
    icon = "fa-solid fa-user"
    column_list = [User.id, User.email, User.username, User.is_active, User.is_staff, User.is_superuser, User.last_login]
    column_searchable_list = [User.username, User.email]
    column_sortable_list = [User.id, User.email, User.username, User.last_login]
    column_filters = [BooleanFilter(User.is_active), BooleanFilter(User.is_staff), BooleanFilter(User.is_superuser)]
    column_details_exclude_list = [User.hashed_password]
    column_export_exclude_list = [User.hashed_password]
    form_excluded_columns = [User.hashed_password, User.last_login, User.created_at, User.conversations]
    form_args = {
        "is_staff": {"description": "Can log in to this admin panel. Only superusers can change this."},
        "is_superuser": {"description": "Has every permission without assigning them. Only superusers can change this."},
        "groups": {"description": "Only superusers can change this."},
        "user_permissions": {"description": "Only superusers can change this."},
    }

    async def scaffold_form(self, rules=None):
        form = await super().scaffold_form(rules)
        form.password = PasswordField(
            "Password", description=f"At least {MIN_PASSWORD_LENGTH} characters. Leave blank to keep the current one."
        )
        return form

    def _can_manage(self, request: Request, target: User) -> bool:
        # Staff can't touch superuser accounts (e.g. reset their password and log in as them)
        user = current_user(request)
        return bool(user and (user.is_superuser or not target.is_superuser))

    async def check_can_edit(self, request: Request, model: User) -> bool:
        return await super().check_can_edit(request, model) and self._can_manage(request, model)

    async def check_can_delete(self, request: Request, model: User) -> bool:
        user = current_user(request)
        return (
            await super().check_can_delete(request, model)
            and self._can_manage(request, model)
            and model.id != user.id  # can't delete yourself
        )

    async def on_model_change(self, data: dict, model: User, is_created: bool, request: Request) -> None:
        password = data.pop("password", None)
        if not current_user(request).is_superuser:
            for field in SUPERUSER_ONLY_FIELDS:
                data.pop(field, None)
        if data.get("email"):
            data["email"] = data["email"].strip().lower()

        if password:
            if len(password) < MIN_PASSWORD_LENGTH:
                raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
            model.hashed_password = await run_in_threadpool(hash_password, password)
        elif is_created and data.get("is_staff"):
            raise ValueError("Staff users need a password to log in.")


class GroupAdmin(SuperuserOnlyMixin, ModelView, model=Group):
    icon = "fa-solid fa-users"
    column_list = [Group.id, Group.name]
    column_searchable_list = [Group.name]
    form_columns = [Group.name, Group.permissions]


class PermissionAdmin(SuperuserOnlyMixin, ModelView, model=Permission):
    icon = "fa-solid fa-key"
    # Created automatically for every admin view, so read-only here
    can_create = False
    can_edit = False
    can_delete = False
    column_list = [Permission.identity, Permission.codename, Permission.name]
    column_searchable_list = [Permission.identity, Permission.name]
    column_sortable_list = [Permission.identity, Permission.codename]


class ConversationAdmin(ModelView, model=Conversation):
    icon = "fa-solid fa-comments"
    column_list = [Conversation.id, Conversation.title, Conversation.user, Conversation.created_at]
    column_searchable_list = [Conversation.title]
    column_sortable_list = [Conversation.id, Conversation.created_at]
    form_excluded_columns = [Conversation.created_at, Conversation.messages]


class MessageAdmin(ModelView, model=Message):
    icon = "fa-solid fa-message"
    column_list = [Message.id, Message.conversation, Message.role, Message.content, Message.created_at]
    column_searchable_list = [Message.content]
    column_sortable_list = [Message.id, Message.created_at]
    column_formatters = {Message.content: lambda m, a: m.content[:80]}
    form_excluded_columns = [Message.created_at]


def setup_admin(app, engine):
    admin = Admin(
        app,
        engine,
        title="Chatbot Admin",
        authentication_backend=AdminAuth(secret_key=SECRET_KEY),
        authorization_backend=PermissionAuthorization(),
        templates_dir=str(TEMPLATES_DIR),
    )
    for view in (UserAdmin, GroupAdmin, PermissionAdmin, ConversationAdmin, MessageAdmin):
        admin.add_view(view)

    # Create view/add/change/delete permissions for every permission-controlled view
    with SessionLocal() as session:
        sync_permissions(
            session,
            [
                (view.identity, view.name.lower())
                for view in admin.views
                if isinstance(view, ModelView) and not isinstance(view, SuperuserOnlyMixin)
            ],
        )
    return admin
