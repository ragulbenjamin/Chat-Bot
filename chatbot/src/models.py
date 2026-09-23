from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, String, Table, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base

user_groups = Table(
    "user_groups",
    Base.metadata,
    Column("user_id", ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("group_id", ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True),
)

user_permissions = Table(
    "user_permissions",
    Base.metadata,
    Column("user_id", ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("permission_id", ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True),
)

group_permissions = Table(
    "group_permissions",
    Base.metadata,
    Column("group_id", ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True),
    Column("permission_id", ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True),
)


class Permission(Base):
    """One action on one admin view, e.g. identity="conversation", codename="change"."""

    __tablename__ = "permissions"
    __table_args__ = (UniqueConstraint("identity", "codename"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    identity: Mapped[str] = mapped_column(String(100))  # sqladmin ModelView.identity
    codename: Mapped[str] = mapped_column(String(50))  # view / add / change / delete
    name: Mapped[str] = mapped_column(String(255))

    def __str__(self):
        return f"{self.identity} | {self.name}"


class Group(Base):
    __tablename__ = "groups"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(150), unique=True)

    permissions: Mapped[list[Permission]] = relationship(secondary=group_permissions)
    users: Mapped[list["User"]] = relationship(secondary=user_groups, back_populates="groups")

    def __str__(self):
        return self.name


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(100), index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True)
    hashed_password: Mapped[str | None] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(default=True)
    is_staff: Mapped[bool] = mapped_column(default=False)  # can log in to the admin
    is_superuser: Mapped[bool] = mapped_column(default=False)  # has every permission
    last_login: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    groups: Mapped[list[Group]] = relationship(secondary=user_groups, back_populates="users")
    user_permissions: Mapped[list[Permission]] = relationship(secondary=user_permissions)
    conversations: Mapped[list["Conversation"]] = relationship(back_populates="user")

    def __str__(self):
        return self.email


class Conversation(Base):
    __tablename__ = "conversations"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(200), default="New chat")
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    user: Mapped[User] = relationship(back_populates="conversations")
    messages: Mapped[list["Message"]] = relationship(
        back_populates="conversation", cascade="all, delete-orphan"
    )

    def __str__(self):
        return self.title


class Message(Base):
    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(primary_key=True)
    conversation_id: Mapped[int] = mapped_column(ForeignKey("conversations.id"))
    role: Mapped[str] = mapped_column(String(20))  # "user" or "assistant"
    content: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    conversation: Mapped[Conversation] = relationship(back_populates="messages")

    def __str__(self):
        return f"{self.role}: {self.content[:40]}"
