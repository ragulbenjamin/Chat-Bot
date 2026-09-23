"""Admin user management, like Django's manage.py.

    python manage.py createsuperuser
    python manage.py createstaffuser
    python manage.py changepassword someone@example.com
"""

import argparse
import getpass
import sys

import models  # noqa: F401 - registers models on Base.metadata
from admin import MIN_PASSWORD_LENGTH
from auth import create_user, get_user_by_email
from database import Base, SessionLocal, engine
from security import hash_password


def prompt_password() -> str:
    while True:
        password = getpass.getpass("Password: ")
        if len(password) < MIN_PASSWORD_LENGTH:
            print(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
            continue
        if password != getpass.getpass("Password (again): "):
            print("Passwords didn't match.")
            continue
        return password


def create(args, is_superuser: bool):
    email = args.email or input("Email: ").strip()
    default_username = email.split("@")[0]
    username = args.username or input(f"Username [{default_username}]: ").strip() or default_username
    password = prompt_password()
    with SessionLocal() as session:
        try:
            create_user(session, email, password, username, is_staff=True, is_superuser=is_superuser)
        except ValueError as e:
            sys.exit(f"Error: {e}")
    print(f"{'Superuser' if is_superuser else 'Staff user'} {email} created.")


def changepassword(args):
    with SessionLocal() as session:
        user = get_user_by_email(session, args.email)
        if user is None:
            sys.exit(f"Error: no user with email {args.email}")
        user.hashed_password = hash_password(prompt_password())
        session.commit()
    print(f"Password changed for {args.email}.")


def main():
    parser = argparse.ArgumentParser(description="Manage admin users")
    commands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("createsuperuser", "Create a user with every permission"),
        ("createstaffuser", "Create a user who can log in; give them permissions in the admin"),
    ):
        cmd = commands.add_parser(name, help=help_text)
        cmd.add_argument("--email")
        cmd.add_argument("--username")
    cmd = commands.add_parser("changepassword", help="Change a user's password")
    cmd.add_argument("email")

    args = parser.parse_args()
    Base.metadata.create_all(bind=engine)
    if args.command == "createsuperuser":
        create(args, is_superuser=True)
    elif args.command == "createstaffuser":
        create(args, is_superuser=False)
    else:
        changepassword(args)


if __name__ == "__main__":
    main()
