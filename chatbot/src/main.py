from fastapi import FastAPI

import models  # noqa: F401 - registers models on Base.metadata
from admin import setup_admin
from auth import create_user, get_user_by_email
from config import settings
from database import Base, SessionLocal, engine

Base.metadata.create_all(bind=engine)


def create_initial_superuser():
    if not (settings.admin_email and settings.admin_password):
        return
    with SessionLocal() as session:
        if get_user_by_email(session, settings.admin_email) is None:
            create_user(
                session,
                email=settings.admin_email,
                password=settings.admin_password.get_secret_value(),
                is_superuser=True,
            )


create_initial_superuser()

app = FastAPI(title="Chatbot")
setup_admin(app, engine)


@app.get("/")
def root():
    return {"status": "ok"}
