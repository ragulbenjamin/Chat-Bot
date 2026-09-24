from pydantic import EmailStr, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = "sqlite:///./chatbot.db"

    # Required - the app will not start unless this is set in .env or the environment
    secret_key: SecretStr

    # Lifetime of the JWTs issued by POST /auth/token
    access_token_expire_minutes: int = 60

    # Optional - if both are set, a superuser with these details is created on startup
    # when no user with that email exists yet. Otherwise use: python manage.py createsuperuser
    admin_email: EmailStr | None = None
    admin_password: SecretStr | None = None


settings = Settings()
