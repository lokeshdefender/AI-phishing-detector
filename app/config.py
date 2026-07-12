import os
from dataclasses import dataclass


@dataclass(frozen=True)
class AppConfig:
    app_env: str
    app_version: str
    host: str
    port: int
    reload: bool
    log_level: str
    cors_allow_origins: list[str]
    auth_cookie_secure: bool
    auth_cookie_samesite: str



def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}



def _parse_cors_origins(value: str | None) -> list[str]:
    raw = (value or "*").strip()
    if not raw:
        return ["*"]
    if raw == "*":
        return ["*"]
    return [item.strip() for item in raw.split(",") if item.strip()]



def load_config() -> AppConfig:
    app_env = (os.getenv("APP_ENV") or os.getenv("ENV") or "development").strip().lower()
    default_reload = app_env == "development"
    return AppConfig(
        app_env=app_env,
        app_version=(os.getenv("APP_VERSION") or "0.3.0").strip(),
        host=(os.getenv("APP_HOST") or "0.0.0.0").strip(),
        port=int(os.getenv("PORT") or os.getenv("APP_PORT") or "8000"),
        reload=_as_bool(os.getenv("APP_RELOAD"), default_reload),
        log_level=(os.getenv("LOG_LEVEL") or "INFO").strip().upper(),
        cors_allow_origins=_parse_cors_origins(os.getenv("CORS_ALLOW_ORIGINS")),
        auth_cookie_secure=_as_bool(os.getenv("AUTH_COOKIE_SECURE"), app_env == "production"),
        auth_cookie_samesite=(os.getenv("AUTH_COOKIE_SAMESITE") or "lax").strip().lower(),
    )


CONFIG = load_config()
