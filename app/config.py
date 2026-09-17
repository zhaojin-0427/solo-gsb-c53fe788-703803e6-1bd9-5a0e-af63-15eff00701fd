from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = (
        "postgresql+asyncpg://gateway:gateway_change_me@localhost:5432/gateway"
    )
    # 服务端 HMAC 密钥：生产必须显式注入
    server_hmac_key: str = ""
    # 仅本地开发：允许在未配置 SERVER_HMAC_KEY 时使用固定开发密钥
    allow_insecure_dev_key: bool = False
    log_level: str = "INFO"
    port: int = 8080

    def hmac_key_bytes(self) -> bytes:
        if self.server_hmac_key:
            return self.server_hmac_key.encode("utf-8")
        if self.allow_insecure_dev_key:
            return b"dev-only-insecure-hmac-key-do-not-use-in-production"
        raise RuntimeError(
            "SERVER_HMAC_KEY is not configured; refusing to start without a tokenization key"
        )


settings = Settings()
