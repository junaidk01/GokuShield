"""
Configuration for the GokuShield Telegram bot, loaded from environment
variables. Fails fast and loudly if required values are missing rather
than starting in a half-working state.
"""
import os
from dataclasses import dataclass, field


@dataclass
class BotConfig:
    telegram_token: str
    api_url: str
    admin_telegram_ids: set[int]
    admin_email: str
    admin_password: str

    @classmethod
    def from_env(cls) -> "BotConfig":
        token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
        api_url = os.environ.get("GOKUSHIELD_API_URL", "http://backend:5000")

        raw_ids = os.environ.get("ADMIN_TELEGRAM_IDS", "")
        admin_ids = set()
        for part in raw_ids.split(","):
            part = part.strip()
            if part:
                try:
                    admin_ids.add(int(part))
                except ValueError:
                    pass

        admin_email = os.environ.get("GOKUSHIELD_ADMIN_EMAIL", "")
        admin_password = os.environ.get("GOKUSHIELD_ADMIN_PASSWORD", "")

        if not token:
            raise RuntimeError(
                "TELEGRAM_BOT_TOKEN is not set. Get one from @BotFather on "
                "Telegram — see the setup guide."
            )

        return cls(
            telegram_token=token,
            api_url=api_url,
            admin_telegram_ids=admin_ids,
            admin_email=admin_email,
            admin_password=admin_password,
        )
