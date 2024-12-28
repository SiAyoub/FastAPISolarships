import os

SECRET_KEY = os.getenv(
    "SECRET_KEY",
    "sraGbRmjYQXmYdnrgPk!OFE35UP6n/QqeoED=iu/bUXBFSSPwnsuprP6T45Qsbwywu2khUka!6IIleY",
)
if not SECRET_KEY:
    SECRET_KEY = os.urandom(32)

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRES_MINUTES = 30
REFRESH_TOKEN_EXPIRES_MINUTES = 15 * 24 * 60  # 15 days