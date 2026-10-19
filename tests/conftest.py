import os

os.environ.setdefault("JWT_SECRET", "test-secret-not-for-production-use-0123456789")
os.environ.setdefault("JWT_AUDIENCE", "helpdeskai-api")
os.environ.setdefault("JWT_ISSUER", "helpdeskai-auth")
