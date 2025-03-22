"""
Configuration settings for the C2 framework
"""
import os

# Server settings
SERVER_HOST = os.environ.get("C2_SERVER_HOST", "0.0.0.0")
SERVER_PORT = int(os.environ.get("C2_SERVER_PORT", "443"))
SSL_CERT = os.environ.get("C2_SSL_CERT", "cert.pem")
SSL_KEY = os.environ.get("C2_SSL_KEY", "key.pem")

# Client settings
AGENT_SLEEP_MIN = int(os.environ.get("C2_AGENT_SLEEP_MIN", "3"))
AGENT_SLEEP_MAX = int(os.environ.get("C2_AGENT_SLEEP_MAX", "7"))
COMMAND_TIMEOUT = int(os.environ.get("C2_COMMAND_TIMEOUT", "30"))

# Security settings
USE_HTTPS = os.environ.get("C2_USE_HTTPS", "True").lower() == "true"
COOKIE_SECURE = os.environ.get("C2_COOKIE_SECURE", "True").lower() == "true"
COOKIE_HTTPONLY = True
COOKIE_SAMESITE = os.environ.get("C2_COOKIE_SAMESITE", "Strict")

# C2 server address
C2_SERVER = os.environ.get("C2_SERVER_URL", "https://127.0.0.1:443")

# Logging settings
LOG_LEVEL = os.environ.get("C2_LOG_LEVEL", "INFO")
LOG_FORMAT = os.environ.get("C2_LOG_FORMAT", '%(asctime)s [%(levelname)s] %(message)s')

# Shared secret for authentication
SHARED_SECRET = os.environ.get("C2_SHARED_SECRET", "uacneQWE1AKfjf")