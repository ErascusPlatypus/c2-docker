"""
Configuration settings for the C2 framework
"""

# Server settings
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 443
SSL_CERT = "cert.pem"
SSL_KEY = "key.pem"

# Client settings
AGENT_SLEEP_MIN = 3  # Minimum sleep time in seconds
AGENT_SLEEP_MAX = 7  # Maximum sleep time in seconds
COMMAND_TIMEOUT = 30  # Command execution timeout in seconds

# Security settings
USE_HTTPS = True
COOKIE_SECURE = True
COOKIE_HTTPONLY = True
COOKIE_SAMESITE = "Strict"

# C2 server address to be updated in production
C2_SERVER = "https://C2_IP"  # Use actual IP/domain in production

# Logging settings
LOG_LEVEL = "INFO"
LOG_FORMAT = '%(asctime)s [%(levelname)s] %(message)s'