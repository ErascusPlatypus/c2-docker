"""
Entry point for the C2 server
"""
import logging
from flask import Flask
from srvr.routes import register_routes
from config.settings import SERVER_HOST, SERVER_PORT, SSL_CERT, SSL_KEY, LOG_LEVEL, LOG_FORMAT

def create_app():
    """Create and configure the Flask application"""
    app = Flask(__name__)
    
    # Configure logging
    logging.basicConfig(level=getattr(logging, LOG_LEVEL), format=LOG_FORMAT)
    
    # Register routes
    register_routes(app)
    
    return app

if __name__ == '__main__':
    app = create_app()
    
    # Configure SSL context
    ssl_context = (SSL_CERT, SSL_KEY)
    
    # Run the server
    logging.info(f"Starting C2 server on {SERVER_HOST}:{SERVER_PORT}")
    app.run(
        host=SERVER_HOST,
        port=SERVER_PORT,
        ssl_context=ssl_context,
        debug=False  # Set to True during development
    )