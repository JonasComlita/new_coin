import os
from flask import Flask
from dotenv import load_dotenv
import uuid
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('main')  # Create a logger for main.py

def main(node_id=None, is_validator=False, port=5000, host="0.0.0.0"):
    load_dotenv()
    node_id = node_id or os.getenv("NODE_ID") or str(uuid.uuid4())
    is_validator = is_validator or (os.getenv("IS_VALIDATOR", "false").lower() == "true")
    
    logger.info(f"Starting main with node_id: {node_id}, is_validator: {is_validator}, port: {port}")
    
    from key_rotation.core import KeyRotationManager
    try:
        rotation_manager = KeyRotationManager(node_id=node_id, is_validator=is_validator)
        logger.info(f"KeyRotationManager initialized successfully for {node_id}")
    except Exception as e:
        import traceback
        logger.error(f"Failed to initialize KeyRotationManager: {e}")
        logger.error(traceback.format_exc())
        raise
    
    app = Flask(__name__)
    logger.info("Flask app created")
    
    try:
        from key_rotation.api import create_rotation_api
        logger.info("Imported create_rotation_api")
        create_rotation_api(app, rotation_manager)
        logger.info("create_rotation_api executed")
    except Exception as e:
        import traceback
        logger.error(f"Failed to import or execute create_rotation_api: {e}")
        logger.error(traceback.format_exc())
        raise
    
    if port == 5000:
        cert_path = Path("C:/blockchain-ca/certs/node5000.pem")
        key_path = Path("C:/blockchain-ca/private/node5000.key")
    elif port == 5001:
        cert_path = Path("C:/blockchain-ca/certs/node5001.pem")
        key_path = Path("C:/blockchain-ca/private/node5001.key")
    else:
        cert_path = Path(os.getcwd()) / "cert.pem"
        key_path = Path(os.getcwd()) / "key.pem"
    
    if cert_path.exists() and key_path.exists():
        logger.info(f"Starting HTTPS server on {host}:{port}")
        app.run(host=host, port=port, ssl_context=(str(cert_path), str(key_path)))
    else:
        logger.info(f"Starting HTTP server on {host}:{port}")
        app.run(host=host, port=port)