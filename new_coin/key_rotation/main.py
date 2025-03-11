import os
from flask import Flask
from dotenv import load_dotenv
import uuid

def main(node_id=None, is_validator=False, port=5000, host="0.0.0.0"):
    # Load environment variables
    load_dotenv()
    
    # Use provided node_id or generate one
    node_id = node_id or os.getenv("NODE_ID") or str(uuid.uuid4())
    
    # Determine validator status
    is_validator = is_validator or (os.getenv("IS_VALIDATOR", "false").lower() == "true")
    
    # Initialize the key rotation manager
    from .core import KeyRotationManager
    rotation_manager = KeyRotationManager(node_id=node_id, is_validator=is_validator)
    
    # Create a Flask app
    app = Flask(__name__)
    
    # Create API endpoints
    from .api import create_rotation_api
    create_rotation_api(app, rotation_manager)
    
    # Start the API server
    app.run(host=host, port=port)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Secure Key Rotation Service")
    parser.add_argument("--node-id", help="Unique node identifier")
    parser.add_argument("--validator", action="store_true", help="Run as validator node")
    parser.add_argument("--port", type=int, default=5000, help="API server port")
    parser.add_argument("--host", default="0.0.0.0", help="API server host")
    args = parser.parse_args()
    main(args.node_id, args.validator, args.port, args.host)