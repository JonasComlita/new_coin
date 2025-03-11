# main.py
import os
import argparse
from flask import Flask
from dotenv import load_dotenv
import uuid

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Secure Key Rotation Service')
    parser.add_argument('--node-id', help='Unique node identifier')
    parser.add_argument('--validator', action='store_true', help='Run as validator node')
    parser.add_argument('--port', type=int, default=5000, help='API server port')
    parser.add_argument('--host', default='0.0.0.0', help='API server host')
    args = parser.parse_args()
    
    # Load environment variables
    load_dotenv()
    
    # Generate node ID if not provided
    node_id = args.node_id or os.getenv('NODE_ID') or str(uuid.uuid4())
    
    # Determine if this is a validator node
    is_validator = args.validator or (os.getenv('IS_VALIDATOR', 'false').lower() == 'true')
    
    # Initialize the key rotation manager
    from core import KeyRotationManager
    rotation_manager = KeyRotationManager(
        node_id=node_id,
        is_validator=is_validator
    )
    
    # Create a Flask app
    app = Flask(__name__)
    
    # Create API endpoints
    from api import create_rotation_api
    create_rotation_api(app, rotation_manager)
    
    # Start the API server
    app.run(host=args.host, port=args.port)

if __name__ == '__main__':
    main()