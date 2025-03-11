# api.py
from flask import Flask, request, jsonify
from functools import wraps
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_rotation_api(app, rotation_manager):
    """
    Create API endpoints for the key rotation system.
    This integrates with a Flask application.
    """
    # Add error handler for all uncaught exceptions
    @app.errorhandler(Exception)
    def handle_exception(e):
        import traceback
        logger.error(f"Unhandled exception: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": "Internal server error", "message": str(e)}), 500
    
    def require_auth(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return jsonify({"error": "Missing Authorization header"}), 401
            
            parts = auth_header.split(' ')
            if len(parts) != 2 or parts[0].lower() != 'bearer':
                return jsonify({"error": "Invalid Authorization header format"}), 401
            
            token = parts[1]
            if not rotation_manager.authenticate_peer(token):
                return jsonify({"error": "Authentication failed"}), 401
            
            return f(*args, **kwargs)
        return decorated
    
    @app.route('/api/v1/node/info', methods=['GET'])
    def get_node_info():
        """Endpoint to get this node's info."""
        return jsonify({
            "node_id": rotation_manager.node_id,
            "is_validator": rotation_manager.is_validator,
            "certificate": rotation_manager.pki.get_certificate_pem(),
            "public_key": rotation_manager.pki.get_public_key_pem()
        })
    
    @app.route('/api/v1/nodes/register', methods=['POST'])
    @require_auth
    def register_node():
        """Endpoint to register a new node."""
        data = request.json
        if not data or not all(k in data for k in ['node_id', 'node_url', 'public_key', 'certificate']):
            return jsonify({"error": "Missing required fields"}), 400
        
        success = rotation_manager.node_registry.register_node(
            data['node_id'],
            data['node_url'],
            data['public_key'],
            data['certificate']
        )
        
        if success:
            return jsonify({"status": "success"}), 200
        else:
            return jsonify({"error": "Failed to register node"}), 500
    
    @app.route('/api/v1/nodes', methods=['GET'])
    @require_auth
    def get_nodes():
        """Endpoint to get all registered nodes."""
        return jsonify({
            "nodes": rotation_manager.node_registry.get_all_nodes()
        })
    
    @app.route('/api/v1/rotation/proposals', methods=['GET'])
    @require_auth
    def get_proposals():
        """Endpoint to get active key rotation proposals."""
        proposals = rotation_manager.consensus.get_active_proposals()
        return jsonify({"proposals": proposals})
    
    @app.route('/api/v1/rotation/propose', methods=['POST'])
    @require_auth
    def propose_rotation():
        """Endpoint to propose a new key rotation."""
        try:
            logger.info("Received propose_rotation request")
            if not rotation_manager.is_validator:
                logger.error("Node is not a validator")
                return jsonify({"error": "Only validators can propose rotations"}), 403
            
            # Generate a new key and create a proposal
            logger.info("Generating new secret key")
            new_key = rotation_manager._generate_secure_secret()
            key_hash = rotation_manager._hash_secret(new_key)
            
            # Store the pending key
            logger.info("Storing pending secret")
            rotation_manager.pending_auth_secret = new_key
            rotation_manager.secure_storage.store("pending_auth_secret", new_key)
            
            # Create the proposal
            logger.info("Creating consensus proposal")
            proposal_id = rotation_manager.consensus.create_proposal(key_hash)
            
            if proposal_id:
                # Store the proposal ID
                logger.info(f"Proposal created successfully: {proposal_id}")
                rotation_manager.pending_proposal_id = proposal_id
                rotation_manager.secure_storage.store("pending_proposal_id", proposal_id)
                
                # Broadcast the proposal
                logger.info(f"Broadcasting proposal {proposal_id}")
                broadcast_result = rotation_manager.p2p.broadcast_proposal(proposal_id)
                logger.info(f"Broadcast result: {broadcast_result}")
                
                return jsonify({
                    "status": "success",
                    "proposal_id": proposal_id
                })
            else:
                logger.error("Failed to create proposal")
                return jsonify({"error": "Failed to create proposal"}), 500
        except Exception as e:
            import traceback
            logger.error(f"Exception in propose_rotation: {str(e)}")
            logger.error(traceback.format_exc())
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    
    @app.route('/api/v1/rotation/vote', methods=['POST'])
    @require_auth
    def vote_on_rotation():
        """Endpoint to vote on a key rotation proposal."""
        data = request.json
        if not data or 'proposal_id' not in data or 'approve' not in data:
            return jsonify({"error": "Missing required fields"}), 400
        
        if not rotation_manager.is_validator:
            return jsonify({"error": "Only validators can vote"}), 403
        
        proposal_id = data['proposal_id']
        approve = data['approve']
        
        # Record the vote
        success = rotation_manager.consensus.vote_on_proposal(proposal_id, approve)
        
        if success:
            # Broadcast the vote
            rotation_manager.p2p.broadcast_vote(proposal_id, approve)
            
            return jsonify({"status": "success"})
        else:
            return jsonify({"error": "Failed to record vote"}), 500
    
    @app.route('/api/v1/rotation/status/<proposal_id>', methods=['GET'])
    @require_auth
    def get_proposal_status(proposal_id):
        """Endpoint to get the status of a specific proposal."""
        status = rotation_manager.consensus.check_proposal_status(proposal_id)
        
        if "error" in status:
            return jsonify({"error": status["error"]}), 404
        
        return jsonify(status)
    
    @app.route('/api/v1/rotation/finalize', methods=['POST'])
    @require_auth
    def finalize_rotation():
        """Endpoint to finalize an approved key rotation."""
        data = request.json
        if not data or 'proposal_id' not in data:
            return jsonify({"error": "Missing proposal_id"}), 400
        
        proposal_id = data['proposal_id']
        
        # Finalize the proposal
        success, key_hash = rotation_manager.consensus.finalize_proposal(proposal_id)
        
        if success:
            # Apply the rotation if it's our proposal
            if proposal_id == rotation_manager.pending_proposal_id:
                rotation_manager._apply_key_rotation()
                
                # Distribute the key to other nodes
                rotation_manager._distribute_finalized_key()
            
            return jsonify({
                "status": "success",
                "key_hash": key_hash
            })
        else:
            return jsonify({"error": "Failed to finalize proposal"}), 500
    
    @app.route('/api/v1/p2p/message', methods=['POST'])
    def receive_p2p_message():
        """Endpoint to receive P2P messages from other nodes."""
        data = request.json
        if not data or 'message' not in data or 'signature' not in data:
            return jsonify({"error": "Invalid message format"}), 400
        
        message = data['message']
        signature = data['signature']
        
        if 'sender' not in message:
            return jsonify({"error": "Invalid message: missing sender"}), 400
        
        sender_id = message['sender']
        
        # Process the message
        success = rotation_manager.p2p.process_message(message, signature, sender_id)
        
        if success:
            return jsonify({"status": "success"})
        else:
            return jsonify({"error": "Failed to process message"}), 400
    
    @app.route('/api/v1/rotation/receive-key', methods=['POST'])
    def receive_key():
        """Endpoint to receive a new encrypted key."""
        data = request.json
        if not data or 'encrypted_key' not in data:
            return jsonify({"error": "Missing encrypted_key"}), 400
        
        # Apply the received key
        success = rotation_manager.receive_key(data['encrypted_key'])
        
        if success:
            logger.info("Rotation API endpoints registered successfully")
            return jsonify({"status": "success"})
        else:
            return jsonify({"error": "Failed to process received key"}), 500
        
    # Add to api.py
    @app.route('/api/v1/auth/secret', methods=['GET'])
    @require_auth
    def get_auth_secret():
        """Endpoint to get the current auth secret."""
        return jsonify({
            "secret": rotation_manager.get_current_auth_secret()
        })

    @app.route('/api/v1/auth/validate', methods=['POST'])
    def validate_auth():
        """Endpoint to validate an auth token."""
        data = request.json
        if not data or 'token' not in data:
            return jsonify({"error": "Missing token"}), 400
        
        if rotation_manager.authenticate_peer(data['token']):
            return jsonify({"status": "valid"}), 200
        else:
            return jsonify({"status": "invalid"}), 401
        
    # Add this function to the API to check registered nodes
    @app.route('/api/v1/nodes/debug', methods=['GET'])
    def debug_nodes():
        """Endpoint to get debugging info about registered nodes."""
        nodes = rotation_manager.node_registry.get_all_nodes()
        active_nodes = rotation_manager.node_registry.get_active_nodes()
        return jsonify({
            "total_nodes": len(nodes),
            "active_nodes": len(active_nodes),
            "nodes": {node_id: {"url": data.get("url"), "last_seen": data.get("last_seen")} for node_id, data in nodes.items()},
            "active": {node_id: {"url": data.get("url"), "last_seen": data.get("last_seen")} for node_id, data in active_nodes.items()}
        })