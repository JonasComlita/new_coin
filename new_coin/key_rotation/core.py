# key_rotation/

# core.py
import os
import time
import json
import uuid
import base64
import hashlib
import logging
import threading
import schedule
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.x509.extensions import SubjectAlternativeName, DNSName, IPAddress
import requests
import socket
import ssl
import urllib3
# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('key_rotation')

# Constants
KEY_ROTATION_INTERVAL_DAYS = 30
CERT_VALIDITY_DAYS = 365
VOTE_THRESHOLD_PERCENT = 66  # 66% of nodes must approve for key rotation
VOTE_TIMEOUT_HOURS = 48
CONFIG_DIR = Path.home() / '.blockchain' / 'secure_config'

class SecureStorage:
    """Secure storage for keys using local encrypted storage."""
    
    def __init__(self):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        self.storage_path = CONFIG_DIR / 'secure_store.enc'
        self.storage_data = {}
        
        # Initialize encryption key
        self.master_key_path = CONFIG_DIR / 'master.key'
        if not self.master_key_path.exists():
            self._generate_master_key()
        else:
            with open(self.master_key_path, 'rb') as f:
                self.master_key = f.read()
        
        self.fernet = Fernet(self.master_key)
        
        # Load existing storage if it exists
        if self.storage_path.exists():
            self._load_storage()
    
    def _generate_master_key(self):
        """Generate a secure master key for local encryption."""
        # Generate a strong random password
        password = os.urandom(32)
        salt = os.urandom(16)
        
        # Derive a key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        self.master_key = base64.urlsafe_b64encode(kdf.derive(password))
        
        # Save the key and salt
        with open(self.master_key_path, 'wb') as f:
            f.write(self.master_key)
        os.chmod(self.master_key_path, 0o600)  # Restrict permissions
            
        salt_path = CONFIG_DIR / 'salt.bin'
        with open(salt_path, 'wb') as f:
            f.write(salt)
        os.chmod(salt_path, 0o600)  # Restrict permissions
            
        logger.info("Generated new master encryption key")
    
    def _load_storage(self):
        """Load the encrypted storage from disk."""
        try:
            with open(self.storage_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt the data
            decrypted_data = self.fernet.decrypt(encrypted_data)
            self.storage_data = json.loads(decrypted_data.decode('utf-8'))
        except Exception as e:
            logger.error(f"Failed to load secure storage: {e}")
            self.storage_data = {}
    
    def _save_storage(self):
        """Save the encrypted storage to disk."""
        try:
            # Encrypt the data
            encrypted_data = self.fernet.encrypt(json.dumps(self.storage_data).encode('utf-8'))
            
            # Save to disk with secure permissions
            with open(self.storage_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Set secure permissions
            os.chmod(self.storage_path, 0o600)
        except Exception as e:
            logger.error(f"Failed to save secure storage: {e}")
    
    def store(self, key: str, value: str, namespace: str = 'default'):
        """Store a value securely."""
        if namespace not in self.storage_data:
            self.storage_data[namespace] = {}
        self.storage_data[namespace][key] = value
        self._save_storage()
    
    def retrieve(self, key: str, namespace: str = 'default') -> Optional[str]:
        """Retrieve a value from secure storage."""
        try:
            return self.storage_data.get(namespace, {}).get(key)
        except Exception as e:
            logger.error(f"Failed to retrieve value for {key}: {e}")
            return None
    
    def delete(self, key: str, namespace: str = 'default'):
        """Delete a value from secure storage."""
        if namespace in self.storage_data and key in self.storage_data[namespace]:
            del self.storage_data[namespace][key]
            self._save_storage()
    
    def list_keys(self, namespace: str = 'default') -> List[str]:
        """List all keys in a namespace."""
        return list(self.storage_data.get(namespace, {}).keys())


class PKIManager:
    """Manages PKI certificates and keys for secure node communication."""
    
    def __init__(self, node_id: str):
        self.node_id = node_id
        self.cert_dir = CONFIG_DIR / 'certs'
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        
        # Check if we have keys and certificates
        self.private_key_path = self.cert_dir / f"{node_id}_private.pem"
        self.public_key_path = self.cert_dir / f"{node_id}_public.pem"
        self.cert_path = self.cert_dir / f"{node_id}_cert.pem"
        
        if not self.private_key_path.exists() or not self.cert_path.exists():
            self._generate_keys_and_cert()
    
    def _generate_keys_and_cert(self):
        """Generate RSA key pair and certificate with improved SAN support."""
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Extract public key
        public_key = private_key.public_key()
        
        # Prepare subject and issuer information
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Blockchain Network"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"node-{self.node_id}")
        ])
        
        # Prepare Subject Alternative Names
        san_entries = [
            x509.DNSName('localhost'),
            x509.DNSName(socket.getfqdn()),
            x509.IPAddress(ipaddress.IPv4Address('127.0.0.1')),
            x509.IPAddress(ipaddress.IPv4Address('::1'))  # IPv6 localhost
        ]
        
        # Try to get the node's hostname and IP
        try:
            import socket
            hostname = socket.gethostname()
            san_entries.append(x509.DNSName(hostname))
            
            # Get IP addresses
            ips = socket.gethostbyname_ex(hostname)[2]
            for ip in ips:
                try:
                    san_entries.append(x509.IPAddress(ipaddress.IPv4Address(ip)))
                except ValueError:
                    pass
        except Exception as e:
            logger.warning(f"Could not retrieve hostname/IPs: {e}")
        
        # Check if CA certificate exists
        ca_cert_path = Path.home() / 'blockchain-ca' / 'certs' / 'ca.pem'
        ca_key_path = Path.home() / 'blockchain-ca' / 'private' / 'ca.key'
        
        # Prepare certificate builder
        cert_builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=CERT_VALIDITY_DAYS)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        ).add_extension(
            x509.SubjectAlternativeName(san_entries), 
            critical=False
        )
        
        # Try to use CA certificate for signing
        try:
            if ca_cert_path.exists() and ca_key_path.exists():
                with open(ca_cert_path, "rb") as f:
                    ca_cert = x509.load_pem_x509_certificate(f.read())
                
                with open(ca_key_path, "rb") as f:
                    ca_key = serialization.load_pem_private_key(f.read(), password=None)
                
                # Sign with CA
                cert = cert_builder.sign(ca_key, hashes.SHA256())
                logger.info(f"Generated CA-signed certificate for node {self.node_id}")
            else:
                raise FileNotFoundError("CA certificate or key not found")
        except Exception as e:
            logger.warning(f"CA signing failed: {e}. Falling back to self-signed.")
            
            # Self-signed certificate
            cert = cert_builder.sign(private_key, hashes.SHA256())
            logger.info(f"Generated self-signed certificate for node {self.node_id}")
        
        # Save private key
        with open(self.private_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        os.chmod(self.private_key_path, 0o600)
        
        # Save public key
        with open(self.public_key_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        
        # Save certificate
        with open(self.cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    def encrypt_message(self, message: str, public_key_pem: str) -> str:
        """Encrypt a message using the recipient's public key."""
        try:
            # Load recipient's public key
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8')
            )
            
            # Encrypt the message
            encrypted = public_key.encrypt(
                message.encode('utf-8'),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Return base64-encoded encrypted message
            return base64.b64encode(encrypted).decode('utf-8')
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise
    
    def decrypt_message(self, encrypted_message: str) -> str:
        """Decrypt a message using this node's private key."""
        try:
            # Load our private key
            with open(self.private_key_path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None
                )
            
            # Decode and decrypt the message
            decoded = base64.b64decode(encrypted_message)
            decrypted = private_key.decrypt(
                decoded,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Return decrypted message
            return decrypted.decode('utf-8')
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise
    
    def sign_message(self, message: str) -> str:
        """Sign a message using this node's private key."""
        try:
            # Load our private key
            with open(self.private_key_path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None
                )
            
            # Sign the message
            signature = private_key.sign(
                message.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Return base64-encoded signature
            return base64.b64encode(signature).decode('utf-8')
        except Exception as e:
            logger.error(f"Signing failed: {e}")
            raise
    
    def verify_signature(self, message: str, signature: str, public_key_pem: str) -> bool:
        """Verify a signature using the sender's public key."""
        try:
            # Load sender's public key
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8')
            )
            
            # Decode the signature
            decoded_signature = base64.b64decode(signature)
            
            # Verify the signature
            public_key.verify(
                decoded_signature,
                message.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # If we get here, verification succeeded
            return True
        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False
    
    def get_public_key_pem(self) -> str:
        """Get this node's public key in PEM format."""
        with open(self.public_key_path, "rb") as f:
            return f.read().decode('utf-8')
    
    def get_certificate_pem(self) -> str:
        """Get this node's certificate in PEM format."""
        with open(self.cert_path, "rb") as f:
            return f.read().decode('utf-8')


class NodeRegistry:
    def __init__(self):
        self.registry_path = CONFIG_DIR / 'node_registry.json'
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)  # Ensure dir exists
        self.nodes = {}
        self._load_registry()
    
    def _load_registry(self):
        if self.registry_path.exists():
            try:
                with open(self.registry_path, 'r') as f:
                    self.nodes = json.load(f)
            except Exception as e:
                logger.error(f"Failed to load node registry: {e}")
                self.nodes = {}
        else:
            self._save_registry()  # Create empty file if missing
    
    def _save_registry(self):
        """Save the node registry to disk."""
        try:
            with open(self.registry_path, 'w') as f:
                json.dump(self.nodes, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save node registry: {e}")
    
    def register_node(self, node_id: str, node_url: str, public_key: str, certificate: str) -> bool:
        """Register a new node or update an existing one."""
        self.nodes[node_id] = {
            "url": node_url,
            "public_key": public_key,
            "certificate": certificate,
            "last_seen": datetime.now().isoformat(),
        }
        self._save_registry()
        return True
    
    def get_node(self, node_id: str) -> Optional[Dict]:
        """Get information about a registered node."""
        return self.nodes.get(node_id)
    
    def get_node_public_key(self, node_id: str) -> Optional[str]:
        """Get the public key of a registered node."""
        node = self.get_node(node_id)
        if node:
            return node.get("public_key")
        return None
    
    def get_all_nodes(self) -> Dict[str, Dict]:
        """Get all registered nodes."""
        return self.nodes
    
    def get_active_nodes(self) -> Dict[str, Dict]:
        """Get all active nodes (seen in the last 24 hours)."""
        active_nodes = {}
        now = datetime.utcnow()
        for node_id, node_data in self.nodes.items():
            last_seen = datetime.fromisoformat(node_data["last_seen"])
            if (now - last_seen).total_seconds() < 86400:  # 24 hours
                active_nodes[node_id] = node_data
        return active_nodes
    
    def update_node_last_seen(self, node_id: str):
        """Update the last seen timestamp for a node."""
        if node_id in self.nodes:
            self.nodes[node_id]["last_seen"] = datetime.utcnow().isoformat()
            self._save_registry()


class ConsensusManager:
    """Manages consensus for key rotation without relying on a blockchain."""
    
    def __init__(self, node_id: str, node_registry: NodeRegistry, pki: PKIManager):
        self.node_id = node_id
        self.node_registry = node_registry
        self.pki = pki
        self.proposals_dir = CONFIG_DIR / 'proposals'
        self.proposals_dir.mkdir(parents=True, exist_ok=True)
        self.active_proposals = {}
        self._load_active_proposals()

        # Log initialization details
        logger.info(f"ConsensusManager initialized with node_id: {self.node_id}")
        logger.info(f"Active nodes at startup: {len(self.node_registry.get_active_nodes())}")
        for nid, node_data in self.node_registry.get_active_nodes().items():
            logger.info(f"  - Node {nid}: {node_data.get('url')}, last seen: {node_data.get('last_seen')}")
    
    
    def _load_active_proposals(self):
        """Load active proposals from disk."""
        for proposal_file in self.proposals_dir.glob('*.json'):
            try:
                with open(proposal_file, 'r') as f:
                    proposal = json.load(f)
                    if not proposal.get('finalized', False):
                        proposal_id = proposal.get('id')
                        if proposal_id:
                            self.active_proposals[proposal_id] = proposal
            except Exception as e:
                logger.error(f"Failed to load proposal {proposal_file}: {e}")
    
    def _save_proposal(self, proposal_id: str, proposal_data: Dict):
        """Save a proposal to disk."""
        try:
            with open(self.proposals_dir / f"{proposal_id}.json", 'w') as f:
                json.dump(proposal_data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save proposal {proposal_id}: {e}")
    
    def create_proposal(self, key_hash: str) -> Optional[str]:
        """Create a new key rotation proposal."""
        try:
            # Generate a unique proposal ID
            proposal_id = str(uuid.uuid4())
            
            # Create a signature of the key hash
            signature = self.pki.sign_message(key_hash)
            
            # Create the proposal
            proposal = {
                "id": proposal_id,
                "type": "key_rotation",
                "key_hash": key_hash,
                "proposer": self.node_id,
                "proposer_signature": signature,
                "timestamp": datetime.utcnow().isoformat(),
                "expiration": (datetime.utcnow() + timedelta(hours=VOTE_TIMEOUT_HOURS)).isoformat(),
                "votes": {
                    self.node_id: {
                        "approved": True,
                        "timestamp": datetime.utcnow().isoformat(),
                        "signature": signature
                    }
                },
                "finalized": False
            }
            
            # Save the proposal
            self._save_proposal(proposal_id, proposal)
            
            # Add to active proposals
            self.active_proposals[proposal_id] = proposal
            
            return proposal_id
        except Exception as e:
            logger.error(f"Failed to create proposal: {e}")
            return None
    
    def vote_on_proposal(self, proposal_id: str, approve: bool) -> bool:
        """Vote on a key rotation proposal."""
        try:
            # Get the proposal
            proposal = self.active_proposals.get(proposal_id)
            if not proposal:
                logger.error(f"Proposal {proposal_id} not found")
                return False
            
            # Check if already voted
            if self.node_id in proposal.get('votes', {}):
                logger.warning(f"Already voted on proposal {proposal_id}")
                return False
            
            # Check if proposal has expired
            expiration = datetime.fromisoformat(proposal['expiration'])
            if datetime.utcnow() > expiration:
                logger.error(f"Proposal {proposal_id} has expired")
                return False
            
            # Create a signature
            signature = self.pki.sign_message(f"{proposal_id}:{approve}")
            
            # Record the vote
            if 'votes' not in proposal:
                proposal['votes'] = {}
                
            proposal['votes'][self.node_id] = {
                "approved": approve,
                "timestamp": datetime.utcnow().isoformat(),
                "signature": signature
            }
            
            # Save the updated proposal
            self._save_proposal(proposal_id, proposal)
            
            # Update active proposals
            self.active_proposals[proposal_id] = proposal
            
            return True
        except Exception as e:
            logger.error(f"Failed to vote on proposal {proposal_id}: {e}")
            return False
    
    def check_proposal_status(self, proposal_id: str) -> Dict:
        """Check the status of a proposal."""
        try:
            proposal = self.active_proposals.get(proposal_id)
            if not proposal:
                # Try to load from disk
                proposal_path = self.proposals_dir / f"{proposal_id}.json"
                if proposal_path.exists():
                    with open(proposal_path, 'r') as f:
                        proposal = json.load(f)
                else:
                    return {"error": "Proposal not found"}
            
            # Count votes
            approval_count = 0
            total_votes = 0
            
            for vote_data in proposal.get('votes', {}).values():
                total_votes += 1
                if vote_data.get('approved', False):
                    approval_count += 1
            
            # Get active nodes count
            active_nodes = self.node_registry.get_active_nodes()
            active_count = len(active_nodes)
            
            # Calculate approval percentage
            approval_percentage = 0
            if total_votes > 0:
                approval_percentage = (approval_count / total_votes) * 100
            
            # Check if proposal has reached threshold
            threshold_reached = False
            if active_count > 0:
                threshold_reached = (approval_count / active_count) * 100 >= VOTE_THRESHOLD_PERCENT
            
            # Check if proposal has expired
            expired = False
            if 'expiration' in proposal:
                expiration = datetime.fromisoformat(proposal['expiration'])
                expired = datetime.utcnow() > expiration
            
            return {
                "id": proposal_id,
                "type": proposal.get('type'),
                "key_hash": proposal.get('key_hash'),
                "proposer": proposal.get('proposer'),
                "timestamp": proposal.get('timestamp'),
                "expiration": proposal.get('expiration'),
                "total_votes": total_votes,
                "approval_count": approval_count,
                "approval_percentage": approval_percentage,
                "active_nodes": active_count,
                "threshold_reached": threshold_reached,
                "expired": expired,
                "finalized": proposal.get('finalized', False)
            }
        except Exception as e:
            logger.error(f"Failed to check proposal status {proposal_id}: {e}")
            return {"error": str(e)}
    
    def finalize_proposal(self, proposal_id: str) -> Tuple[bool, Optional[str]]:
        """
        Finalize an approved proposal.
        Returns (success, key_hash) tuple.
        """
        try:
            # Check proposal status
            status = self.check_proposal_status(proposal_id)
            
            # Ensure proposal exists
            if 'error' in status:
                return False, None
            
            # Check if proposal is already finalized
            if status.get('finalized', False):
                return False, status.get('key_hash')
            
            # Check if proposal has reached threshold and not expired
            if not status.get('threshold_reached', False):
                logger.error(f"Proposal {proposal_id} has not reached threshold")
                return False, None
            
            if status.get('expired', True):
                logger.error(f"Proposal {proposal_id} has expired")
                return False, None
            
            # Get the proposal
            proposal = self.active_proposals.get(proposal_id)
            if not proposal:
                logger.error(f"Proposal {proposal_id} not found")
                return False, None
            
            # Mark as finalized
            proposal['finalized'] = True
            proposal['finalized_timestamp'] = datetime.utcnow().isoformat()
            
            # Save the updated proposal
            self._save_proposal(proposal_id, proposal)
            
            # Remove from active proposals
            if proposal_id in self.active_proposals:
                del self.active_proposals[proposal_id]
            
            return True, proposal.get('key_hash')
        except Exception as e:
            logger.error(f"Failed to finalize proposal {proposal_id}: {e}")
            return False, None
    
    def get_active_proposals(self) -> List[Dict]:
        """Get all active proposals."""
        active_list = []
        for proposal_id, proposal in self.active_proposals.items():
            status = self.check_proposal_status(proposal_id)
            if not status.get('finalized', False) and not status.get('expired', True):
                active_list.append(status)
        return active_list
    
    def cleanup_expired_proposals(self):
        """Clean up expired proposals."""
        to_remove = []
        for proposal_id, proposal in self.active_proposals.items():
            status = self.check_proposal_status(proposal_id)
            if status.get('expired', False) and not status.get('finalized', False):
                proposal['expired'] = True
                self._save_proposal(proposal_id, proposal)
                to_remove.append(proposal_id)
        
        for proposal_id in to_remove:
            if proposal_id in self.active_proposals:
                del self.active_proposals[proposal_id]

class P2PNetwork:
    """Simple P2P network for distributing key rotation information."""
    
    def __init__(self, node_id: str, node_registry: NodeRegistry, pki: PKIManager, consensus: ConsensusManager):
        self.node_id = node_id
        self.node_registry = node_registry
        self.pki = pki
        self.consensus = consensus
        self.message_cache = set()  # Track processed message IDs
    
    def broadcast_proposal(self, proposal_id: str) -> bool:
        """Broadcast a new proposal to all nodes."""
        try:
            # Get proposal data
            proposal_status = self.consensus.check_proposal_status(proposal_id)
            if 'error' in proposal_status:
                return False
            
            # Prepare the message
            message = {
                "type": "new_proposal",
                "proposal_id": proposal_id,
                "sender": self.node_id,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Sign the message
            message_str = json.dumps(message, sort_keys=True)
            signature = self.pki.sign_message(message_str)
            
            payload = {
                "message": message,
                "signature": signature
            }
            
            # Send to all nodes
            return self._send_to_all_nodes("/api/v1/p2p/message", payload)
        except Exception as e:
            logger.error(f"Failed to broadcast proposal {proposal_id}: {e}")
            return False
    
    def broadcast_vote(self, proposal_id: str, approved: bool) -> bool:
        """Broadcast a vote to all nodes."""
        try:
            # Prepare the message
            message = {
                "type": "vote",
                "proposal_id": proposal_id,
                "approved": approved,
                "sender": self.node_id,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Sign the message
            message_str = json.dumps(message, sort_keys=True)
            signature = self.pki.sign_message(message_str)
            
            payload = {
                "message": message,
                "signature": signature
            }
            
            # Send to all nodes
            return self._send_to_all_nodes("/api/v1/p2p/message", payload)
        except Exception as e:
            logger.error(f"Failed to broadcast vote for proposal {proposal_id}: {e}")
            return False
    
    def broadcast_finalized_key(self, proposal_id: str, key_hash: str, encrypted_key_data: Dict) -> bool:
        """Broadcast a finalized key to all nodes."""
        try:
            # Prepare the message
            message = {
                "type": "finalized_key",
                "proposal_id": proposal_id,
                "key_hash": key_hash,
                "encrypted_keys": encrypted_key_data,
                "sender": self.node_id,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Sign the message
            message_str = json.dumps(message, sort_keys=True)
            signature = self.pki.sign_message(message_str)
            
            payload = {
                "message": message,
                "signature": signature
            }
            
            # Send to all nodes
            return self._send_to_all_nodes("/api/v1/p2p/message", payload)
        except Exception as e:
            logger.error(f"Failed to broadcast finalized key for proposal {proposal_id}: {e}")
            return False
    
    def process_message(self, message: Dict, signature: str, sender_id: str) -> bool:
        """Process a received P2P message."""
        try:
            # Get sender's public key
            sender_public_key = self.node_registry.get_node_public_key(sender_id)
            if not sender_public_key:
                logger.error(f"Unknown sender node {sender_id}")
                return False
            
            # Verify the signature
            message_str = json.dumps(message, sort_keys=True)
            if not self.pki.verify_signature(message_str, signature, sender_public_key):
                logger.error(f"Invalid signature on message from {sender_id}")
                return False
            
            # Check for duplicate messages
            message_id = hashlib.sha256(message_str.encode()).hexdigest()
            if message_id in self.message_cache:
                logger.debug(f"Ignoring duplicate message {message_id}")
                return True
            
            # Add to message cache
            self.message_cache.add(message_id)
            if len(self.message_cache) > 1000:  # Limit cache size
                self.message_cache.pop()
            
            # Update last seen time for the sender
            self.node_registry.update_node_last_seen(sender_id)
            
            # Process based on message type
            message_type = message.get('type')
            
            if message_type == 'new_proposal':
                # A new proposal was created
                proposal_id = message.get('proposal_id')
                if proposal_id:
                    # Sync the proposal data
                    # In a real implementation, you would request the full proposal data
                    logger.info(f"Received new proposal notification: {proposal_id}")
                    return True
            
            elif message_type == 'vote':
                # A node voted on a proposal
                proposal_id = message.get('proposal_id')
                approved = message.get('approved', False)
                
                # Record the vote
                if proposal_id:
                    self.consensus.vote_on_proposal(proposal_id, approved)
                    logger.info(f"Received vote from {sender_id} for proposal {proposal_id}: {approved}")
                    return True
            
            elif message_type == 'finalized_key':
                # A key rotation was finalized
                proposal_id = message.get('proposal_id')
                key_hash = message.get('key_hash')
                encrypted_keys = message.get('encrypted_keys', {})
                
                if proposal_id and key_hash and sender_id in encrypted_keys:
                    # Process the new key
                    logger.info(f"Received finalized key for proposal {proposal_id}")
                    return True
            
            logger.warning(f"Unknown message type: {message_type}")
            return False
        except Exception as e:
            logger.error(f"Failed to process message: {e}")
            return False
    
    def _send_to_all_nodes(self, endpoint: str, payload: Dict) -> bool:
        """
        Enhanced method for sending messages to nodes with improved SSL handling.
        """
        # Disable SSL warnings to prevent cluttering logs
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        success_count = 0
        nodes = self.node_registry.get_all_nodes()
        
        for node_id, node_data in nodes.items():
            # Skip self
            if node_id == self.node_id:
                continue
            
            # Skip inactive nodes
            last_seen = datetime.fromisoformat(node_data.get('last_seen', '2000-01-01T00:00:00'))
            if (datetime.utcnow() - last_seen).total_seconds() > 86400:  # 24 hours
                continue
            
            try:
                url = node_data.get('url')
                if not url:
                    continue
                
                # Enhanced SSL verification
                try:
                    # Try with certificate verification first
                    response = requests.post(
                        f"{url}{endpoint}", 
                        json=payload, 
                        timeout=5,
                        verify=True  # Strict verification
                    )
                except (ssl.SSLCertVerificationError, requests.exceptions.SSLError):
                    # Fallback to more lenient verification
                    logger.warning(f"SSL verification failed for {node_id}, attempting lenient verification")
                    
                    # Create a custom SSL context with less strict verification
                    ssl_context = ssl.create_default_context()
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                    
                    # Use custom adapter to bypass hostname verification
                    session = requests.Session()
                    adapter = requests.adapters.HTTPAdapter(
                        ssl_context=ssl_context
                    )
                    session.mount('https://', adapter)
                    
                    response = session.post(
                        f"{url}{endpoint}", 
                        json=payload, 
                        timeout=5
                    )
                
                if response.status_code == 200:
                    success_count += 1
                else:
                    logger.warning(f"Failed to send to node {node_id}: {response.status_code}")
            
            except requests.RequestException as e:
                logger.warning(f"Network error sending to node {node_id}: {e}")
            except Exception as e:
                logger.error(f"Unexpected error sending to node {node_id}: {e}")
        
        # Consider it successful if we reached at least half the nodes
        success_percentage = (success_count / len(nodes)) * 100 if nodes else 0
        logger.info(f"Broadcast success: {success_count}/{len(nodes)} nodes ({success_percentage:.2f}%)")
        
        return success_count >= len(nodes) / 2


class KeyRotationManager:
    """Manages secure key rotation with PKI and distributed consensus."""
    
    def __init__(self, node_id: str = None, is_validator: bool = False):
        # Generate a unique node ID if none provided
        self.node_id = node_id or str(uuid.uuid4())
        self.is_validator = is_validator
        
        # Initialize components
        self.secure_storage = SecureStorage()
        self.pki = PKIManager(self.node_id)
        self.node_registry = NodeRegistry()
        self.consensus = ConsensusManager(self.node_id, self.node_registry, self.pki)
        self.p2p = P2PNetwork(self.node_id, self.node_registry, self.pki, self.consensus)
        
        # Current auth credentials
        self.current_auth_secret = self.secure_storage.retrieve("current_auth_secret") or self._generate_secure_secret()
        logger.info(f"Initial current_auth_secret for {node_id}: {self.current_auth_secret}")
        self.previous_auth_secret = None
        self.pending_auth_secret = None
        self.pending_proposal_id = None
        
        # Load or generate initial auth secret
        self._load_auth_secrets()
        
        # Start background scheduler
        self._start_scheduler()
    
    def _load_auth_secrets(self):
        """Load authentication secrets from secure storage."""
        # Load current auth secret
        self.current_auth_secret = self.secure_storage.retrieve("current_auth_secret")
        if not self.current_auth_secret:
            # Generate initial auth secret if none exists
            self.current_auth_secret = self._generate_secure_secret()
            self.secure_storage.store("current_auth_secret", self.current_auth_secret)
        
        # Load previous auth secret
        self.previous_auth_secret = self.secure_storage.retrieve("previous_auth_secret")
        
        # Load pending auth secret
        self.pending_auth_secret = self.secure_storage.retrieve("pending_auth_secret")
        self.pending_proposal_id = self.secure_storage.retrieve("pending_proposal_id")
        
        logger.info("Loaded authentication secrets from secure storage")
        
        # Update environment file
        self._update_environment()
    
    def _generate_secure_secret(self, length: int = 64) -> str:
        """Generate a cryptographically secure random secret."""
        start_time = time.time()
        secret = base64.b64encode(os.urandom(length)).decode('utf-8')
        duration = time.time() - start_time
        logger.info(f"Generated secure secret in {duration * 1e6:.2f} µs")
        return secret
    
    def _hash_secret(self, secret: str) -> str:
        """Create a hash of the secret for verification."""
        digest = hashlib.sha256(secret.encode()).hexdigest()
        return digest
    
    def _start_scheduler(self):
        """Start the background schedulers for key rotation tasks."""
        # Schedule periodic tasks
        if self.is_validator:
            # Validators initiate rotation proposals periodically
            schedule.every(KEY_ROTATION_INTERVAL_DAYS).days.do(self._initiate_key_rotation)
        
        # All nodes check for proposal updates
        schedule.every(1).hour.do(self._check_proposals)
        
        # Clean up expired proposals
        schedule.every(6).hours.do(self.consensus.cleanup_expired_proposals)
        
        # Start the scheduler in a background thread
        threading.Thread(target=self._run_scheduler, daemon=True).start()
        
        logger.info("Started key rotation scheduler")
    
    def _run_scheduler(self):
        """Run the scheduler in a loop."""
        while True:
            schedule.run_pending()
            time.sleep(60)  # Check every minute
    
    def _initiate_key_rotation(self):
        """Initiate a key rotation proposal if it's time to rotate."""
        # Skip if we already have a pending proposal
        if self.pending_proposal_id:
            logger.info(f"Skipping key rotation initiation - pending proposal {self.pending_proposal_id} exists")
            return
        
        logger.info("Initiating key rotation proposal")
        
        # Generate a new secret
        new_secret = self._generate_secure_secret()
        new_secret_hash = self._hash_secret(new_secret)
        
        # Store the pending secret
        self.pending_auth_secret = new_secret
        self.secure_storage.store("pending_auth_secret", new_secret)
        
        # Create a proposal
        proposal_id = self.consensus.create_proposal(new_secret_hash)
        if proposal_id:
            self.pending_proposal_id = proposal_id
            self.secure_storage.store("pending_proposal_id", proposal_id)
            logger.info(f"Key rotation proposal {proposal_id} created successfully")
            
            # Immediately clean up expired proposals
            logger.info("Running cleanup of expired proposals after proposal creation")
            self.consensus.cleanup_expired_proposals()

            # Broadcast the proposal to the network
            self.p2p.broadcast_proposal(proposal_id)
        else:
            logger.error("Failed to create key rotation proposal")
    
    def _check_proposals(self):
        """Check for proposal updates and take appropriate actions."""
        # Check our pending proposal if exists
        if self.pending_proposal_id:
            status = self.consensus.check_proposal_status(self.pending_proposal_id)
            
            if status.get('threshold_reached', False) and not status.get('finalized', False):
                # Finalize the proposal
                success, key_hash = self.consensus.finalize_proposal(self.pending_proposal_id)
                
                if success:
                    logger.info(f"Successfully finalized proposal {self.pending_proposal_id}")
                    
                    # Apply the key rotation
                    self._apply_key_rotation()
                    
                    # Distribute the new key to other nodes
                    self._distribute_finalized_key()
        
        # Check for other active proposals to vote on
        if self.is_validator:
            active_proposals = self.consensus.get_active_proposals()
            
            for proposal in active_proposals:
                proposal_id = proposal.get('id')
                
                # Vote on proposals we haven't voted on yet
                votes = proposal.get('votes', {})
                if self.node_id not in votes:
                    # In a real system, you'd have more complex voting logic
                    # For this example, validators automatically approve proposals
                    self.consensus.vote_on_proposal(proposal_id, True)
                    
                    # Broadcast the vote to the network
                    self.p2p.broadcast_vote(proposal_id, True)
    
    def _apply_key_rotation(self):
        """Apply a finalized key rotation."""
        if not self.pending_auth_secret or not self.pending_proposal_id:
            logger.error("Cannot apply key rotation: missing pending secret or proposal ID")
            return
        
        logger.info(f"Applying key rotation from proposal {self.pending_proposal_id}")
        
        # Rotate the keys
        self.previous_auth_secret = self.current_auth_secret
        self.current_auth_secret = self.pending_auth_secret
        
        # Update the secure storage
        self.secure_storage.store("previous_auth_secret", self.previous_auth_secret)
        self.secure_storage.store("current_auth_secret", self.current_auth_secret)
        
        # Clear pending data
        self.pending_auth_secret = None
        self.pending_proposal_id = None
        self.secure_storage.delete("pending_auth_secret")
        self.secure_storage.delete("pending_proposal_id")
        
        # Update environment for application use
        self._update_environment()
        
        logger.info("Key rotation completed successfully")
    
    def _distribute_finalized_key(self):
        """Distribute the finalized key to all nodes in the network."""
        if not self.current_auth_secret:
            logger.error("Cannot distribute key: missing current auth secret")
            return
        
        start_time = time.time()
        try:
            # Prepare encrypted keys for each node
            encrypted_keys = {}
            
            for node_id, node_data in self.node_registry.get_all_nodes().items():
                # Skip self
                if node_id == self.node_id:
                    continue
                
                # Encrypt the secret with the node's public key
                public_key = node_data.get('public_key')
                if not public_key:
                    continue
                
                node_start = time.time()
                encrypted_secret = self.pki.encrypt_message(self.current_auth_secret, public_key)
                logger.info(f"Encrypted key for {node_id} in {(time.time() - node_start) * 1e3:.2f} ms")
                encrypted_keys[node_id] = encrypted_secret
            
            # Broadcast the encrypted keys
            key_hash = self._hash_secret(self.current_auth_secret)
            self.p2p.broadcast_finalized_key(self.pending_proposal_id, key_hash, encrypted_keys)
            
            total_duration = time.time() - start_time
            logger.info(f"Distributed finalized key to {len(encrypted_keys)} nodes in {total_duration:.3f} seconds")
        except Exception as e:
            logger.error(f"Failed to distribute finalized key: {e}")
    
    def _update_environment(self):
        """Update the environment with the current auth secret."""
        env_path = Path(os.getcwd()) / '.env'
        try:
            # Read existing .env file
            env_content = ""
            if env_path.exists():
                with open(env_path, 'r') as f:
                    env_content = f.read()
            
            # Check if PEER_AUTH_SECRET is already set
            if 'PEER_AUTH_SECRET=' in env_content:
                # Replace the existing value
                lines = env_content.splitlines()
                for i, line in enumerate(lines):
                    if line.startswith('PEER_AUTH_SECRET='):
                        lines[i] = f'PEER_AUTH_SECRET={self.current_auth_secret}'
                        break
                
                env_content = '\n'.join(lines)
            else:
                # Add the key if it doesn't exist
                if env_content and not env_content.endswith('\n'):
                    env_content += '\n'
                env_content += f'PEER_AUTH_SECRET={self.current_auth_secret}\n'
            
            # Write the updated content
            with open(env_path, 'w') as f:
                f.write(env_content)
            
            # Set secure permissions
            os.chmod(env_path, 0o600)
            
            logger.info("Updated environment with new auth secret")
        except Exception as e:
            logger.error(f"Failed to update environment: {e}")
    
    def receive_key(self, encrypted_key: str) -> bool:
        """
        Receive and apply a new key that was encrypted for this node.
        Returns success status.
        """
        try:
            # Decrypt the key
            decrypted_key = self.pki.decrypt_message(encrypted_key)
            
            # Verify it's different from current key
            if decrypted_key == self.current_auth_secret:
                logger.warning("Received key is identical to current key")
                return True
            
            # Apply the new key
            self.previous_auth_secret = self.current_auth_secret
            self.current_auth_secret = decrypted_key
            
            # Update storage
            self.secure_storage.store("previous_auth_secret", self.previous_auth_secret)
            self.secure_storage.store("current_auth_secret", self.current_auth_secret)
            
            # Update environment
            self._update_environment()
            
            logger.info("Successfully applied received key")
            return True
        except Exception as e:
            logger.error(f"Failed to apply received key: {e}")
            return False
    
    def authenticate_peer(self, provided_secret: str) -> bool:
        """Authenticate a peer using either current or previous secret."""
        start_time = time.time()
        if not self.current_auth_secret:  # Add null check
            logger.warning("Current auth secret not initialized")
        elif provided_secret == self.current_auth_secret:
            duration = time.time() - start_time
            logger.info(f"Authenticated with current secret in {duration * 1e6:.2f} µs")
            return True
        if self.previous_auth_secret:
            last_rotation = self.secure_storage.retrieve("last_rotation_time") or "0"
            if time.time() - float(last_rotation) < 172800:  # 48 hours
                if provided_secret == self.previous_auth_secret:
                    duration = time.time() - start_time
                    logger.info(f"Authenticated with previous secret in {duration * 1e6:.2f} µs")
                    return True
        duration = time.time() - start_time
        logger.info(f"Authentication failed in {duration * 1e6:.2f} µs")
        return False
    
    def get_current_auth_secret(self) -> str:
        """Get the current authentication secret."""
        start_time = time.time()
        secret = self.current_auth_secret
        duration = time.time() - start_time
        logger.info(f"Accessed current_auth_secret in {duration * 1e6:.2f} µs")
        return secret