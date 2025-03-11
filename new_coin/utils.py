import os
import yaml
import ecdsa
import hashlib
from enum import Enum
from dataclasses import dataclass
from typing import Dict, Optional, Any, Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import socket
from dotenv import load_dotenv
from key_rotation.core import KeyRotationManager
import requests
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Initialize with a consistent node_id (to be set by main.py)
rotation_manager = None

def init_rotation_manager(node_id):
    global rotation_manager
    import time
    start_time = time.time()
    rotation_manager = KeyRotationManager(node_id=node_id)
    duration = time.time() - start_time
    logger.info(f"Initialized KeyRotationManager for {node_id} in {duration:.3f} seconds")

def get_peer_auth_secret():
    import time
    if not rotation_manager:
        raise ValueError("Rotation manager not initialized")
    start_time = time.time()
    secret = rotation_manager.get_current_auth_secret()
    duration = time.time() - start_time
    logger.info(f"Retrieved peer auth secret in {duration * 1e6:.2f} µs")
    return secret

# Default to function for dynamic access
PEER_AUTH_SECRET = get_peer_auth_secret

def validate_peer_auth(received_auth):
    """
    Validates peer authentication against current and previous secrets.
    
    Args:
        received_auth (str): The authentication received from a peer
        
    Returns:
        bool: True if authentication is valid, False otherwise
    """
    import time
    if not rotation_manager:
        raise ValueError("Rotation manager not initialized")
    start_time = time.time()
    result = rotation_manager.authenticate_peer(received_auth)
    duration = time.time() - start_time
    logger.info(f"Validated peer auth in {duration * 1e6:.2f} µs")
    return result

SSL_CERT_PATH = os.getenv("SSL_CERT_PATH", "server.crt")
SSL_KEY_PATH = os.getenv("SSL_KEY_PATH", "server.key")

if not os.path.exists(SSL_CERT_PATH) or not os.path.exists(SSL_KEY_PATH):
    result = os.system(f'openssl req -x509 -newkey rsa:2048 -keyout "{SSL_KEY_PATH}" -out "{SSL_CERT_PATH}" -days 365 -nodes -subj "/CN=localhost"')
    if result != 0:
        raise RuntimeError("Failed to generate SSL certificate with OpenSSL")

# Define node key pair
def generate_node_keypair():
    private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    public_key = private_key.get_verifying_key()
    return private_key.to_string().hex(), public_key.to_string().hex()
    
def load_config(config_file: str = "config.yaml") -> Dict:
    """Enhanced configuration loading with network-wide validation"""
    default_config = {
        # Existing defaults
        "network_version": "1.0",
        "min_peer_trust_threshold": 50,
        "max_chain_divergence": 10
    }
    
    try:
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f) or {}
        
        # Validate configuration
        for key, value in default_config.items():
            config.setdefault(key, value)
        
        # Optional: Add configuration validation
        if config['min_peer_trust_threshold'] < 0 or config['min_peer_trust_threshold'] > 100:
            logger.warning("Invalid peer trust threshold, using default")
            config['min_peer_trust_threshold'] = 50
        
        return config
    except FileNotFoundError:
        return default_config

CONFIG = load_config()

class TransactionType(Enum):
    """Enum representing types of transactions."""
    COINBASE = "coinbase"
    REGULAR = "regular"

@dataclass
class TransactionOutput:
    """Represents an output in a transaction."""
    recipient: str
    amount: float
    script: str = "P2PKH"

    def to_dict(self) -> Dict[str, Any]:
        return {"recipient": self.recipient, "amount": self.amount, "script": self.script}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TransactionOutput':
        return cls(recipient=data["recipient"], amount=data["amount"], script=data.get("script", "P2PKH"))

@dataclass
class TransactionInput:
    """Represents an input in a transaction."""
    tx_id: str
    output_index: int
    public_key: Optional[str] = None
    signature: Optional[bytes] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tx_id": self.tx_id,
            "output_index": self.output_index,
            "public_key": self.public_key,
            "signature": self.signature.hex() if self.signature else None
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TransactionInput':
        signature = bytes.fromhex(data["signature"]) if data.get("signature") else None
        return cls(tx_id=data["tx_id"], output_index=data["output_index"], public_key=data.get("public_key"), signature=signature)

class SecurityUtils:
    """Utility class for cryptographic operations."""
    @staticmethod
    def generate_keypair() -> Tuple[str, str]:
        """Generate an ECDSA key pair.

        Returns:
            tuple[str, str]: Private key and public key in hex format.
        """
        private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        public_key = private_key.get_verifying_key()
        return private_key.to_string().hex(), public_key.to_string().hex()

    @staticmethod
    def public_key_to_address(public_key: str) -> str:
        """Convert a public key to a blockchain address.

        Args:
            public_key (str): Public key in hex format.

        Returns:
            str: Address string.
        """
        pub_bytes = bytes.fromhex(public_key)
        sha256_hash = hashlib.sha256(pub_bytes).hexdigest()
        ripemd160_hash = hashlib.new('ripemd160', bytes.fromhex(sha256_hash)).hexdigest()
        return f"1{ripemd160_hash[:20]}"

def generate_wallet() -> Dict[str, str]:
    """Generate a wallet with private key, public key, and address.

    Returns:
        Dict[str, str]: Wallet dictionary.
    """
    private_key, public_key = SecurityUtils.generate_keypair()
    address = SecurityUtils.public_key_to_address(public_key)
    return {"address": address, "private_key": private_key, "public_key": public_key}

def derive_key(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
    """Derive an encryption key from a password using PBKDF2.

    Args:
        password (str): Password to derive key from.
        salt (bytes, optional): Salt for key derivation. Generates new if None.

    Returns:
        tuple[bytes, bytes]: Derived key and salt.
    """
    if not salt:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def is_port_available(port: int, host: str = 'localhost') -> bool:
    """Check if a port is available on the host.

    Args:
        port (int): Port number to check.
        host (str): Host to check against.

    Returns:
        bool: True if port is available, False otherwise.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex((host, port)) != 0

def find_available_port(start_port: int = 1024, end_port: int = 65535, host: str = 'localhost') -> int:
    """Find an available port within a range.

    Args:
        start_port (int): Starting port number.
        end_port (int): Ending port number.
        host (str): Host to check against.

    Returns:
        int: An available port number.
    """
    import random
    port = random.randint(start_port, end_port)
    while not is_port_available(port, host):
        port = random.randint(start_port, end_port)
    return port