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
import logging
import time
import random
from prometheus_client import REGISTRY, Counter, Gauge, CollectorRegistry, GC_COLLECTOR, PLATFORM_COLLECTOR, PROCESS_COLLECTOR
import getpass

try:
    from utils import blockchain_cpp
    CPP_ACCELERATED = True
except ImportError:
    CPP_ACCELERATED = False

# Configure logging
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Create a custom registry for our metrics
BLOCKCHAIN_REGISTRY = CollectorRegistry()

# Global KeyRotationManager instance
rotation_manager: Optional[KeyRotationManager] = None

async def init_rotation_manager(node_id: str) -> None:
    """Initialize the KeyRotationManager for the node."""
    global rotation_manager
    if rotation_manager is None:
            from key_rotation.core import KeyRotationManager
            rotation_manager = KeyRotationManager(node_id=node_id)
            await rotation_manager.start()
    logger.debug(f"Rotation manager initialized for {node_id}")

async def get_peer_auth_secret() -> str:
    """Retrieve the current peer authentication secret."""
    if not rotation_manager:
        raise ValueError("Rotation manager not initialized")
    start_time = time.time()
    secret = await rotation_manager.get_current_auth_secret()
    logger.debug(f"Retrieved peer auth secret in {(time.time() - start_time) * 1e6:.2f} µs")
    return secret

PEER_AUTH_SECRET = get_peer_auth_secret

def validate_peer_auth(received_auth: str) -> bool:
    """Validate peer authentication against current and previous secrets."""
    if not rotation_manager:
        raise ValueError("Rotation manager not initialized")
    start_time = time.time()
    result = rotation_manager.authenticate_peer(received_auth)
    logger.debug(f"Validated peer auth in {(time.time() - start_time) * 1e6:.2f} µs")
    return result

SSL_CERT_PATH = os.getenv("SSL_CERT_PATH", "server.crt")
SSL_KEY_PATH = os.getenv("SSL_KEY_PATH", "server.key")

if not os.path.exists(SSL_CERT_PATH) or not os.path.exists(SSL_KEY_PATH):
    result = os.system(f'openssl req -x509 -newkey rsa:2048 -keyout "{SSL_KEY_PATH}" -out "{SSL_CERT_PATH}" -days 365 -nodes -subj "/CN=localhost"')
    if result != 0:
        raise RuntimeError("Failed to generate SSL certificate with OpenSSL")

def generate_node_keypair() -> Tuple[str, str]:
    """Generate an ECDSA key pair for node identity."""
    private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    public_key = private_key.get_verifying_key()
    return private_key.to_string().hex(), public_key.to_string().hex()

def load_config(config_file: str = "config.yaml") -> Dict[str, Any]:
    """Load and validate configuration from a YAML file."""
    default_config = {
        "difficulty": 4,
        "current_reward": 50.0,
        "halving_interval": 210000,
        "mempool_max_size": 1000,
        "max_retries": 3,
        "sync_interval": 300
    }
    try:
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f) or {}
        for key, value in default_config.items():
            config.setdefault(key, value)
        return config
    except FileNotFoundError:
        logger.warning(f"Config file {config_file} not found, using defaults")
        return default_config
    except Exception as e:
        logger.error(f"Error loading config: {e}")
        return default_config

CONFIG = load_config()

class TransactionType(Enum):
    """Enum representing types of transactions."""
    COINBASE = "coinbase"
    TRANSFER = "transfer"  # Renamed from REGULAR for clarity

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
        return cls(tx_id=data["tx_id"], output_index=data["output_index"], 
                  public_key=data.get("public_key"), signature=signature)

class SecurityUtils:
    """Utility class for cryptographic operations."""
    @staticmethod
    def generate_keypair() -> Tuple[str, str]:
        """Generate an ECDSA key pair."""
        try:
            private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
            public_key = private_key.get_verifying_key()
            return private_key.to_string().hex(), public_key.to_string().hex()
        except Exception as e:
            logger.error(f"Failed to generate keypair: {e}")
            raise

    @staticmethod
    def public_key_to_address(public_key: str) -> str:
        """Convert a public key to a blockchain address."""
        try:
            pub_bytes = bytes.fromhex(public_key)
            sha256_hash = hashlib.sha256(pub_bytes).hexdigest()
            ripemd160_hash = hashlib.new('ripemd160', bytes.fromhex(sha256_hash)).hexdigest()
            return f"1{ripemd160_hash[:20]}"
        except Exception as e:
            logger.error(f"Failed to convert public key to address: {e}")
            raise

def generate_wallet() -> Dict[str, str]:
    """Generate a wallet with private key, public key, and address."""
    try:
        private_key, public_key = SecurityUtils.generate_keypair()
        address = SecurityUtils.public_key_to_address(public_key)
        return {"address": address, "private_key": private_key, "public_key": public_key}
    except Exception as e:
        logger.error(f"Failed to generate wallet: {e}")
        raise

def derive_key(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """Derive an encryption key from a password using PBKDF2."""
    try:
        if not salt:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
    except Exception as e:
        logger.error(f"Failed to derive key: {e}")
        raise

def is_port_available(port: int, host: str = 'localhost') -> bool:
    """Check if a port is available on the host."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex((host, port)) != 0
    except Exception as e:
        logger.warning(f"Error checking port {port} availability: {e}")
        return False

async def find_available_port_async(start_port: int = 1024, end_port: int = 65535, host: str = 'localhost') -> int:
    """Find an available port asynchronously"""
    try:
        port = random.randint(start_port, end_port)
        attempts = 0
        max_attempts = 100

        while attempts < max_attempts:
            try:
                # Test if port is available
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.bind((host, port))
                sock.close()
                logger.info(f"Found available port: {port}")
                return port
            except OSError:
                attempts += 1
                port = random.randint(start_port, end_port)
                
        raise RuntimeError(f"No available ports found between {start_port} and {end_port}")
    except Exception as e:
        logger.error(f"Error finding available port: {e}")
        raise

def safe_gauge(name: str, description: str, registry=BLOCKCHAIN_REGISTRY) -> Gauge:
    """Safely create or get a Gauge metric with labels"""
    try:
        return Gauge(name, description, labelnames=['instance'], registry=registry)
    except ValueError:
        # If metric already exists, get it from registry
        for collector in registry._names_to_collectors.values():
            if hasattr(collector, 'name') and collector.name == name:
                return collector
        raise  # Re-raise if we can't find it

def safe_counter(name: str, description: str, registry=BLOCKCHAIN_REGISTRY) -> Counter:
    """Safely create or get a Counter metric with labels"""
    try:
        return Counter(name, description, labelnames=['instance'], registry=registry)
    except ValueError:
        # If metric already exists, get it from registry
        for collector in registry._names_to_collectors.values():
            if hasattr(collector, 'name') and collector.name == name:
                return collector
        raise  # Re-raise if we can't find it
# Disable automatic collector registration
for collector in [GC_COLLECTOR, PLATFORM_COLLECTOR, PROCESS_COLLECTOR]:
    try:
        REGISTRY.unregister(collector)
    except KeyError:
        pass  # Collector might not be registered

# Define metrics with consistent names
BLOCKS_RECEIVED = safe_counter('blocks_received_total', 'Total number of blocks received from peers')
TXS_BROADCAST = safe_counter('transactions_broadcast_total', 'Total number of transactions broadcast')
PEER_FAILURES = safe_counter('peer_failures_total', 'Total number of peer connection failures')
BLOCKS_MINED = safe_counter('blocks_mined_total', 'Total number of blocks mined')
PEER_COUNT = safe_gauge('peer_count', 'Number of connected peers')
BLOCK_HEIGHT = safe_gauge('blockchain_height', 'Current height of the blockchain')
ACTIVE_REQUESTS = safe_gauge('active_peer_requests', 'Number of active requests to peers')

def get_secure_password(provided_password: str = None) -> str:
    if provided_password:
        return provided_password
    env_password = os.environ.get("WALLET_PASSWORD")
    if env_password:
        return env_password
    if os.isatty(0):
        return getpass.getpass("Enter wallet encryption password: ")
    raise ValueError("Password required in non-interactive mode")

# New utils/serialization.py
import msgpack
from typing import Any, Dict

def serialize(data: Any) -> bytes:
    """Serialize data using msgpack"""
    return msgpack.packb(data, use_bin_type=True)

def deserialize(data: bytes) -> Any:
    """Deserialize msgpack data"""
    return msgpack.unpackb(data, raw=False)

# Functions to handle binary data for network transmission
def prepare_for_network(obj: Dict) -> Dict:
    """Prepare object for network transmission"""
    # Convert bytes to base64 strings for safe transmission
    result = {}
    for k, v in obj.items():
        if isinstance(v, bytes):
            result[k] = v.hex()
        elif isinstance(v, dict):
            result[k] = prepare_for_network(v)
        elif isinstance(v, list):
            result[k] = [prepare_for_network(item) if isinstance(item, dict) else item for item in v]
        else:
            result[k] = v
    return result

def restore_from_network(obj: Dict) -> Dict:
    """Restore object after network transmission"""
    # Convert base64 strings back to bytes
    result = {}
    for k, v in obj.items():
        if k.endswith('_bytes') and isinstance(v, str):
            result[k[:-6]] = bytes.fromhex(v)
        elif isinstance(v, dict):
            result[k] = restore_from_network(v)
        elif isinstance(v, list):
            result[k] = [restore_from_network(item) if isinstance(item, dict) else item for item in v]
        else:
            result[k] = v
    return result

import importlib
import os
import sys

def import_cpp_extension(extension_name):
    """
    Dynamically import C++ extensions with fallback mechanism
    """
    try:
        # Try standard import first
        return importlib.import_module(extension_name)
    except ImportError:
        # Search in various potential locations
        possible_paths = [
            os.path.join(os.path.dirname(__file__), f"{extension_name}.pyd"),
            os.path.join(os.path.dirname(__file__), '..', f"{extension_name}.pyd"),
            os.path.join(sys.prefix, 'lib', 'site-packages', f"{extension_name}.pyd"),
            os.path.join(os.getcwd(), f"{extension_name}.pyd")
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                try:
                    # Add directory to Python path
                    sys.path.insert(0, os.path.dirname(path))
                    return importlib.import_module(extension_name)
                except Exception as e:
                    print(f"Failed to import {extension_name} from {path}: {e}")
        
        # Fallback implementation if C++ extension cannot be loaded
        class FallbackExtension:
            def __getattr__(self, name):
                def fallback_func(*args, **kwargs):
                    print(f"Warning: Using Python fallback for {name}")
                    # Implement basic fallback logic
                    if name == 'sha256':
                        import hashlib
                        return lambda x: hashlib.sha256(x.encode()).hexdigest()
                    elif name == 'calculate_merkle_root':
                        return lambda tx_ids: hashlib.sha256(''.join(tx_ids).encode()).hexdigest()
                    elif name == 'public_key_to_address':
                        return lambda public_key: f"1{hashlib.sha256(public_key.encode()).hexdigest()[:10]}"
                    else:
                        raise NotImplementedError(f"Fallback for {name} not implemented")
                return fallback_func
        
        return FallbackExtension()

# Replace direct imports with this function
blockchain_cpp = import_cpp_extension('blockchain_cpp')