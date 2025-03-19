"""
P2P components and utilities for blockchain network communication.
"""

import os
import json
import time
import logging
import ecdsa
import subprocess
import ssl
import uuid
from collections import defaultdict
from pathlib import Path
from datetime import datetime, timedelta

logger = logging.getLogger("P2PNetwork")

class PeerReputation:
    def __init__(self):
        self.reputation_scores = defaultdict(lambda: 100)  # Start with 100 points
        self.violation_weights = {
            'invalid_transaction': -10,
            'invalid_block': -20,
            'failed_auth': -15,
            'rate_limit_exceeded': -5,
            'successful_transaction': 1,
            'successful_block': 2
        }
        
    def update_reputation(self, peer_id: str, event: str) -> int:
        """Update peer reputation based on events"""
        self.reputation_scores[peer_id] += self.violation_weights.get(event, 0)
        self.reputation_scores[peer_id] = max(0, min(100, self.reputation_scores[peer_id]))
        return self.reputation_scores[peer_id]
    
    def is_peer_trusted(self, peer_id: str, minimum_score: int = 50) -> bool:
        return self.reputation_scores[peer_id] >= minimum_score


class RateLimiter:
    def __init__(self):
        self.request_counts = defaultdict(lambda: defaultdict(int))
        self.last_reset = defaultdict(float)
        
        # Configure limits for different operations
        self.limits = {
            'transaction': {'count': 100, 'window': 60},  # 100 transactions per minute
            'block': {'count': 10, 'window': 60},        # 10 blocks per minute
            'peer_connect': {'count': 5, 'window': 60},  # 5 connection attempts per minute
        }

    async def check_rate_limit(self, peer_id: str, operation: str) -> bool:
        current_time = time.time()
        window = self.limits[operation]['window']
        
        # Reset counters if window has passed
        if current_time - self.last_reset[peer_id] > window:
            self.request_counts[peer_id] = defaultdict(int)
            self.last_reset[peer_id] = current_time
        
        # Check if limit is exceeded
        if self.request_counts[peer_id][operation] >= self.limits[operation]['count']:
            return False
        
        self.request_counts[peer_id][operation] += 1
        return True


class NonceTracker:
    def __init__(self):
        self.nonce_map = defaultdict(set)
        self.nonce_expiry = {}  # Store block height when nonce was used
        
    async def add_nonce(self, address: str, nonce: int, block_height: int):
        self.nonce_map[address].add(nonce)
        self.nonce_expiry[(address, nonce)] = block_height
        
    async def is_nonce_used(self, address: str, nonce: int) -> bool:
        return nonce in self.nonce_map[address]
    
    async def cleanup_old_nonces(self, current_height: int, retention_blocks: int = 10000):
        """Remove nonces older than retention_blocks"""
        expired = [(addr, nonce) for (addr, nonce), height 
                  in self.nonce_expiry.items() 
                  if current_height - height > retention_blocks]
        
        for addr, nonce in expired:
            self.nonce_map[addr].remove(nonce)
            del self.nonce_expiry[(addr, nonce)]


class NodeIdentity:
    """Manages persistent node identity across restarts"""
    
    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.identity_file = self.data_dir / "node_identity.json"
        self.node_id = None
        self.private_key = None
        self.public_key = None
        
    async def initialize(self):
        """Initialize or load existing node identity"""
        # Create data directory if it doesn't exist
        os.makedirs(self.data_dir, exist_ok=True)
        
        # Check if identity file exists
        if self.identity_file.exists():
            # Load existing identity
            with open(self.identity_file, 'r') as f:
                data = json.load(f)
                self.node_id = data['node_id']
                self.private_key = data['private_key']
                self.public_key = data['public_key']
            logger.info(f"Loaded existing node identity: {self.node_id}")
        else:
            # Generate new identity
            from utils import generate_node_keypair
            self.node_id = f"node-{uuid.uuid4()}"
            self.private_key, self.public_key = generate_node_keypair()
            
            # Save the identity
            with open(self.identity_file, 'w') as f:
                json.dump({
                    'node_id': self.node_id,
                    'private_key': self.private_key,
                    'public_key': self.public_key
                }, f)
            logger.info(f"Created new node identity: {self.node_id}")
        
        return self.node_id, self.private_key, self.public_key
    
    
class CertificateManager:
    """Manages SSL certificates with proper validation and rotation"""
    
    def __init__(self, node_id: str, host: str, data_dir: str = "data"):
        self.node_id = node_id
        self.host = host
        self.data_dir = Path(data_dir)
        self.cert_dir = self.data_dir / "certs"
        self.ca_cert = self.cert_dir / "ca.crt"
        self.ca_key = self.cert_dir / "ca.key"
        self.cert_file = self.cert_dir / f"{node_id}.crt"
        self.key_file = self.cert_dir / f"{node_id}.key"
        
    async def initialize(self):
        """Initialize certificate infrastructure"""
        # Create certificate directory
        os.makedirs(self.cert_dir, exist_ok=True)
        
        # Create CA if it doesn't exist
        if not self.ca_cert.exists() or not self.ca_key.exists():
            await self._create_ca()
            
        # Create or renew node certificate
        if not self.cert_file.exists() or not self.key_file.exists() or await self._is_cert_expired():
            await self._create_node_cert()
        
        # Create SSL contexts
        server_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        server_ctx.load_cert_chain(self.cert_file, self.key_file)
        
        client_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        client_ctx.load_verify_locations(self.ca_cert)
        
        return server_ctx, client_ctx
        
    async def _create_ca(self):
        """Create a Certificate Authority for the network"""
        logger.info("Creating Certificate Authority")
        
        # Create private key for CA
        subprocess.run([
            'openssl', 'genrsa', 
            '-out', str(self.ca_key),
            '4096'
        ], check=True)
        
        # Create CA certificate
        subprocess.run([
            'openssl', 'req', '-new', '-x509',
            '-key', str(self.ca_key),
            '-out', str(self.ca_cert),
            '-days', '3650',  # 10 years
            '-subj', f"/CN=OriginalCoin CA"
        ], check=True)
        
        logger.info(f"CA certificate created: {self.ca_cert}")
        
    async def _create_node_cert(self):
        """Create or renew node certificate signed by the CA"""
        logger.info(f"Creating certificate for node {self.node_id}")
        
        # Generate CSR configuration
        csr_config = self.cert_dir / f"{self.node_id}.cnf"
        with open(csr_config, 'w') as f:
            f.write(f"""[req]
        distinguished_name=req_distinguished_name
        req_extensions=v3_req
        prompt=no

        [req_distinguished_name]
        CN={self.node_id}

        [v3_req]
        basicConstraints=CA:FALSE
        keyUsage=digitalSignature, keyEncipherment
        extendedKeyUsage=serverAuth
        subjectAltName=@alt_names

        [alt_names]
        DNS.1={self.host}
        IP.1=127.0.0.1

        [san]
        subjectAltName=DNS:{self.host},IP:127.0.0.1
        """)
            
        # Create private key
        subprocess.run([
            'openssl', 'genrsa',
            '-out', str(self.key_file),
            '2048'
        ], check=True)
        
        # Create CSR
        subprocess.run([
            'openssl', 'req', '-new',
            '-key', str(self.key_file),
            '-out', str(self.cert_dir / f"{self.node_id}.csr"),
            '-subj', f"/CN={self.node_id}",
            '-config', str(csr_config)
        ], check=True)
        
        # Sign certificate with CA
        subprocess.run([
            'openssl', 'x509', '-req',
            '-in', str(self.cert_dir / f"{self.node_id}.csr"),
            '-CA', str(self.ca_cert),
            '-CAkey', str(self.ca_key),
            '-CAcreateserial',
            '-out', str(self.cert_file),
            '-days', '365',  # 1 year
            '-extensions', 'v3_req',
            '-extfile', str(csr_config)
        ], check=True)
        
        logger.info(f"Node certificate created: {self.cert_file}")
    
    async def _is_cert_expired(self):
        """Check if the certificate is expired or about to expire"""
        if not self.cert_file.exists():
            return True
            
        # Get certificate expiration date
        output = subprocess.check_output([
            'openssl', 'x509', '-enddate', '-noout',
            '-in', str(self.cert_file)
        ]).decode('utf-8')
        
        # Parse expiration date
        expiration_str = output.split('=')[1].strip()
        expiration_date = datetime.strptime(expiration_str, '%b %d %H:%M:%S %Y %Z')
        
        # Renew if less than 30 days until expiration
        return (expiration_date - datetime.now()) < timedelta(days=30)