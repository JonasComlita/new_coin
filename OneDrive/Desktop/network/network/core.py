"""
Core network functionality for blockchain P2P communication.
"""

import aiohttp
import asyncio
import os
import logging
import time
import random
import json
import threading
import ssl
from typing import Dict, List, Optional, Tuple, TYPE_CHECKING
from collections import defaultdict
import ecdsa
from pathlib import Path
from utils import serialize_block, deserialize_block, serialize_transaction, deserialize_transaction

from .p2p import (
    PeerReputation, 
    RateLimiter, 
    NonceTracker, 
    NodeIdentity, 
    CertificateManager
)
from .api import setup_api_routes

from blockchain import Blockchain, Block, Transaction
from utils import (
    PEER_AUTH_SECRET, 
    SSL_CERT_PATH, 
    SSL_KEY_PATH, 
    generate_node_keypair, 
    validate_peer_auth,
    SecurityUtils,
    BLOCKS_RECEIVED, 
    TXS_BROADCAST, 
    PEER_FAILURES, 
    BLOCKS_MINED, 
    BLOCK_HEIGHT, 
    PEER_COUNT, 
    ACTIVE_REQUESTS, 
    safe_gauge, 
    safe_counter,
    find_available_port_async
)
from security import SecurityMonitor
from security.mfa import MFAManager
from aiohttp import web

# Configure logging
logger = logging.getLogger("BlockchainNetwork")

def get_default_config() -> dict:
    """Return default configuration values"""
    return {
        "p2p_port": int(os.getenv("P2P_PORT", 8333)),  # Default Bitcoin P2P port
        "api_port": 8332,           # Default Bitcoin RPC port 
        "key_rotation_port": 8334,  # Custom port for key rotation
        "sync_interval": 10,         
        "max_peers": 10,            
        "peer_discovery_interval": 60,
        "max_retries": 3,           
        "isolation_timeout": 300,   
        "data_dir": "data",         # Directory for persistent data
        "log_level": "INFO",
        "peer_discovery_enabled": True,
        "ssl": {
            "enabled": True,
            "cert_validity_days": 365,
            "ca_validity_days": 3650
        },
        "bootstrap_nodes": []
    }

def load_config(config_path: str = "network_config.json") -> dict:
    """
    Load configuration from the specified file or create a default one if it doesn't exist.
    
    Args:
        config_path: Path to the configuration file
        
    Returns:
        dict: The loaded configuration
    """
    # Get default configuration
    network_config = get_default_config()
    
    # Create network_config directory if it doesn't exist
    config_dir = os.path.dirname(config_path)
    if config_dir and not os.path.exists(config_dir):
        os.makedirs(config_dir, exist_ok=True)
    
    # If network_config file exists, load it
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                user_config = json.load(f)
                
            # Deep merge configuration
            def deep_update(d, u):
                for k, v in u.items():
                    if isinstance(v, dict) and k in d and isinstance(d[k], dict):
                        deep_update(d[k], v)
                    else:
                        d[k] = v
                return d
                
            network_config = deep_update(network_config, user_config)
            logger.info(f"Loaded configuration from {config_path}")
            
        except json.JSONDecodeError:
            logger.error(f"Error parsing {config_path}: Invalid JSON format")
            logger.info(f"Using default configuration")
            
        except Exception as e:
            logger.error(f"Error loading configuration from {config_path}: {str(e)}")
            logger.info(f"Using default configuration")
    else:
        # Create default configuration file
        try:
            with open(config_path, 'w') as f:
                json.dump(network_config, f, indent=2, sort_keys=True)
            logger.info(f"Created default configuration at {config_path}")
        except Exception as e:
            logger.error(f"Error creating default configuration at {config_path}: {str(e)}")
    
    return network_config

def save_config(network_config: dict, config_path: str = "network_config.json") -> bool:
    """
    Save configuration to the specified file.
    
    Args:
        network_config: Configuration dictionary
        config_path: Path to save the configuration
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        with open(config_path, 'w') as f:
            json.dump(network_config, f, indent=2, sort_keys=True)
        logger.info(f"Saved configuration to {config_path}")
        return True
    except Exception as e:
        logger.error(f"Error saving configuration to {config_path}: {str(e)}")
        return False

async def rate_limit_middleware(app: web.Application, handler: callable) -> callable:
    """Simple rate-limiting middleware (placeholder for expansion)."""
    async def middleware(request: web.Request) -> web.Response:
        # Future: Add IP-based or token-based rate limiting
        return await handler(request)
    return middleware


class BlockchainNetwork:
    """Manages peer-to-peer networking for the blockchain with enhanced security and reliability."""
    def __init__(self, blockchain: 'Blockchain', node_id: str, host: str, port: int, 
                 bootstrap_nodes: Optional[List[Tuple[str, int]]] = None, security_monitor=None,
                 config_path = "network_config.json"):
        # Load configuration
        self.config = load_config(config_path)
        
        # Use provided port or default from config
        self.port = port if port is not None else self.config["p2p_port"]
        self.api_port = self.config["api_port"]
        self.key_rotation_port = self.config["key_rotation_port"]
        self.port_range = (1024, 65535)  # Configurable range
        self.heartbeat_interval = 30  # Heartbeat every 30s

        self.blockchain = blockchain
        self.node_id = node_id
        self.host = host

        # Initialize node identity
        self.identity = NodeIdentity(self.config["data_dir"])
        
        # Set up certificate manager
        self.cert_manager = CertificateManager(self.node_id, host, self.config["data_dir"])

        self.bootstrap_nodes = bootstrap_nodes or []
        self.security_monitor = security_monitor
        self.shutdown_flag = asyncio.Event()
        self.loop = None
        self.private_key, self.public_key = generate_node_keypair()
        self.peers = {}
        self.app = web.Application(middlewares=[rate_limit_middleware])
        
        # Set up API routes
        setup_api_routes(self)
        
        self.sync_task = None
        self.background_tasks = []
        self.discovery_task = None
        self.last_announcement = time.time()
        self.peer_failures = defaultdict(int)
        self.start_time = time.time()
        self.lock = threading.Lock() 
        self.active_requests = ACTIVE_REQUESTS
        self.active_requests.labels(instance=self.node_id).set(0)
        self.peer_reputation = PeerReputation()
        self.rate_limiter = RateLimiter()
        self.nonce_tracker = NonceTracker()
        self.mfa_manager = MFAManager()
        self.server = None  # Store server instance for cleanup
        self.health_server = None
        self.runner = web.AppRunner(self.app)  # Add runner for proper web app handling

        self.message_queue = asyncio.Queue(maxsize=1000)  # Queue for broadcasts
        self.broadcast_task = None
        
        # Initialize SSL contexts
        self.ssl_context = None
        self.client_ssl_context = None
        if self.port is not None:  # Only init_ssl if port is set
            self.init_ssl()
        logger.info(f"BlockchainNetwork initialized with port: {self.port}")

    def init_ssl(self):
        """Initialize SSL contexts"""
        if self.port is None:
            logger.warning(f"Skipping SSL initialization for {self.node_id} as port is None")
            return

        # Client SSL context
        self.client_ssl_context = ssl.create_default_context()
        self.client_ssl_context.check_hostname = False
        self.client_ssl_context.verify_mode = ssl.CERT_NONE

        # Server SSL context
        try:
            # Use port-specific certificate paths
            cert_path = f"certs/{self.node_id}_{self.port}.crt"
            key_path = f"certs/{self.node_id}_{self.port}.key"
            
            # Ensure certs directory exists
            os.makedirs("certs", exist_ok=True)
            
            # Debug file existence and paths
            logger.debug(f"Checking SSL for {self.node_id} on port {self.port}: "
                        f"cert_path={cert_path}, exists={os.path.exists(cert_path)}, "
                        f"key_path={key_path}, exists={os.path.exists(key_path)}")
            
            # Generate self-signed certificate if files are missing
            if not (os.path.exists(cert_path) and os.path.exists(key_path)):
                logger.info(f"SSL certificates not found for {self.node_id} on port {self.port}. Generating self-signed certificates...")
                cmd = (
                    f'openssl req -x509 -newkey rsa:2048 -keyout "{key_path}" '
                    f'-out "{cert_path}" -days 365 -nodes -subj "/CN={self.node_id}"'
                )
                with open(os.devnull, 'w') as devnull:
                    result = os.system(f"{cmd} > {os.devnull} 2>&1")
                if result != 0:
                    raise RuntimeError(f"Failed to generate SSL certificates for {self.node_id} on port {self.port} with OpenSSL")
                logger.info(f"Generated self-signed certificates: {cert_path}, {key_path}")
            else:
                logger.debug(f"Using existing SSL certificates for {self.node_id} on port {self.port}")
            
            # Load the certificates
            self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.ssl_context.load_cert_chain(
                certfile=cert_path,
                keyfile=key_path
            )
            logger.info(f"HTTPS enabled with certificates for {self.node_id} on port {self.port}")
            
        except Exception as e:
            logger.error(f"Failed to initialize SSL for {self.node_id} on port {self.port}: {e}", exc_info=True)
            logger.warning(f"Running without HTTPS for {self.node_id} on port {self.port} due to SSL failure")
            self.ssl_context = None

    async def start(self):
        """Start the network with periodic discovery and sync"""
        if self.loop is None:
            self.loop = asyncio.get_event_loop()

        # Initialize identity and certificates
        await self.identity.initialize()
        self.node_id, self.private_key, self.public_key = self.identity.node_id, self.identity.private_key, self.identity.public_key
        self.ssl_context, self.client_ssl_context = await self.cert_manager.initialize()

        # Connect to bootstrap nodes
        for host, port in self.bootstrap_nodes:
            if (host, port) != (self.host, self.port):
                peer_id = f"node{port}"
                await self.add_peer(peer_id, host, port, self.public_key)  # Use public key as initial auth

        # Start server
        self.server_task_handle = asyncio.create_task(self.start_server())
        self.background_tasks.append(self.server_task_handle)

        # Start periodic tasks
        self.sync_task = await self.start_periodic_sync(interval=self.config["sync_interval"])
        self.discovery_task = asyncio.create_task(self.periodic_discovery())
        self.background_tasks.append(self.discovery_task)

        # Start security monitoring
        if self.security_monitor:
            asyncio.create_task(self.security_monitor.analyze_patterns())

        logger.info(f"Network started on {self.host}:{self.port} with sync interval {self.config['sync_interval']}s")

        self.broadcast_task = asyncio.create_task(self.process_message_queue())
        self.background_tasks.append(self.broadcast_task)

    async def stop(self):
        """Stop the network and cancel background tasks."""
        logger.info("Stopping network...")
        self.shutdown_flag.set()  # Signal shutdown
        tasks_to_cancel = []

        # Cancel background tasks
        for task in self.background_tasks:
            if not task.done():
                task.cancel()
                tasks_to_cancel.append(task)
        
        if self.sync_task and not self.sync_task.done():
            tasks_to_cancel.append(self.sync_task)
        if self.discovery_task and not self.discovery_task.done():
            tasks_to_cancel.append(self.discovery_task)
        
        for task in tasks_to_cancel:
            task.cancel()
        
        if tasks_to_cancel:
            try:
                await asyncio.gather(*tasks_to_cancel, return_exceptions=True)
            except asyncio.CancelledError:
                pass
        
        if hasattr(self, 'runner'):
            await self.runner.cleanup()

        # Cleanup P2P server
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        
        logger.info("Network stopped")

    # Modified core.py for network communication
async def send_with_retry(self, url: str, data: dict, method: str = "post", max_retries: Optional[int] = None) -> Tuple[bool, Optional[dict]]:
    """Send request with per-node auth and msgpack serialization"""
    if max_retries is None:
        max_retries = self.config["max_retries"]
    
    # Sign the request with our private key
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(self.private_key), curve=ecdsa.SECP256k1)
    
    # Serialize using msgpack instead of JSON
    from utils import serialize, deserialize
    serialized_data = serialize(data)
    message = serialized_data
    signature = sk.sign(message).hex()
    
    headers = {
        "Node-ID": self.node_id, 
        "Signature": signature,
        "Content-Type": "application/msgpack"
    }
    
    async with aiohttp.ClientSession() as session:
        for attempt in range(max_retries):
            try:
                if method == "post":
                    async with session.post(url, data=serialized_data, headers=headers, ssl=self.client_ssl_context) as resp:
                        if resp.status == 200:
                            if resp.content_type == "application/msgpack":
                                resp_data = await resp.read()
                                return True, deserialize(resp_data)
                            else:
                                return True, await resp.json() if resp.content_type == "application/json" else None
                        return False, None
                elif method == "get":
                    async with session.get(url, headers=headers, ssl=self.client_ssl_context) as resp:
                        if resp.status == 200:
                            if resp.content_type == "application/msgpack":
                                resp_data = await resp.read()
                                return True, deserialize(resp_data)
                            else:
                                return True, await resp.json() if resp.content_type == "application/json" else None
                        return False, None
            except Exception as e:
                logger.warning(f"Request to {url} failed (attempt {attempt + 1}): {e}")
                if attempt == max_retries - 1:
                    return False, None
                await asyncio.sleep(0.5 * (2 ** attempt))  # Exponential backoff
            return False, None
    
    async def process_message_queue(self):
        """Process queued broadcast messages"""
        while not self.shutdown_flag.is_set():
            try:
                msg_type, data = await self.message_queue.get()
                if msg_type == "block":
                    await self.broadcast_block(data)
                elif msg_type == "transaction":
                    await self.broadcast_transaction(data)
                self.message_queue.task_done()
            except Exception as e:
                logger.error(f"Error processing message queue: {e}")
            await asyncio.sleep(0.1)
            
    async def broadcast_block(self, block: Block) -> None:
        """Broadcast a block to all peers using batch requests with optimized serialization"""
        if len(self.peers) <= 3:
            # For few peers, direct broadcast is fine
            tasks = []
            for peer_id, peer_data in self.peers.items():
                tasks.append(self.send_block(peer_id, peer_data["host"], peer_data["port"], block))
            await asyncio.gather(*tasks, return_exceptions=True)
        else:
            # For many peers, use batched broadcasts to reduce network overhead
            peer_batches = []
            peers_list = list(self.peers.items())
            batch_size = max(3, len(peers_list) // 3)  # Balance between parallelism and efficiency
            
            for i in range(0, len(peers_list), batch_size):
                peer_batches.append(peers_list[i:i+batch_size])
                
            for batch in peer_batches:
                tasks = []
                for peer_id, peer_data in batch:
                    tasks.append(self.send_block(peer_id, peer_data["host"], peer_data["port"], block))
                await asyncio.gather(*tasks, return_exceptions=True)
                # Small delay between batches to avoid network congestion
                await asyncio.sleep(0.05)
                
        BLOCKS_RECEIVED.labels(instance=self.node_id).inc()
        
    async def broadcast_transaction(self, transaction: Transaction) -> None:
        """Broadcast a transaction to all peers"""
        tasks = []
        for peer_id, peer_data in self.peers.items():
            tasks.append(self.send_transaction(peer_id, peer_data["host"], peer_data["port"], transaction))
        await asyncio.gather(*tasks, return_exceptions=True)
        TXS_BROADCAST.labels(instance=self.node_id).inc()

    async def send_block(self, peer_id: str, host: str, port: int, block: Block) -> None:
        """Send block to a peer with msgpack serialization and compression"""
        url = f"https://{host}:{port}/receive_block"
        
        # Use msgpack serialization with compression for better performance
        from utils import serialize
        
        # Convert block to dict and serialize
        data = {"block": block.to_dict()}
        success, _ = await self.send_with_retry(url, data)
        
        if not success:
            self._increment_failure(peer_id)

    async def send_transaction(self, peer_id: str, host: str, port: int, tx: Transaction) -> None:
        """Send a transaction to a specific peer."""
        url = f"https://{host}:{port}/receive_transaction"
        data = {"transaction": tx.to_dict()}
        success, _ = await self.send_with_retry(url, data)
        if success:
            logger.info(f"Sent transaction {tx.tx_id[:8]} to {peer_id}")
        else:
            logger.warning(f"Failed to send transaction {tx.tx_id[:8]} to {peer_id}")

    def _load_peers(self) -> Dict[str, Tuple[str, int, str]]:
        """Load known peers from persistent storage."""
        peers = {}
        try:
            if os.path.exists("known_peers.txt"):
                with open("known_peers.txt", "r") as f:
                    for line in f:
                        if ":" in line:
                            parts = line.strip().split(":")
                            if len(parts) >= 3:
                                host, port, pubkey = parts[0], int(parts[1]), ":".join(parts[2:])
                                peer_id = f"node{port}"
                                peers[peer_id] = (host, port, pubkey)
        except Exception as e:
            logger.error(f"Failed to load peers: {e}")
        return peers

    def _save_peers(self) -> None:
        """Save current peers to persistent storage."""
        try:
            with open("known_peers.txt", "w") as f:
                for peer_id, peer_data in self.peers.items():
                    host = peer_data["host"]
                    port = peer_data["port"]
                    pubkey = peer_data.get("public_key", "")
                    f.write(f"{host}:{port}:{pubkey}\n")
        except Exception as e:
            logger.error(f"Failed to save peers: {e}")

    async def broadcast_peer_announcement(self) -> None:
        """Announce this node to all peers."""
        sk = ecdsa.SigningKey.from_string(bytes.fromhex(self.private_key), curve=ecdsa.SECP256k1)
        message = f"{self.node_id}{self.host}{self.port}".encode()
        signature = sk.sign(message).hex()
        data = {
            "peer_id": self.node_id,
            "host": self.host,
            "port": self.port,
            "public_key": self.public_key,
            "signature": signature
        }
        tasks = []
        with self.lock:
            for peer_id, peer_data in self.peers.items():
                url = f"https://{peer_data['host']}:{peer_data['port']}/announce_peer"
                tasks.append(self.send_with_retry(url, data))
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for peer_id, result in zip(self.peers.keys(), results):
                if isinstance(result, Exception) or not result[0]:
                    logger.warning(f"Failed to announce to {peer_id}")
                    self._increment_failure(peer_id)
                else:
                    logger.debug(f"Announced to {peer_id}")
                    self.peer_failures[peer_id] = 0

    async def discover_peers(self) -> None:
        """Discover new peers from bootstrap nodes and existing peers."""
        with self.lock:
            # Bootstrap nodes
            for host, port in self.bootstrap_nodes:
                if (host, port) != (self.host, self.port):
                    peer_id = f"node{port}"
                    url = f"https://{host}:{port}/get_chain"
                    logger.debug(f"Attempting to discover peer {peer_id} at {url}")
                    success, response = await self.send_with_retry(url, {}, method="get")
                    if success:
                        if await self.add_peer(peer_id, host, port, PEER_AUTH_SECRET()):
                            logger.debug(f"Successfully added bootstrap node {peer_id}")
                    else:
                        logger.debug(f"Skipping unresponsive bootstrap node {peer_id}")

            # Discover from existing peers
            if not self.bootstrap_nodes and not self.peers:
                return
            peer_items = list(self.peers.items())
            if peer_items:
                peer_id, peer_data = random.choice(peer_items)
                url = f"https://{peer_data['host']}:{peer_data['port']}/get_peers"
                success, peers_data = await self.send_with_retry(url, {}, method="get")
                if success and peers_data:
                    for peer in peers_data:
                        if (peer["host"], peer["port"]) != (self.host, self.port):
                            await self.add_peer(peer["peer_id"], peer["host"], peer["port"], PEER_AUTH_SECRET())
                else:
                    logger.warning(f"Peer discovery failed with {peer_id}")
                    self._increment_failure(peer_id)
            logger.info("Peer discovery cycle completed")

    async def periodic_discovery(self) -> None:
        """Run peer discovery periodically with heartbeat"""
        while not self.shutdown_flag.is_set():
            try:
                await self.discover_peers()
                await self.send_heartbeat()  # Added heartbeat
            except Exception as e:
                logger.error(f"Periodic discovery/heartbeat error: {e}")
            await asyncio.sleep(self.config["peer_discovery_interval"])

    async def add_peer(self, peer_id: str, host: str, port: int, public_key: str) -> bool:
        """Add a peer with faster announcement"""
        with self.lock:
            if len(self.peers) >= self.config["max_peers"] and peer_id not in self.peers:
                logger.debug(f"Cannot add peer {peer_id}: max peers ({self.config['max_peers']}) reached")
                return False
            if peer_id not in self.peers or self.peers[peer_id]["host"] != host or self.peers[peer_id]["port"] != port:
                self.peers[peer_id] = {
                    "host": host,
                    "port": port,
                    "public_key": public_key,
                    "failed_attempts": 0,
                    "last_seen": time.time()
                }
                logger.info(f"Added/updated peer {peer_id}: {host}:{port}")
                if time.time() - self.last_announcement > 5:  # Reduced from 10s to 5s
                    self.last_announcement = time.time()
                    await self.broadcast_peer_announcement()
                    logger.debug(f"Broadcasted peer announcement after adding {peer_id}")
                return True
            return False

    def _increment_failure(self, peer_id: str) -> None:
        """Track peer failures and remove unresponsive peers."""
        self.peer_failures[peer_id] += 1
        PEER_FAILURES.labels(instance=self.node_id).inc()
        if self.peer_failures[peer_id] > 3:
            if peer_id in self.peers:
                del self.peers[peer_id]
                logger.info(f"Removed unresponsive peer {peer_id} after {self.peer_failures[peer_id]} failures")
                self._save_peers()
            del self.peer_failures[peer_id]

    async def request_chain(self):
        """Request chain incrementally"""
        if not self.peers:
            return False
        
        our_height = len(self.blockchain.chain) - 1
        our_difficulty = self.blockchain.get_total_difficulty()
        best_chain = None
        best_difficulty = our_difficulty
        best_peer = None
        
        for peer_id, peer_data in self.peers.items():
            try:
                url = f"https://{peer_data['host']}:{peer_data['port']}/get_chain?since={our_height}"
                success, chain_data = await asyncio.wait_for(self.send_with_retry(url, {}, method="get"), timeout=10)
                if not success or not chain_data:
                    continue
                
                new_chain = [Block.from_dict(block) for block in chain_data]
                if not new_chain:
                    continue
                
                new_difficulty = sum(block.difficulty for block in new_chain) + our_difficulty
                if len(new_chain) > 0 and new_difficulty > best_difficulty:
                    if await self.blockchain.is_valid_chain(self.blockchain.chain + new_chain):
                        best_chain = new_chain
                        best_difficulty = new_difficulty
                        best_peer = peer_id
            except asyncio.TimeoutError:
                self._increment_failure(peer_id)
        
        if best_chain:
            logger.info(f"Appending {len(best_chain)} blocks from {best_peer}")
            for block in best_chain:
                await self.blockchain.add_block(block)
            return True
        return False

    async def sync_and_discover(self) -> None:
        """Perform a full sync and discovery cycle."""
        try:
            logger.debug("Starting sync and discovery cycle")
            self.blockchain.difficulty = self.blockchain.adjust_difficulty()
            await self.discover_peers()
            await self.request_chain()
            await self.broadcast_peer_announcement()
            logger.debug("Sync and discovery cycle completed")
        except Exception as e:
            logger.error(f"Sync and discovery error: {e}")

    async def start_periodic_sync(self, interval=30):
        """Start periodic chain synchronization with proper shutdown handling"""
        logger.info(f"Starting periodic chain sync with interval {interval} seconds")
        
        async def sync_loop():
            while not self.shutdown_flag.is_set():
                try:
                    await asyncio.wait_for(self.request_chain(), timeout=interval/2)  # Limit each request duration
                    await asyncio.sleep(interval)
                except asyncio.TimeoutError:
                    logger.warning("Chain sync request timed out")
                except asyncio.CancelledError:
                    logger.info("Periodic sync loop cancelled")
                    break
                except Exception as e:
                    logger.error(f"Error in periodic sync: {e}", exc_info=True)
                    await asyncio.sleep(5)  # Short delay before retry
        
        self.sync_task = asyncio.create_task(sync_loop())
        self.background_tasks.append(self.sync_task)
        return self.sync_task

    def _handle_task_result(self, task: asyncio.Task) -> None:
        """Handle task completion and log exceptions."""
        try:
            task.result()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Task failed: {e}")

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Thread-safe connection handling"""
        with self.lock:
            peer_address = writer.get_extra_info('peername')
            client_ip = peer_address[0] if peer_address else 'unknown'
            
            try:
                # Check security monitor if available
                if self.security_monitor and not await self.security_monitor.monitor_connection(client_ip):
                    logger.warning(f"Connection rejected from {client_ip} by security monitor")
                    writer.close()
                    await writer.wait_closed()
                    return

                logger.info(f"New connection from {client_ip}")

                # Read first chunk of data to detect protocol
                initial_data = await reader.read(1024)
                if not initial_data:
                    logger.warning(f"Empty initial data from {client_ip}")
                    return
                    
                # Check if this looks like an HTTP request
                if initial_data.startswith(b'GET') or initial_data.startswith(b'POST') or initial_data.startswith(b'PUT'):
                    logger.warning(f"Received HTTP request on P2P port from {client_ip}. This connection should go to the HTTP server.")
                    response = b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nThis is a P2P socket server, not an HTTP server."
                    writer.write(response)
                    await writer.drain()
                    return
                
                while not self.shutdown_flag.is_set():
                    try:
                        # Read message length first (4 bytes)
                        length_data = await reader.read(4)
                        if not length_data:
                            break
                        
                        message_length = int.from_bytes(length_data, 'big')
                        
                        # Read the actual message
                        data = await reader.read(message_length)
                        if not data:
                            break
                        
                        try:
                            # Decode as JSON
                            message = json.loads(data.decode('utf-8'))
                            await self.handle_message(message, client_ip)
                        except json.JSONDecodeError:
                            logger.error(f"Received invalid JSON message from {client_ip}: {data[:100]}...")  # Log first 100 bytes
                            if self.security_monitor:
                                await self.security_monitor.record_failed_attempt(client_ip, 'invalid_message')
                            continue  # Skip invalid messages instead of breaking
                        
                        # Send acknowledgment
                        ack = "ACK".encode('utf-8')
                        writer.write(len(ack).to_bytes(4, 'big') + ack)
                        await writer.drain()
                        
                    except Exception as e:
                        logger.error(f"Error handling connection from {client_ip}: {e}", exc_info=True)
                        if self.security_monitor:
                            await self.security_monitor.record_failed_attempt(client_ip, 'connection_error')
                        break
                        
            except Exception as e:
                logger.error(f"Connection error from {client_ip}: {e}", exc_info=True)
                if self.security_monitor:
                    await self.security_monitor.record_failed_attempt(client_ip, 'connection_error')
            
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                    logger.info(f"Connection closed from {client_ip}")
                except Exception as e:
                    logger.error(f"Error closing connection from {client_ip}: {e}")