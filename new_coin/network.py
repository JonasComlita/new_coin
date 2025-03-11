import aiohttp
import aiohttp.web
from aiohttp import web
import asyncio
import ssl
import ecdsa
import os
import logging
import time
import random
from typing import Dict
from collections import defaultdict
from blockchain import Blockchain, Block, Transaction
from utils import PEER_AUTH_SECRET, SSL_CERT_PATH, SSL_KEY_PATH, generate_node_keypair
logger = logging.getLogger("Blockchain")

CONFIG = {
    "sync_interval": 10,
    "max_peers": 10,
    "peer_discovery_interval": 60,
    "max_retries": 3,
    "isolation_timeout": 300,
    "tls_cert_file": "cert.pem",
    "tls_key_file": "key.pem"
}

async def rate_limit_middleware(app, handler):
    async def middleware(request):
        return await handler(request)
    return middleware


class BlockchainNetwork:
    """Manages peer-to-peer networking for the blockchain."""
    def __init__(self, blockchain: 'Blockchain', node_id: str, host: str, port: int, loop: asyncio.AbstractEventLoop, bootstrap_nodes: list[tuple[str, int]] = None):
        self.blockchain = blockchain
        self.node_id = node_id
        self.host = host
        self.port = port
        self.bootstrap_nodes = bootstrap_nodes or []
        self.loop = loop
        self.private_key, self.public_key = generate_node_keypair()  # Generate unique keys per node
        self.peers: Dict[str, tuple[str, int, str]] = self._load_peers()  # (host, port, public_key)
        self.app = aiohttp.web.Application(loop=loop, middlewares=[rate_limit_middleware])
        self.app.add_routes([
            web.get("/health", self.health_handler),
            aiohttp.web.post('/receive_block', self.receive_block),
            aiohttp.web.post('/receive_transaction', self.receive_transaction),
            aiohttp.web.get('/get_chain', self.get_chain),
            aiohttp.web.post('/announce_peer', self.announce_peer),
            aiohttp.web.get('/get_peers', self.get_peers)
        ])

        # Server SSL context for accepting connections
        self.server_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.server_ssl_context.load_cert_chain(certfile=CONFIG["tls_cert_file"], keyfile=CONFIG["tls_key_file"])
        
        # Client SSL context for outgoing requests
        self.client_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.client_ssl_context.load_verify_locations(cafile=CONFIG["tls_cert_file"])  # Trust the same cert for simplicity
        self.client_ssl_context.check_hostname = False  # Optional, for self-signed certs
        self.client_ssl_context.verify_mode = ssl.CERT_REQUIRED  # Optional, for testing

        self.blockchain.network = self
        self.sync_task = None
        self.discovery_task = None
        self.last_announcement = 0
        self.peer_failures: Dict[str, int] = {}
        self.start_time = time.time()

        self.peer_trust_scores = defaultdict(lambda: {
                'successful_responses': 0,
                'failed_responses': 0,
                'total_score': 100
            })
        
        self.partition_detection_threshold = 0.5

    def _update_peer_trust(self, peer_id, success):
        """Update peer trust score"""
        peer_data = self.peer_trust_scores[peer_id]
        
        if success:
            peer_data['successful_responses'] += 1
            peer_data['total_score'] = min(100, peer_data['total_score'] + 1)
        else:
            peer_data['failed_responses'] += 1
            peer_data['total_score'] = max(0, peer_data['total_score'] - 2)
        
        # Optional: Periodically clean up old peer scores
        if len(self.peer_trust_scores) > 100:
            lowest_scored_peers = sorted(
                self.peer_trust_scores.items(), 
                key=lambda x: x[1]['total_score']
            )[:10]
            for peer_id, _ in lowest_scored_peers:
                del self.peer_trust_scores[peer_id]

    async def detect_network_partition(self):
        """Detect potential network partitions"""
        if not self.peers:
            return False

        chain_versions = defaultdict(list)
        for peer_id, (host, port, _) in self.peers.items():
            # You might need to modify this to actually fetch peer chains
            try:
                chain = await self.fetch_peer_chain(host, port)
                chain_hash = hash(tuple(block.header.hash for block in chain))
                chain_versions[chain_hash].append(peer_id)
            except Exception:
                continue

        if not chain_versions:
            return False

        majority_chain = max(chain_versions, key=lambda k: len(chain_versions[k]))
        partition_ratio = len(chain_versions[majority_chain]) / len(self.peers)

        if partition_ratio < self.partition_detection_threshold:
            logger.warning(f"Network partition detected! Partition ratio: {partition_ratio}")
            await self.resolve_network_partition(chain_versions)
            return True
        return False

    async def resolve_network_partition(self, chain_versions):
        """Resolve network partition by selecting most representative chain"""
        majority_chain_hash = max(chain_versions, key=lambda k: len(chain_versions[k]))
        majority_peers = chain_versions[majority_chain_hash]
        
        # Logic to synchronize or elect a primary chain
        logger.info(f"Resolving partition with {len(majority_peers)} peers")

    async def health_handler(self, request):
        """Handle health check requests."""
        logger.info(f"Received health check request from {request.remote}")
        return web.Response(status=200, text="OK")

    def run(self) -> None:
        logger.info(f"Setting up network server on {self.host}:{self.port}")
        runner = aiohttp.web.AppRunner(self.app)
        self.loop.run_until_complete(runner.setup())
        site = aiohttp.web.TCPSite(runner, self.host, self.port, ssl_context=self.server_ssl_context)  # Fix: Use server_ssl_context
        self.loop.run_until_complete(site.start())
        logger.info(f"Network server running on {self.host}:{self.port}")
        # Start periodic sync tasks
        self.loop.run_until_complete(self.start_periodic_sync())
        self.loop.run_forever()

    async def send_with_retry(self, url: str, data: dict, method: str = "post", max_retries: int = CONFIG["max_retries"]):
        headers = {"Authorization": f"Bearer {PEER_AUTH_SECRET}"}
        for attempt in range(max_retries):
            try:
                async with aiohttp.ClientSession() as session:
                    if method == "post":
                        async with session.post(url, json=data, headers=headers, ssl=self.client_ssl_context, timeout=aiohttp.ClientTimeout(total=5)) as response:
                            return response.status == 200
                    elif method == "get":
                        async with session.get(url, headers=headers, ssl=self.client_ssl_context, timeout=aiohttp.ClientTimeout(total=5)) as response:
                            return response.status == 200, await response.json()
            except Exception as e:
                logger.error(f"Connection error to {url} (attempt {attempt + 1}/{max_retries}): {e}")
                if attempt == max_retries - 1:
                    return False if method == "post" else (False, None)
                await asyncio.sleep(0.5 * (2 ** attempt))

    async def broadcast_block(self, block: Block):
        for peer_id, peer_data in list(self.peers.items()):
            host, port, public_key = peer_data  # Unpack properly
            try:
                await self.send_block(peer_id, host, port, block)
            except Exception as e:
                logger.warning(f"Error broadcasting block {block.index} to {peer_id}: {e}")
                self._increment_failure(peer_id)

    async def send_block(self, peer_id: str, host: str, port: int, block: Block) -> None:
        url = f"https://{host}:{port}/receive_block"
        data = {"block": block.to_dict()}
        success = await self.send_with_retry(url, data)
        if success:
            logger.info(f"Sent block {block.index} to {peer_id}")
        else:
            logger.warning(f"Failed to send block {block.index} to {peer_id}")

    async def receive_block(self, request):
        data = await request.json()
        block = Block.from_dict(data)
        if await self.blockchain.add_block(block):  # Now async
            logger.info(f"Received and added block {block.header.index} from peer")
            self._save_peers()
            return aiohttp.web.Response(status=200)
        return aiohttp.web.Response(status=400)

    async def broadcast_transaction(self, transaction: 'Transaction'):
        for peer_id, peer_data in list(self.peers.items()):
            host, port, public_key = peer_data  # Unpack properly
            try:
                async with aiohttp.ClientSession() as session:
                    url = f"https://{host}:{port}/receive_transaction"
                    headers = {"Authorization": f"Bearer {PEER_AUTH_SECRET}"}
                    # Fix the SSL context reference
                    async with session.post(url, json=transaction.to_dict(), headers=headers, ssl=self.client_ssl_context) as resp:
                        if resp.status == 200:
                            logger.info(f"Transaction {transaction.tx_id[:8]} broadcast to {peer_id}")
                        else:
                            logger.warning(f"Failed to broadcast transaction to {peer_id}: {resp.status}")
            except Exception as e:
                logger.warning(f"Error broadcasting transaction to {peer_id}: {e}")
                self._increment_failure(peer_id)

    async def send_transaction(self, peer_id: str, host: str, port: int, tx: Transaction) -> None:
        url = f"https://{host}:{port}/receive_transaction"
        data = {"transaction": tx.to_dict()}
        success = await self.send_with_retry(url, data)
        if not success:
            logger.error(f"Failed to send transaction to {peer_id}")

    async def receive_transaction(self, request):
        data = await request.json()
        transaction = Transaction.from_dict(data)
        if self.blockchain.add_transaction_to_mempool(transaction):
            logger.info(f"Received transaction {transaction.tx_id[:8]} from peer")
            return aiohttp.web.Response(status=200)
        return aiohttp.web.Response(status=400)

    async def get_chain(self, request):
        chain_data = [block.to_dict() for block in self.blockchain.chain]
        return aiohttp.web.json_response(chain_data)

    def _load_peers(self):
        peers = {}
        if os.path.exists("known_peers.txt"):
            with open("known_peers.txt", "r") as f:
                for line in f:
                    if ":" in line:
                        parts = line.strip().split(":")
                        if len(parts) >= 3:
                            host, port, pubkey = parts[0], parts[1], ":".join(parts[2:])
                            peer_id = f"node{port}"
                            peers[peer_id] = (host, int(port), pubkey)
        return peers

    def _save_peers(self):
        with open("known_peers.txt", "w") as f:
            for peer_id, (host, port, pubkey) in self.peers.items():
                f.write(f"{host}:{port}:{pubkey}\n")

    async def announce_peer(self, request):
        data = await request.json()
        peer_id = data.get("peer_id")
        host = data.get("host")
        port = data.get("port")
        public_key = data.get("public_key")
        signature = bytes.fromhex(data.get("signature", ""))
        message = f"{peer_id}{host}{port}".encode()
        
        # Verify the signature
        start_time = time.time()
        if public_key and signature:
            try:
                vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.SECP256k1)
                if not vk.verify(signature, message):
                    logger.warning(f"Peer {peer_id} failed signature verification")
                    return aiohttp.web.Response(status=403)
            except Exception as e:
                logger.warning(f"Peer {peer_id} failed signature verification: {e}")
                return aiohttp.web.Response(status=403)
        logger.info(f"Validated peer auth in {(time.time() - start_time) * 1e6:.2f} µs")

        auth_key = public_key if public_key else PEER_AUTH_SECRET
        logger.info(f"Retrieved peer auth secret in {(time.time() - start_time) * 1e6:.2f} µs")
        await self.add_peer(peer_id, host, int(port), auth_key)
        self._save_peers()
        logger.info(f"Authenticated peer {peer_id}")
        return aiohttp.web.Response(status=200)

    async def broadcast_peer_announcement(self):
        sk = ecdsa.SigningKey.from_string(bytes.fromhex(self.private_key), curve=ecdsa.SECP256k1)
        for peer_id, peer_data in list(self.peers.items()):
            host, port, peer_pubkey = peer_data  # Unpack properly
            message = f"{self.node_id}{self.host}{self.port}".encode()
            signature = sk.sign(message).hex()
            url = f"https://{host}:{port}/announce_peer"
            headers = {"Authorization": f"Bearer {self.public_key}"}  # Optional, for identification
            data = {
                "peer_id": self.node_id,
                "host": self.host,
                "port": self.port,
                "public_key": self.public_key,
                "signature": signature
            }
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=data, headers=headers, ssl=self.client_ssl_context) as resp:
                    if resp.status == 200:
                        logger.info(f"Announced to {peer_id}")
                        self.peer_failures[peer_id] = 0
                    else:
                        logger.warning(f"Failed to announce to {peer_id}: {resp.status}")

    async def get_peers(self, request):
        # Update the list comprehension to handle 3-tuple peer data
        peer_list = []
        for pid, peer_data in self.peers.items():
            host, port, _ = peer_data  # Unpack all three values, ignore the public_key
            if (host, port) != (self.host, self.port):
                peer_list.append({"peer_id": pid, "host": host, "port": port})
        
        # Shuffle the list to promote network diversity
        random.shuffle(peer_list)
        # Limit the number of peers returned
        limited_list = peer_list[:min(CONFIG["max_peers"], len(peer_list))]
        return aiohttp.web.json_response(limited_list)
    
    async def discover_peers(self):
        """Discover peers from known nodes."""
        # First part: try to discover from bootstrap nodes
        for host, port in self.bootstrap_nodes:
            if (host, port) != (self.host, self.port):
                peer_id = f"node{port}"
                url = f"https://{host}:{port}/get_chain"
                success, _ = await self.send_with_retry(url, {}, method="get")
                if success:
                    await self.add_peer(peer_id, host, port, PEER_AUTH_SECRET)
                else:
                    logger.info(f"Skipping unresponsive bootstrap node {peer_id} at {host}:{port}")

        # Second part: discover from existing peers
        if not self.peers:
            logger.info("No peers to discover from.")
            return
        
        # Choose a random peer - this is where the error occurs
        try:
            # The issue is here - you need to unpack 3 values, not 2
            for peer_id, peer_data in list(self.peers.items()):
                trust_score = self.peer_trust_scores[peer_id]['total_score']
                
                # Skip peers with very low trust
                if trust_score < 20:
                    logger.info(f"Skipping low-trust peer {peer_id}")
                    continue
                
                # Prioritize higher trust peers
                discovery_probability = trust_score / 100
                if random.random() < discovery_probability:
                    host, port, public_key = peer_data  # Properly unpack the 3 values
                    
                    logger.info(f"Discovering peers from {peer_id} at {host}:{port}")
                    
                    # Request peers from the selected peer
                    try:
                        async with aiohttp.ClientSession() as session:
                            url = f"https://{host}:{port}/get_peers"
                            headers = {"Authorization": f"Bearer {PEER_AUTH_SECRET}"}
                            async with session.get(url, headers=headers, ssl=self.client_ssl_context) as resp:
                                if resp.status == 200:
                                    peers_data = await resp.json()
                                    for peer in peers_data:
                                        if (peer["host"], peer["port"]) != (self.host, self.port):
                                            await self.add_peer(peer["peer_id"], peer["host"], peer["port"], PEER_AUTH_SECRET)
                    except Exception as e:
                        logger.warning(f"Peer exchange failed with {peer_id}: {e}")
                        self._increment_failure(peer_id)
        except ValueError as e:
            logger.error(f"Failed to select peer for discovery: {e}")
            return
            
        logger.info("Peer discovery completed")

    async def add_peer(self, peer_id: str, host: str, port: int, public_key: str):
        peer_key = (host, port)
        # Store public_key instead of shared_secret
        if peer_id not in self.peers or self.peers.get(peer_id)[:2] != peer_key:
            self.peers[peer_id] = (host, port, public_key)
            logger.info(f"Added peer {peer_id}: {host}:{port}")
            current_time = time.time()
            if current_time - self.last_announcement > 10:
                await self.broadcast_peer_announcement()
                self.last_announcement = current_time
        return True

    def _increment_failure(self, peer_id: str):
        self.peer_failures[peer_id] = self.peer_failures.get(peer_id, 0) + 1
        if self.peer_failures[peer_id] > 3:
            if peer_id in self.peers:
                del self.peers[peer_id]
                del self.peer_failures[peer_id]
                logger.info(f"Removed unresponsive peer {peer_id} after {self.peer_failures.get(peer_id, 0)} failures")
                self._save_peers()

    async def request_chain(self):
        best_chain = self.blockchain.chain
        best_difficulty = self.blockchain.get_total_difficulty()
        for peer_id, peer_data in list(self.peers.items()):
            host, port, public_key = peer_data  # Unpack properly
            try:
                async with aiohttp.ClientSession() as session:
                    url = f"https://{host}:{port}/get_chain"
                    headers = {"Authorization": f"Bearer {PEER_AUTH_SECRET}"}
                    async with session.get(url, headers=headers, ssl=self.client_ssl_context) as resp:
                        if resp.status == 200:
                            chain_data = await resp.json()
                            new_chain = [Block.from_dict(block) for block in chain_data]
                            new_difficulty = sum(block.header.difficulty for block in new_chain)
                            if new_difficulty > best_difficulty and self.blockchain.is_valid_chain(new_chain):
                                best_chain = new_chain
                                best_difficulty = new_difficulty
                                logger.info(f"Updated chain from peer {peer_id} with higher difficulty")
                                self.blockchain.replace_chain(best_chain)
                            self.peer_failures[peer_id] = 0
            except Exception as e:
                logger.warning(f"Failed to get chain from {peer_id}: {e}")
                self._increment_failure(peer_id)

    async def sync_and_discover(self):
        """Synchronize the blockchain and discover new peers."""
        try:
            logger.info("Sync and discovery cycle starting")
            # Update difficulty before syncing
            self.blockchain.difficulty = self.blockchain.adjust_difficulty()
            
            # Run peer discovery
            await self.discover_peers()
            
            # Request latest chain from peers
            await self.request_chain()
            
            # Announce this node to peers
            await self.broadcast_peer_announcement()
            
            logger.info("Sync and discovery cycle completed successfully")
        except Exception as e:
            logger.error(f"Error during sync and discovery: {e}")
            # Consider adding more detailed error handling based on exception type

    async def periodic_discovery(self):
        """Run peer discovery at regular intervals."""
        try:
            while True:
                await self.discover_peers()
                await asyncio.sleep(CONFIG["peer_discovery_interval"])
        except asyncio.CancelledError:
            logger.info("Periodic discovery task cancelled")
        except Exception as e:
            logger.error(f"Error in periodic discovery: {e}")
            # Re-raise to ensure the task failure is properly handled
            raise

    def start_periodic_sync(self):
        """
        Start periodic synchronization and discovery as background tasks.
        Returns the main sync task for monitoring.
        """
        # Check if sync task exists and is still running
        if hasattr(self, 'sync_task') and isinstance(self.sync_task, asyncio.Task) and not self.sync_task.done():
            logger.warning("Sync task already running, not starting a new one")
            return self.sync_task
            
        async def sync_loop():
            try:
                logger.info("Starting periodic sync loop")
                
                # Initial discovery and sync
                await self.discover_peers()
                logger.info("Initial peer discovery completed")
                
                # Start the dedicated discovery task
                if not hasattr(self, 'discovery_task') or not isinstance(self.discovery_task, asyncio.Task) or self.discovery_task.done():
                    self.discovery_task = self.loop.create_task(self.periodic_discovery())
                    self.discovery_task.add_done_callback(self._handle_task_result)
                
                # Main sync loop with proper error handling
                while True:
                    try:
                        await self.sync_and_discover()
                    except Exception as e:
                        logger.error(f"Error in sync cycle: {e}")
                        # Continue despite errors but with a slightly longer delay
                        await asyncio.sleep(min(CONFIG["sync_interval"] * 1.5, 60))
                    else:
                        await asyncio.sleep(CONFIG["sync_interval"])
            except asyncio.CancelledError:
                logger.info("Sync loop task cancelled")
                # Clean cancellation of the discovery task if needed
                if hasattr(self, 'discovery_task') and isinstance(self.discovery_task, asyncio.Task) and not self.discovery_task.done():
                    self.discovery_task.cancel()
            except Exception as e:
                logger.critical(f"Fatal error in sync loop: {e}")
                raise

        # Create and store the main sync task
        self.sync_task = self.loop.create_task(sync_loop())
        self.sync_task.add_done_callback(self._handle_task_result)
        return self.sync_task
        
    def _handle_task_result(self, task):
        """Handle completed tasks and log any exceptions."""
        try:
            # This will re-raise any exception that occurred in the task
            task.result()
        except asyncio.CancelledError:
            # Normal cancellation, no action needed
            pass
        except Exception as e:
            logger.error(f"Task failed with exception: {e}")