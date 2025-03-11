import aiohttp
import aiohttp.web
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
        for peer_id, (host, port) in list(self.peers.items()):
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
        for peer_id, (host, port) in list(self.peers.items()):
            try:
                async with aiohttp.ClientSession() as session:
                    url = f"https://{host}:{port}/receive_transaction"
                    headers = {"Authorization": f"Bearer {PEER_AUTH_SECRET}"}
                    async with session.post(url, json=transaction.to_dict(), headers=headers, ssl=self.ssl_context) as resp:
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
        try:
            vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.SECP256k1)
            if not vk.verify(signature, message):
                logger.warning(f"Peer {peer_id} failed signature verification")
                return aiohttp.web.Response(status=403)
        except Exception as e:
            logger.warning(f"Peer {peer_id} failed signature verification: {e}")
            return aiohttp.web.Response(status=403)

        # Call add_peer with public_key instead of shared_secret
        await self.add_peer(peer_id, host, int(port), public_key)
        self._save_peers()
        logger.info(f"Authenticated peer {peer_id} via signature")
        return aiohttp.web.Response(status=200)

    async def broadcast_peer_announcement(self):
        sk = ecdsa.SigningKey.from_string(bytes.fromhex(self.private_key), curve=ecdsa.SECP256k1)
        for peer_id, (host, port, _) in list(self.peers.items()):
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
        peer_list = [{"peer_id": pid, "host": host, "port": port} for pid, (host, port) in self.peers.items() if (host, port) != (self.host, self.port)]
        random.shuffle(peer_list)
        return aiohttp.web.json_response(peer_list[:min(CONFIG["max_peers"], len(peer_list))])

    async def discover_peers(self):
        for host, port in self.bootstrap_nodes:
            if (host, port) != (self.host, self.port):
                peer_id = f"node{port}"
                url = f"https://{host}:{port}/get_chain"
                success, _ = await self.send_with_retry(url, {}, method="get")
                if success:
                    await self.add_peer(peer_id, host, port, PEER_AUTH_SECRET)
                else:
                    logger.info(f"Skipping unresponsive bootstrap node {peer_id} at {host}:{port}")

        if self.peers:
            peer_id, (host, port) = random.choice(list(self.peers.items()))
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
        logger.info("Initial peer discovery completed")

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
        for peer_id, (host, port) in list(self.peers.items()):
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

    def start_periodic_sync(self):
        async def sync_and_discover():
            logger.info("Starting periodic sync and discovery loop")
            await self.discover_peers()
            logger.info("Initial peer discovery completed")
            self.discovery_task = self.loop.create_task(self.periodic_discovery())
            while True:
                logger.info("Sync loop iteration starting")
                self.blockchain.difficulty = self.blockchain.adjust_difficulty()
                await self.request_chain()
                await self.broadcast_peer_announcement()
                logger.info("Sync loop iteration completed")
                await asyncio.sleep(CONFIG["sync_interval"])

        self.sync_task = self.loop.create_task(sync_and_discover())
        return sync_and_discover()

    async def periodic_discovery(self):
        while True:
            await self.discover_peers()
            if not self.peers and time.time() - self.start_time > 300:
                logger.warning("Network isolated: no peers detected for 5 minutes")
            await asyncio.sleep(CONFIG["peer_discovery_interval"])