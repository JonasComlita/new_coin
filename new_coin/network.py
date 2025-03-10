import aiohttp
import aiohttp.web
import asyncio
import ssl
import os
import logging
from time import time
from typing import Dict
from collections import defaultdict
from blockchain import Blockchain, Block, Transaction
from utils import CONFIG, PEER_AUTH_SECRET, SSL_CERT_PATH, SSL_KEY_PATH

logger = logging.getLogger("Blockchain")

@aiohttp.web.middleware
async def rate_limit_middleware(request, handler):
    client_ip = request.remote
    rate_limit = 100
    window = 60
    if not hasattr(request.app, 'request_timestamps'):
        request.app.request_timestamps = defaultdict(list)
    timestamps = request.app.request_timestamps[client_ip]
    current_time = time()
    timestamps[:] = [t for t in timestamps if current_time - t < window]
    if len(timestamps) >= rate_limit:
        logger.warning(f"Rate limit exceeded for IP {client_ip}")
        raise aiohttp.web.HTTPTooManyRequests(text="Rate limit exceeded")
    timestamps.append(current_time)
    return await handler(request)


class BlockchainNetwork:
    """Manages peer-to-peer networking for the blockchain."""
    def __init__(self, blockchain: Blockchain, node_id: str, host: str, port: int, bootstrap_nodes: list[tuple[str, int]] = None):
        self.blockchain = blockchain
        self.node_id = node_id
        self.host = host
        self.port = port
        self.peers: Dict[str, tuple[str, int]] = {}
        self.bootstrap_nodes = bootstrap_nodes or []
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.app = aiohttp.web.Application(middlewares=[rate_limit_middleware])
        self.app.add_routes([
            aiohttp.web.post('/receive_block', self.receive_block),
            aiohttp.web.post('/receive_transaction', self.receive_transaction),
            aiohttp.web.get('/get_chain', self.get_chain),
            aiohttp.web.post('/announce_peer', self.announce_peer)
        ])
        self.blockchain.network = self
        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ssl_context.load_cert_chain(SSL_CERT_PATH, SSL_KEY_PATH)

    def add_peer(self, peer_id: str, host: str, port: int, auth_key: str = None):
            if auth_key != PEER_AUTH_SECRET:
                logger.warning(f"Peer {peer_id} failed authentication")
                return False
            self.peers[peer_id] = (host, port)
            return True

    def run(self) -> None:
        runner = aiohttp.web.AppRunner(self.app)
        self.loop.run_until_complete(runner.setup())
        site = aiohttp.web.TCPSite(runner, self.host, self.port, ssl_context=self.ssl_context)
        self.loop.run_until_complete(site.start())
        self.loop.run_forever()

    async def send_with_retry(self, url: str, data: dict, method: str = "post", max_retries: int = CONFIG["max_retries"]):
        headers = {"Authorization": f"Bearer {PEER_AUTH_SECRET}"}
        for attempt in range(max_retries):
            try:
                async with aiohttp.ClientSession() as session:
                    if method == "post":
                        async with session.post(url, json=data, headers=headers, ssl=self.ssl_context, timeout=aiohttp.ClientTimeout(total=5)) as response:
                            return response.status == 200
                    elif method == "get":
                        async with session.get(url, headers=headers, ssl=self.ssl_context, timeout=aiohttp.ClientTimeout(total=5)) as response:
                            return response.status == 200, await response.json()
            except aiohttp.ClientConnectorError as e:
                logger.error(f"Connection error to {url}: {e}")
                if attempt == max_retries - 1:
                    return False if method == "post" else (False, None)
            except aiohttp.ClientSSLError as e:
                logger.error(f"SSL error: {e}")
                return False if method == "post" else (False, None)
            except Exception as e:
                logger.error(f"Unexpected error: {e}")
                if attempt == max_retries - 1:
                    return False if method == "post" else (False, None)
            await asyncio.sleep(0.5 * (2 ** attempt))

    async def receive_block(self, request: aiohttp.web.Request) -> aiohttp.web.Response:
        if request.headers.get("Authorization") != f"Bearer {PEER_AUTH_SECRET}":
            return aiohttp.web.Response(status=403, text="Unauthorized")
        data = await request.json()
        block = Block.from_dict(data["block"])
        success = await self.blockchain.add_block(block)
        if not success:
            self.blockchain.handle_potential_fork(block)
        return aiohttp.web.Response(status=200)

    async def broadcast_block(self, block: Block):
        for peer_id, (host, port) in self.peers.items():
            url = f"https://{host}:{port}/receive_block"
            await self.send_with_retry(url, {"block": block.to_dict()})

    async def broadcast_transaction(self, tx: Transaction):
        for peer_id, (host, port) in self.peers.items():
            url = f"https://{host}:{port}/receive_transaction"
            await self.send_with_retry(url, {"transaction": tx.to_dict()})

    async def send_block(self, peer_id: str, host: str, port: int, block: Block) -> None:
        url = f"http://{host}:{port}/receive_block"
        data = {"block": block.to_dict()}
        success = await self.send_with_retry(url, data)
        if success:
            logger.info(f"Sent block {block.index} to {peer_id}")
        else:
            logger.warning(f"Failed to send block {block.index} to {peer_id}")

    async def broadcast_transaction(self, tx: Transaction) -> None:
        tasks = [self.send_transaction(peer_id, host, port, tx) for peer_id, (host, port) in self.peers.items() if peer_id != self.node_id]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def send_transaction(self, peer_id: str, host: str, port: int, tx: Transaction) -> None:
        url = f"http://{host}:{port}/receive_transaction"
        data = {"transaction": tx.to_dict()}
        success = await self.send_with_retry(url, data)
        if not success:
            logger.error(f"Failed to send transaction to {peer_id}")

    async def receive_transaction(self, request: aiohttp.web.Request) -> aiohttp.web.Response:
        if request.headers.get("Authorization") != f"Bearer {PEER_AUTH_SECRET}":
            return aiohttp.web.Response(status=403, text="Unauthorized")
        data = await request.json()
        tx = Transaction.from_dict(data["transaction"])
        self.blockchain.mempool.add_transaction(tx)
        return aiohttp.web.Response(status=200)

    async def get_chain(self, request: aiohttp.web.Request) -> aiohttp.web.Response:
        if request.headers.get("Authorization") != f"Bearer {PEER_AUTH_SECRET}":
            return aiohttp.web.Response(status=403, text="Unauthorized")
        chain_data = [block.to_dict() for block in self.blockchain.chain]
        return aiohttp.web.json_response({"chain": chain_data})

    async def announce_peer(self, request: aiohttp.web.Request) -> aiohttp.web.Response:
        if request.headers.get("Authorization") != f"Bearer {PEER_AUTH_SECRET}":
            return aiohttp.web.Response(status=403, text="Unauthorized")
        data = await request.json()
        peer_id = data["node_id"]
        host = data["host"]
        port = data["port"]
        if peer_id != self.node_id and peer_id not in self.peers:
            self.peers[peer_id] = (host, port)
            logger.info(f"Added peer {peer_id} at {host}:{port}")
            await self.broadcast_peer_announcement()
        return aiohttp.web.Response(status=200)

    async def broadcast_peer_announcement(self):
        data = {"node_id": self.node_id, "host": self.host, "port": self.port}
        for peer_id, (host, port) in list(self.peers.items()):
            url = f"https://{host}:{port}/announce_peer"
            if not await self.send_with_retry(url, data):
                logger.warning(f"Failed to announce to {peer_id}, removing")
                del self.peers[peer_id]

    async def discover_peers(self):
        data = {"node_id": self.node_id, "host": self.host, "port": self.port}
        for host, port in self.bootstrap_nodes:
            url = f"https://{host}:{port}/announce_peer"
            if await self.send_with_retry(url, data):
                self.peers[f"node{port}"] = (host, port)
                logger.info(f"Connected to bootstrap node at {host}:{port}")

    def start_periodic_sync(self):
        async def sync_loop():
            await self.discover_peers()  # Initial discovery
            while True:
                await self.request_chain()
                await self.broadcast_peer_announcement()
                await asyncio.sleep(CONFIG["sync_interval"])
        asyncio.run_coroutine_threadsafe(sync_loop(), self.loop)

    async def request_chain(self):
        if self.peers:
            peer_id, (host, port) = next(iter(self.peers.items()))
            url = f"https://{host}:{port}/get_chain"
            success, data = await self.send_with_retry(url, {}, method="get")
            if success and data:
                new_chain = [Block.from_dict(b) for b in data["chain"]]
                self.blockchain.validate_and_replace_chain(new_chain)