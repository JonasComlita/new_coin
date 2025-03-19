"""
HTTP API endpoints for blockchain network communication.
"""

import logging
import json
import time
from aiohttp import web
from typing import Dict, List, Tuple
import ecdsa

from blockchain import Block, Transaction
from utils import validate_peer_auth, SecurityUtils, BLOCKS_RECEIVED, TXS_BROADCAST

logger = logging.getLogger("NetworkAPI")

def setup_api_routes(network):
    """Configure HTTP routes for the network."""
    network.app.add_routes([
        web.get("/health", health_handler(network)),
        web.post('/receive_block', receive_block(network)),
        web.post('/receive_transaction', receive_transaction(network)),
        web.get('/get_chain', get_chain(network)),
        web.post('/announce_peer', announce_peer(network)),
        web.get('/get_peers', get_peers(network)),
        web.post('/heartbeat', heartbeat_handler(network))
    ])

def health_handler(network):
    """Handle health check requests."""
    async def handler(request: web.Request) -> web.Response:
        logger.debug(f"Health check from {request.remote}")
        return web.Response(status=200, text="OK")
    return handler

def receive_block(network):
    """Handle incoming block from a peer with msgpack support"""
    async def handler(request: web.Request) -> web.Response:
        if not validate_peer_auth(request.headers.get("Authorization", "").replace("Bearer ", "")):
            return web.Response(status=403, text="Invalid authentication")
        try:
            # Support both msgpack and JSON
            content_type = request.headers.get("Content-Type", "")
            
            if content_type == "application/msgpack":
                # Read raw data and deserialize with msgpack
                from utils import deserialize
                raw_data = await request.read()
                data = deserialize(raw_data)
            else:
                # Fall back to JSON for backward compatibility
                data = await request.json()
                
            block = Block.from_dict(data["block"])
            if await network.blockchain.add_block(block):
                logger.info(f"Received and added block {block.index} from {request.remote}")
                network._save_peers()
                return web.Response(status=200)
            return web.Response(status=400, text="Block validation failed")
        except Exception as e:
            logger.error(f"Error receiving block: {e}")
            return web.Response(status=400, text=str(e))
    return handler

def receive_transaction(network):
    """Handle incoming transaction with nonce check"""
    async def handler(request: web.Request) -> web.Response:
        peer_id = request.headers.get("Node-ID")
        signature = request.headers.get("Signature")
        if not peer_id or not signature or peer_id not in network.peers:
            return web.Response(status=403, text="Invalid authentication")
        
        data = await request.json()
        message = json.dumps(data["transaction"]).encode()
        vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(network.peers[peer_id]["public_key"]), curve=ecdsa.SECP256k1)
        if not vk.verify(bytes.fromhex(signature), message):
            return web.Response(status=403, text="Invalid signature")

        tx = Transaction.from_dict(data["transaction"])
        address = SecurityUtils.public_key_to_address(tx.inputs[0].public_key) if tx.inputs else tx.sender
        if await network.nonce_tracker.is_nonce_used(address, tx.nonce):
            network.peer_reputation.update_reputation(peer_id, 'invalid_transaction')
            return web.Response(status=400, text="Nonce already used")
        
        if await network.blockchain.add_transaction_to_mempool(tx):
            await network.nonce_tracker.add_nonce(address, tx.nonce, len(network.blockchain.chain))
            logger.info(f"Received transaction {tx.tx_id[:8]} from {peer_id}")
            return web.Response(status=200)
        return web.Response(status=400, text="Transaction validation failed")
    return handler

def get_chain(network):
    """Return chain incrementally"""
    async def handler(request: web.Request) -> web.Response:
        since = int(request.query.get("since", -1))
        chain_data = [block.to_dict() for block in network.blockchain.chain[since + 1:]]
        return web.json_response(chain_data)
    return handler

def announce_peer(network):
    """Handle peer announcement from another node."""
    async def handler(request: web.Request) -> web.Response:
        if not validate_peer_auth(request.headers.get("Authorization", "").replace("Bearer ", "")):
            return web.Response(status=403, text="Invalid authentication")
        try:
            data = await request.json()
            peer_id = data.get("peer_id")
            host = data.get("host")
            port = int(data.get("port"))
            public_key = data.get("public_key")
            signature = bytes.fromhex(data.get("signature", ""))
            message = f"{peer_id}{host}{port}".encode()

            if public_key and signature:
                vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.SECP256k1)
                if not vk.verify(signature, message):
                    logger.warning(f"Peer {peer_id} failed signature verification")
                    return web.Response(status=403, text="Invalid signature")

            await network.add_peer(peer_id, host, port, public_key)
            network._save_peers()
            logger.info(f"Authenticated and added peer {peer_id} from {request.remote}")
            return web.Response(status=200)
        except Exception as e:
            logger.error(f"Error in peer announcement: {e}")
            return web.Response(status=400, text=str(e))
    return handler

def get_peers(network):
    """Return a list of known peers to a requesting node."""
    async def handler(request: web.Request) -> web.Response:
        if not validate_peer_auth(request.headers.get("Authorization", "").replace("Bearer ", "")):
            return web.Response(status=403, text="Invalid authentication")
        peer_list = [
            {"peer_id": pid, "host": peer_data["host"], "port": peer_data["port"]}
            for pid, peer_data in network.peers.items()
            if (peer_data["host"], peer_data["port"]) != (network.host, network.port)
        ]
        import random
        random.shuffle(peer_list)
        limited_list = peer_list[:min(network.config["max_peers"], len(peer_list))]
        return web.json_response(limited_list)
    return handler

def heartbeat_handler(network):
    """Handle incoming heartbeat"""
    async def handler(request: web.Request) -> web.Response:
        if not validate_peer_auth(request.headers.get("Authorization", "").replace("Bearer ", "")):
            return web.Response(status=403, text="Invalid authentication")
        data = await request.json()
        peer_id = data.get("node_id")
        if peer_id in network.peers:
            network.peers[peer_id]["last_seen"] = time.time()
            logger.debug(f"Received heartbeat from {peer_id}")
        return web.Response(status=200)
    return handler