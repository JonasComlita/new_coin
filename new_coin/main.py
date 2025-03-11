import threading
import signal
import sys
import asyncio
import ssl
import argparse
import logging
import signal
import sys
import threading
from blockchain import Blockchain
from network import BlockchainNetwork
from utils import find_available_port, init_rotation_manager, PEER_AUTH_SECRET
from gui import BlockchainGUI
import os
import aiohttp
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def health_check(host: str, port: int, retries: int = 5, delay: float = 1.0) -> bool:
    for attempt in range(retries):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://{host}:{port}/health", ssl=network.client_ssl_context) as resp:
                    if resp.status == 200:
                        return True
        except Exception as e:
            logger.warning(f"Health check failed (attempt {attempt + 1}/{retries}): {e}")
        await asyncio.sleep(delay)
    return False

def shutdown(signum, frame, gui, network):
    logger.info(f"Received signal {signum}, shutting down...")
    gui.stop()
    network.stop()
    sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run a blockchain node.")
    parser.add_argument("--port", type=int, default=None, help="Port to run the node on")
    parser.add_argument("--bootstrap", type=str, default=None, help="Comma-separated list of bootstrap nodes (host:port)")
    parser.add_argument("--validator", action="store_true", help="Run as validator node for key rotation")  # Added this
    args = parser.parse_args()

    port = args.port if args.port else find_available_port()
    api_port = port + 1000  # Offset by 1000 to avoid conflicts (e.g., 5000 -> 6000)
    node_id = f"node{port}"
    logger.info(f"Initializing blockchain on {port} and key rotation API on {api_port}")

    # Initialize KeyRotationManager
    init_rotation_manager(node_id)  # For utils.py
    from key_rotation.core import KeyRotationManager
    rotation_manager = KeyRotationManager(node_id=node_id, is_validator=args.validator)

    # Start the key rotation API in a separate thread
    from key_rotation.main import main as rotation_main
    rotation_thread = threading.Thread(
        target=rotation_main,
        args=(node_id, args.validator, api_port, "127.0.0.1"),
        daemon=True
    )
    rotation_thread.start()

    blockchain = Blockchain()
    bootstrap_nodes = []
    if args.bootstrap:
        bootstrap_nodes = [(node.split(":")[0], int(node.split(":")[1])) for node in args.bootstrap.split(",")]
    elif port != 5000 and not os.path.exists("bootstrap_nodes.txt"):
        bootstrap_nodes = [("127.0.0.1", 5000)]
    elif os.path.exists("bootstrap_nodes.txt"):
        with open("bootstrap_nodes.txt", "r") as f:
            bootstrap_nodes = [(line.strip().split(":")[0], int(line.strip().split(":")[1])) for line in f if line.strip()]

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    network = BlockchainNetwork(blockchain, node_id, "127.0.0.1", port, loop, bootstrap_nodes)
    logger.info(f"Node {node_id} public key: {network.public_key}")
    
    # Start network using BlockchainNetwork.run()
    network_thread = threading.Thread(target=network.run, daemon=True)
    network_thread.start()
    logger.info("Network thread started")

    # Wait and check network health
    logger.info("Waiting for network to initialize")
    asyncio.run(asyncio.sleep(2))
    if not asyncio.run(health_check(network.host, network.port, retries=5, delay=1.0)):
        logger.error("Health check failed after retries, exiting...")
        sys.exit(1)

    logger.info("Initializing GUI")
    gui = BlockchainGUI(blockchain, network)

    # Set up signal handlers
    signal.signal(signal.SIGINT, lambda s, f: shutdown(s, f, gui, network))
    signal.signal(signal.SIGTERM, lambda s, f: shutdown(s, f, gui, network))

    logger.info("Starting GUI main loop")
    gui.run()
    logger.info("GUI main loop exited")