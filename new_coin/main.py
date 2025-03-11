import threading
import signal
import sys
import asyncio
import ssl
from blockchain import Blockchain
from network import BlockchainNetwork
from gui import BlockchainGUI
from utils import find_available_port, PEER_AUTH_SECRET, SSL_CERT_PATH, SSL_KEY_PATH
from prometheus_client import start_http_server
import logging
import aiohttp
import argparse
import os
import yaml

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger = logging.getLogger("Blockchain")
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Load CONFIG from config.yaml
with open("config.yaml", "r") as f:
    CONFIG = yaml.safe_load(f)

async def health_check(host: str, port: int, retries: int = 5, delay: float = 1.0) -> bool:
    client_ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    client_ssl_context.check_hostname = False
    client_ssl_context.verify_mode = ssl.CERT_NONE
    headers = {"Authorization": f"Bearer {PEER_AUTH_SECRET}"}
    for attempt in range(retries):
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://{host}:{port}/get_chain"
                logger.info(f"Attempting health check {attempt + 1}/{retries} on {url}")
                async with session.get(url, headers=headers, ssl=False) as resp:
                    logger.info(f"Health check response: {resp.status}")
                    return resp.status == 200
        except Exception as e:
            logger.warning(f"Health check attempt {attempt + 1} failed: {e}")
            if attempt < retries - 1:
                await asyncio.sleep(delay)
    logger.error("All health check attempts failed")
    return False

def shutdown(sig, frame, gui: BlockchainGUI, network: BlockchainNetwork):
    logger.info("Shutting down...")
    gui.miner.stop_mining()
    gui.root.quit()
    if network.loop and not network.loop.is_closed():
        if network.sync_task:
            network.sync_task.cancel()
        network.loop.call_soon_threadsafe(network.loop.stop)
    sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run a blockchain node.")
    parser.add_argument("--port", type=int, default=None, help="Port to run the node on")
    parser.add_argument("--bootstrap", type=str, default=None, help="Comma-separated list of bootstrap nodes (host:port)")
    args = parser.parse_args()

    port = args.port if args.port else find_available_port()
    node_id = f"node{port}"
    logger.info(f"Initializing blockchain and network on port {port}")
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