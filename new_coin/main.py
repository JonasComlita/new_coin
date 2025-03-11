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

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger = logging.getLogger("Blockchain")
logger.addHandler(handler)
logger.setLevel(logging.INFO)

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
                async with session.get(url, headers=headers, ssl=client_ssl_context) as resp:
                    logger.info(f"Health check response: {resp.status}")
                    return resp.status == 200
        except Exception as e:
            logger.warning(f"Health check attempt {attempt + 1} failed: {e}")
            if attempt < retries - 1:
                await asyncio.sleep(delay)
    logger.error("All health check attempts failed")
    return False

def run_network(network: BlockchainNetwork, max_attempts: int = 3):
    for attempt in range(max_attempts):
        try:
            logger.info(f"Starting network thread (attempt {attempt + 1}/{max_attempts})")
            loop = network.loop  # Use the network's loop
            runner = aiohttp.web.AppRunner(network.app)
            loop.run_until_complete(runner.setup())
            site = aiohttp.web.TCPSite(runner, network.host, network.port, ssl_context=network.ssl_context)
            loop.run_until_complete(site.start())
            logger.info(f"Network server running on {network.host}:{network.port}")
            loop.run_forever()
            break
        except PermissionError as e:
            logger.error(f"Port binding failed: {e}")
            if attempt < max_attempts - 1:
                network.port = find_available_port()
                logger.info(f"Retrying with new port: {network.port}")
            else:
                logger.error("Max port binding attempts reached, aborting")
                raise
        except Exception as e:
            logger.error(f"Network startup failed: {e}")
            raise

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
        bootstrap_nodes = [tuple(node.split(":")) for node in args.bootstrap.split(",")]
    elif port != 5000 and not os.path.exists("bootstrap_nodes.txt"):  # Fallback to default if not specified
        bootstrap_nodes = [("127.0.0.1", 5000)]
    elif os.path.exists("bootstrap_nodes.txt"):
        with open("bootstrap_nodes.txt", "r") as f:
            bootstrap_nodes = [tuple(line.strip().split(":")) for line in f if line.strip()]
    loop = asyncio.new_event_loop()
    network = BlockchainNetwork(blockchain, node_id, "127.0.0.1", port, loop, bootstrap_nodes)
    # Start network in a daemon thread
    network_thread = threading.Thread(target=run_network, args=(network,), daemon=True)
    network_thread.start()
    logger.info("Network thread started")

    # Start periodic sync without blocking
    if network.loop:
        logger.info("Scheduling periodic sync task")
        sync_coroutine = network.start_periodic_sync()
        sync_task = asyncio.run_coroutine_threadsafe(sync_coroutine, network.loop)  # Schedule the coroutine

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