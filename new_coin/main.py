import threading
import signal
import sys
import asyncio 
from blockchain import Blockchain
from network import BlockchainNetwork
from gui import BlockchainGUI
from utils import find_available_port
from prometheus_client import start_http_server
import logging
import aiohttp

handler = logging.StreamHandler(sys.stdout)  # Output to console for visibility
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger = logging.getLogger("Blockchain")
logger.addHandler(handler)
logger.setLevel(logging.INFO)

async def health_check(network: BlockchainNetwork) -> bool:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://{network.host}:{network.port}/get_chain", ssl=network.ssl_context) as resp:
                logger.info(f"Health check response: {resp.status}")
                return resp.status == 200
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return False

def run_network(network: BlockchainNetwork):
    """Run the network in a separate thread."""
    logger.info("Starting network thread")
    network.run()

def shutdown(sig, frame, gui: BlockchainGUI, network: BlockchainNetwork):
    """Graceful shutdown."""
    logger.info("Shutting down...")
    gui.miner.stop_mining()
    gui.root.quit()
    network.loop.call_soon_threadsafe(network.loop.stop)
    sys.exit(0)

if __name__ == "__main__":
    logger.info("Starting Prometheus metrics server on port 8000")
    start_http_server(8000)
    logger.info("Prometheus server started")

    port = find_available_port()
    node_id = f"node{port}"
    logger.info(f"Initializing blockchain and network on port {port}")
    blockchain = Blockchain()
    bootstrap_nodes = [("127.0.0.1", 5000)] if port != 5000 else []
    network = BlockchainNetwork(blockchain, node_id, "127.0.0.1", port, bootstrap_nodes)

    # Start network in a daemon thread
    network_thread = threading.Thread(target=run_network, args=(network,), daemon=True)
    network_thread.start()
    logger.info("Network thread started")
    network.start_periodic_sync()

    # Wait briefly to ensure network is up before health check
    asyncio.run(asyncio.sleep(1))  # Give network a moment to start

    if not asyncio.run(health_check(network)):
        logger.error("Health check failed, exiting...")
        sys.exit(1)

    logger.info("Initializing GUI")
    gui = BlockchainGUI(blockchain, network)

    # Set up signal handlers
    signal.signal(signal.SIGINT, lambda s, f: shutdown(s, f, gui, network))
    signal.signal(signal.SIGTERM, lambda s, f: shutdown(s, f, gui, network))

    logger.info("Starting GUI main loop")
    gui.run()  # This should block and display the GUI in the main thread
    logger.info("GUI main loop exited")  # This won’t log unless gui.run() exits