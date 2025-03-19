"""
Network Package for the blockchain P2P communication.
This package handles all communication between nodes in the blockchain network.
"""

import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Export main components
from blockchain.core import (
    BlockchainNetwork,
    load_config,
    save_config,
    get_default_config
)

from p2p import (
    PeerReputation,
    RateLimiter,
    NonceTracker,
    NodeIdentity,
    CertificateManager
)

# Make version info available
__version__ = '1.0.0'