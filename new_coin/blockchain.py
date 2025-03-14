import json
import time
import hashlib
import threading
import asyncio
import sqlite3
from typing import List, Dict, Optional, Any, Callable
from dataclasses import dataclass
from enum import Enum
import logging
import ecdsa
import aiohttp
from logging.handlers import RotatingFileHandler
from prometheus_client import Counter, Gauge
from utils import PEER_AUTH_SECRET

handler = RotatingFileHandler("originalcoin.log", maxBytes=5*1024*1024, backupCount=3)
logging.basicConfig(level=logging.INFO, handlers=[handler])
logger = logging.getLogger("Blockchain")

BLOCKS_MINED = Counter('blocks_mined_total', 'Total number of blocks mined')
PEER_COUNT = Gauge('peer_count', 'Number of connected peers')

from utils import CONFIG, SecurityUtils, TransactionInput, TransactionOutput, TransactionType

class Transaction:
    """A transaction in the blockchain, representing a transfer of value."""
    def __init__(self, tx_type: TransactionType, inputs: List[TransactionInput], outputs: List[TransactionOutput], fee: float = 0.0, nonce: Optional[int] = None):
        self.inputs = inputs
        self.outputs = outputs
        self.tx_type = tx_type
        self.timestamp = time.time()
        self.fee = fee
        self.nonce = nonce or int(time.time() * 1000)
        tx_data = str(self.inputs) + str(self.outputs) + str(self.timestamp)
        self.tx_id = hashlib.sha256(tx_data.encode()).hexdigest()

    def calculate_tx_id(self) -> str:
        data = json.dumps(self.to_dict(exclude_signature=True), sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()

    def to_dict(self, exclude_signature: bool = False) -> Dict[str, Any]:
        inputs = [i.to_dict() if not exclude_signature else {k: v for k, v in i.to_dict().items() if k != "signature"} 
                  for i in self.inputs]
        return {
            "tx_type": self.tx_type.value,
            "inputs": inputs,
            "outputs": [o.to_dict() for o in self.outputs],
            "fee": self.fee,
            "nonce": self.nonce,
            "tx_id": self.tx_id
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Transaction':
        tx_type = TransactionType(data["tx_type"])
        inputs = [TransactionInput.from_dict(i) for i in data["inputs"]]
        outputs = [TransactionOutput.from_dict(o) for o in data["outputs"]]
        tx = cls(tx_type=tx_type, inputs=inputs, outputs=outputs, fee=data["fee"], nonce=data.get("nonce"))
        tx.tx_id = data["tx_id"]
        return tx
    
    def sign(self, private_key: str):
        sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.SECP256k1)
        message = json.dumps(self.to_dict(exclude_signature=True), sort_keys=True).encode()
        for input_tx in self.inputs:
            input_tx.signature = sk.sign(message)

    def verify(self) -> bool:
        message = json.dumps(self.to_dict(exclude_signature=True), sort_keys=True).encode()
        for input_tx in self.inputs:
            if not input_tx.signature or not input_tx.public_key:
                return False
            vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(input_tx.public_key), curve=ecdsa.SECP256k1)
            try:
                if not vk.verify(input_tx.signature, message):
                    return False
            except ecdsa.BadSignatureError:
                return False
        return True

class TransactionFactory:
    @staticmethod
    def create_coinbase_transaction(recipient: str, amount: float, block_height: int) -> Transaction:
        tx_id = hashlib.sha256(f"coinbase_{block_height}_{recipient}".encode()).hexdigest()
        inputs = [TransactionInput(tx_id=tx_id, output_index=-1)]
        outputs = [TransactionOutput(recipient=recipient, amount=amount)]
        return Transaction(tx_type=TransactionType.COINBASE, inputs=inputs, outputs=outputs)

@dataclass
class BlockHeader:
    index: int
    previous_hash: str
    timestamp: float
    difficulty: int
    merkle_root: str  # Added to match Block initialization
    nonce: int = 0
    hash: Optional[str] = None

    def calculate_hash(self) -> str:
        data = f"{self.index}{self.previous_hash}{self.timestamp}{self.difficulty}{self.merkle_root}{self.nonce}"
        return hashlib.sha256(data.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "difficulty": self.difficulty,
            "merkle_root": self.merkle_root,
            "nonce": self.nonce,
            "hash": self.hash
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BlockHeader':
        return cls(
            index=data["index"],
            previous_hash=data["previous_hash"],
            timestamp=data["timestamp"],
            difficulty=data["difficulty"],
            merkle_root=data.get("merkle_root", "0" * 64),
            nonce=data["nonce"],
            hash=data["hash"]
        )

def calculate_merkle_root(transactions: List[Transaction]) -> str:
    tx_ids = [tx.tx_id for tx in transactions]
    if not tx_ids:
        return "0" * 64
    while len(tx_ids) > 1:
        temp_ids = []
        for i in range(0, len(tx_ids), 2):
            pair = tx_ids[i:i+2]
            if len(pair) == 1:
                pair.append(pair[0])
            combined = hashlib.sha256((pair[0] + pair[1]).encode()).hexdigest()
            temp_ids.append(combined)
        tx_ids = temp_ids
    return tx_ids[0]

class Block:
    def __init__(self, index: int, transactions: List[Transaction], previous_hash: str, difficulty: int):
        self.index = index
        self.transactions = transactions
        self.merkle_root = calculate_merkle_root(transactions)
        self.header = BlockHeader(index, previous_hash, time.time(), difficulty, self.merkle_root)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "transactions": [t.to_dict() for t in self.transactions],
            "header": self.header.to_dict()
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Block':
        transactions = [Transaction.from_dict(t) for t in data["transactions"]]
        header = BlockHeader.from_dict(data["header"])
        block = cls(index=data["index"], transactions=transactions, previous_hash=header.previous_hash, difficulty=header.difficulty)
        block.header = header
        return block

class UTXOSet:
    def __init__(self):
        self.utxos: Dict[str, List[TransactionOutput]] = {}
        self.used_nonces: Dict[str, set] = {}  # Track used nonces per address

    def update_with_block(self, block: Block):
        for tx in block.transactions:
            for i, output in enumerate(tx.outputs):
                if tx.tx_id not in self.utxos:
                    self.utxos[tx.tx_id] = []
                while len(self.utxos[tx.tx_id]) <= i:
                    self.utxos[tx.tx_id].append(None)
                self.utxos[tx.tx_id][i] = output
            for input in tx.inputs:
                if input.tx_id in self.utxos and input.output_index < len(self.utxos[input.tx_id]):
                    self.utxos[input.tx_id][input.output_index] = None
            # Track nonces for regular transactions
            if tx.tx_type != TransactionType.COINBASE:
                for input in tx.inputs:
                    if input.public_key:
                        address = SecurityUtils.public_key_to_address(input.public_key)
                        self.used_nonces.setdefault(address, set()).add(tx.nonce)

    def get_utxos_for_address(self, address: str) -> List[tuple[str, int, TransactionOutput]]:
        result = []
        for tx_id, outputs in self.utxos.items():
            for i, output in enumerate(outputs):
                if output and output.recipient == address:
                    result.append((tx_id, i, output))
        return result

    def get_utxo(self, tx_id: str, output_index: int) -> Optional[TransactionOutput]:
        if tx_id in self.utxos and output_index < len(self.utxos[tx_id]):
            return self.utxos[tx_id][output_index]
        return None

    def get_balance(self, address: str) -> float:
        return sum(utxo[2].amount for utxo in self.get_utxos_for_address(address))

    def is_nonce_used(self, address: str, nonce: int) -> bool:
        return address in self.used_nonces and nonce in self.used_nonces[address]

class Mempool:
    def __init__(self):
        self.transactions: Dict[str, Transaction] = {}
        self.timestamps: Dict[str, float] = {}

    def add_transaction(self, tx: Transaction) -> bool:
        if not tx.verify():
            logger.warning(f"Transaction {tx.tx_id} failed verification")
            return False
        max_size = CONFIG["mempool_max_size"]
        if tx.tx_id not in self.transactions:
            if len(self.transactions) >= max_size:
                now = time.time()
                tx_scores = {tx_id: (tx.fee / len(json.dumps(tx.to_dict())) * 1000) / (now - ts + 1)
                            for tx_id, tx, ts in [(tid, t, self.timestamps[tid]) 
                            for tid, t in self.transactions.items()]}
                lowest_score_tx = min(tx_scores, key=tx_scores.get)
                del self.transactions[lowest_score_tx]
                del self.timestamps[lowest_score_tx]
            self.transactions[tx.tx_id] = tx
            self.timestamps[tx.tx_id] = time.time()
            return True
        return False

    def get_transactions(self, max_txs: int, max_size: int) -> List[Transaction]:
        sorted_txs = sorted(self.transactions.values(), key=lambda tx: tx.fee, reverse=True)
        now = time.time()
        expired = [tx_id for tx_id, ts in self.timestamps.items() if now - ts > 24 * 3600]
        for tx_id in expired:
            self.transactions.pop(tx_id, None)
            self.timestamps.pop(tx_id, None)
        return sorted_txs[:max_txs]

    def remove_transactions(self, tx_ids: List[str]) -> None:
        for tx_id in tx_ids:
            self.transactions.pop(tx_id, None)
            self.timestamps.pop(tx_id, None)

class Miner:
    def __init__(self, blockchain: 'Blockchain', mempool: Mempool, wallet_address: Optional[str] = None):
        self.blockchain = blockchain
        self.mempool = mempool
        self.wallet_address = wallet_address
        self.current_block: Optional[Block] = None
        self.mining_task: Optional[threading.Thread] = None
        self.should_stop = False

    def start_mining(self, loop: asyncio.AbstractEventLoop):
        if not self.wallet_address:
            raise ValueError("No wallet address set for mining")
        if self.mining_task and not self.mining_task.done():
            logger.warning("Mining is already running")
            return
        self.should_stop = False
        # Run mining in a separate thread with its own loop
        def run_mining():
            mining_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(mining_loop)
            mining_loop.run_until_complete(self._mine_continuously())
        self.mining_task = threading.Thread(target=run_mining, daemon=True)
        self.mining_task.start()
        logger.info("Mining task started in separate thread")

    async def _mine_continuously(self) -> None:
        while not self.should_stop:
            self._create_new_block()
            if await self._mine_current_block():
                success = await self.blockchain.add_block(self.current_block)  # Now async
                if success:
                    tx_ids = [tx.tx_id for tx in self.current_block.transactions]
                    self.mempool.remove_transactions(tx_ids)
                    logger.info(f"Successfully mined block {self.current_block.index}")
                    if hasattr(self.blockchain, 'network'):
                        await self.blockchain.network.broadcast_block(self.current_block)
            await asyncio.sleep(0.1)

    def _create_new_block(self) -> None:
        latest_block = self.blockchain.chain[-1]
        transactions = self.mempool.get_transactions(1000, 1000000)
        coinbase_tx = TransactionFactory.create_coinbase_transaction(
            recipient=self.wallet_address,
            amount=self.blockchain.current_reward,
            block_height=latest_block.index + 1
        )
        transactions.insert(0, coinbase_tx)
        self.current_block = Block(
            index=latest_block.index + 1,
            transactions=transactions,
            previous_hash=latest_block.header.hash,
            difficulty=self.blockchain.adjust_difficulty()  # Use dynamic difficulty
        )

    def stop_mining(self):
        self.should_stop = True
        if self.mining_task and self.mining_task.is_alive():
            self.mining_task.join(timeout=2)  # Wait for thread to finish, with timeout
            logger.info("Mining thread stopped")
        else:
            logger.warning("No active mining thread to stop")

    async def _mine_current_block(self) -> bool:
        if not self.current_block:
            return False
        target = "0" * self.current_block.header.difficulty
        nonce = 0
        start_time = time.time()
        logger.info(f"Starting to mine block {self.current_block.index} with difficulty {self.current_block.header.difficulty}")
        while not self.should_stop:
            self.current_block.header.nonce = nonce
            block_hash = self.current_block.header.calculate_hash()
            if block_hash.startswith(target):
                self.current_block.header.hash = block_hash
                logger.info(f"Block {self.current_block.index} mined with hash {block_hash}")
                return True
            nonce += 1
            if nonce % 10000 == 0:
                logger.info(f"Reached nonce {nonce} for block {self.current_block.index}")
                elapsed = time.time() - start_time
                await asyncio.sleep(0.001)  # Minimal sleep for responsiveness
                start_time = time.time()
        return False

class Blockchain:
    def __init__(self, storage_path: str = "chain.db"):
        self.chain: List[Block] = []
        self.storage_path = storage_path
        self.difficulty = CONFIG["difficulty"]
        self.current_reward = CONFIG["current_reward"]
        self.halving_interval = CONFIG["halving_interval"]
        self.mempool = Mempool()
        self.utxo_set = UTXOSet()
        self.orphans: Dict[str, Block] = {}
        self.max_orphans = 100
        self.lock = threading.Lock()
        self.listeners = {"new_block": [], "new_transaction": []}
        self.network = None
        self.block_height = Gauge('blockchain_height', 'Current height of the blockchain')
        self.checkpoint_interval = CONFIG.get("checkpoint_interval", 100)
        self.checkpoints = [0]  # List of checkpoint block indices
        self.load_chain()
        self.update_metrics()

    def load_chain(self) -> None:
        conn = sqlite3.connect(self.storage_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS blocks ([index] INTEGER PRIMARY KEY, data TEXT)")
        cursor.execute("SELECT data FROM blocks ORDER BY [index]")
        rows = cursor.fetchall()
        if not rows:
            genesis_block = self.create_genesis_block()
            self.chain.append(genesis_block)
            cursor.execute("INSERT INTO blocks ([index], data) VALUES (?, ?)", (0, json.dumps(genesis_block.to_dict())))
            conn.commit()
        else:
            self.chain = [Block.from_dict(json.loads(row[0])) for row in rows]
            for block in self.chain:
                self.utxo_set.update_with_block(block)
        conn.close()

    def create_genesis_block(self) -> Block:
        """Create the genesis block with zeroed values."""
        genesis_block = Block(index=0, transactions=[], previous_hash="0" * 64, difficulty=self.difficulty)
        genesis_block.header.hash = genesis_block.header.calculate_hash()
        return genesis_block

    def save_chain(self) -> None:
        conn = sqlite3.connect(self.storage_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM blocks WHERE [index] >= ?", (len(self.chain) - 1,))
        cursor.execute("INSERT OR REPLACE INTO blocks ([index], data) VALUES (?, ?)", 
                       (self.chain[-1].index, json.dumps(self.chain[-1].to_dict())))
        conn.commit()
        conn.close()

    def update_metrics(self):
        self.block_height.set(len(self.chain) - 1)
        if hasattr(self, 'network') and self.network:
            PEER_COUNT.set(len(self.network.peers))

    async def validate_block(self, block: Block) -> bool:
        if block.index > 0:
            if block.index > len(self.chain):
                logger.info(f"Block {block.header.hash[:8]} index {block.index} exceeds chain length {len(self.chain)} - potential orphan")
                return False
            prev_block = self.chain[block.index - 1]
            if block.header.timestamp <= prev_block.header.timestamp:
                logger.info(f"Block {block.header.hash[:8]} timestamp {block.header.timestamp} not after previous {prev_block.header.timestamp}")
                return False
            if block.header.previous_hash != prev_block.header.hash:
                logger.info(f"Block {block.header.hash[:8]} previous hash mismatch")
                return False

        if block.header.timestamp > time.time() + 2 * 3600:
            logger.info(f"Block {block.header.hash[:8]} timestamp {block.header.timestamp} too far in future")
            return False

        if not block.transactions or block.transactions[0].tx_type != TransactionType.COINBASE:
            logger.info(f"Block {block.header.hash[:8]} missing or invalid coinbase transaction")
            return False
        coinbase_amount = sum(o.amount for o in block.transactions[0].outputs)
        if coinbase_amount > self.current_reward:
            logger.info(f"Block {block.header.hash[:8]} coinbase amount {coinbase_amount} exceeds reward {self.current_reward}")
            return False

        spent_utxos = set()
        for tx in block.transactions[1:]:
            if tx.tx_type == TransactionType.COINBASE:
                logger.info(f"Block {block.header.hash[:8]} contains multiple coinbase transactions")
                return False
            for tx_input in tx.inputs:
                utxo_key = (tx_input.tx_id, tx_input.output_index)
                if utxo_key in spent_utxos:
                    logger.info(f"Block {block.header.hash[:8]} failed: double-spend detected")
                    return False
                spent_utxos.add(utxo_key)
                if tx_input.public_key:
                    address = SecurityUtils.public_key_to_address(tx_input.public_key)
                    if self.utxo_set.is_nonce_used(address, tx.nonce):
                        logger.info(f"Block {block.header.hash[:8]} failed: nonce {tx.nonce} reused for {address}")
                        return False

        target = "0" * block.header.difficulty
        if not block.header.hash or not block.header.hash.startswith(target):
            logger.info(f"Block {block.header.hash[:8]} failed: hash {block.header.hash} does not meet difficulty {block.header.difficulty}")
            return False

        calculated_merkle_root = calculate_merkle_root(block.transactions)
        if block.header.merkle_root != calculated_merkle_root:
            logger.info(f"Block {block.header.hash[:8]} failed: Merkle root mismatch")
            return False

        tasks = [asyncio.create_task(self.validate_transaction(tx)) for tx in block.transactions]
        results = await asyncio.gather(*tasks)
        if not all(results):
            logger.info(f"Block {block.header.hash[:8]} failed: contains invalid transactions")
            return False

        logger.info(f"Block {block.header.hash[:8]} validated successfully")
        return True

    async def add_block(self, block: Block) -> bool:
        with self.lock:
            if any(b.header.hash == block.header.hash for b in self.chain):
                logger.info(f"Block {block.header.hash[:8]} already in chain")
                return False
            if block.index == len(self.chain) and block.header.previous_hash == self.chain[-1].header.hash:
                if await self.validate_block(block):
                    self.chain.append(block)
                    self.utxo_set.update_with_block(block)
                    if len(self.chain) % 2016 == 0:
                        self.adjust_difficulty()
                    if len(self.chain) % self.halving_interval == 0:
                        self.halve_block_reward()
                    if len(self.chain) % self.checkpoint_interval == 0:
                        self.checkpoints.append(len(self.chain) - 1)
                        logger.info(f"Added checkpoint at block {len(self.chain) - 1}")
                    self.trigger_event("new_block", block)
                    self.save_chain()
                    self.update_metrics()
                    self._process_orphans()
                    BLOCKS_MINED.inc()
                    logger.info(f"Added block {block.index} to chain: {block.header.hash[:8]}")
                    if self.network:  # Check if network exists
                        try:
                            await self.network.broadcast_block(block)
                        except Exception as e:
                            logger.error(f"Failed to broadcast block {block.index}: {e}")
                    return True
            else:
                self.handle_potential_fork(block)
            return False

    def _process_orphans(self):
        for hash, orphan in list(self.orphans.items()):
            if orphan.header.previous_hash == self.chain[-1].header.hash and orphan.index == len(self.chain):
                if asyncio.run(self.validate_block(orphan)):
                    self.chain.append(orphan)
                    self.utxo_set.update_with_block(orphan)
                    self.trigger_event("new_block", orphan)
                    self.save_chain()
                    self.update_metrics()
                    del self.orphans[hash]
                    self._process_orphans()
                    break

    def adjust_difficulty(self) -> int:
        """Adjust difficulty every 2016 blocks and always return the current difficulty."""
        if len(self.chain) % 2016 == 0 and len(self.chain) > 1:
            period_blocks = self.chain[-2016:]
            time_taken = period_blocks[-1].header.timestamp - period_blocks[0].header.timestamp
            target_time = 2016 * 60  # 60 seconds per block
            if time_taken > 0:
                ratio = target_time / time_taken
                self.difficulty = max(1, min(20, int(self.difficulty * ratio)))
                logger.info(f"Difficulty adjusted to {self.difficulty}")
        return self.difficulty  # Always return the current difficulty

    def dynamic_difficulty(self):
        if self.network and len(self.network.peers) < 3:
            return max(6, self.difficulty)
        return self.difficulty

    def get_total_difficulty(self):
        return sum(block.header.difficulty for block in self.chain)

    def is_valid_chain(self, chain):
        if not chain or chain[0] != self.create_genesis_block():
            return False
        for i in range(1, len(chain)):
            if not self._is_valid_block(chain[i], chain[i-1]):
                return False
        for checkpoint in self.checkpoints:
            if checkpoint >= len(chain) or chain[checkpoint] != self.chain[checkpoint]:
                return False
        return True

    def _is_valid_block(self, block: Block, prev_block: Block) -> bool:
        if block.index != prev_block.index + 1:
            return False
        if block.header.previous_hash != prev_block.header.hash:
            return False
        target = "0" * block.header.difficulty
        if not block.header.hash or not block.header.hash.startswith(target):
            return False
        return True

    def halve_block_reward(self) -> None:
        self.current_reward /= 2

    def handle_potential_fork(self, block: Block) -> None:
        with self.lock:
            if block.index <= len(self.chain) - 1:
                return
            if block.index > len(self.chain):
                if len(self.orphans) >= self.max_orphans:
                    oldest = min(self.orphans.keys(), key=lambda k: self.orphans[k].header.timestamp)
                    del self.orphans[oldest]
                self.orphans[block.header.hash] = block
            if self.network:
                asyncio.run_coroutine_threadsafe(self.network.request_chain(), self.network.loop)

    def replace_chain(self, new_chain: List[Block]):
        with self.lock:
            if len(new_chain) <= len(self.chain):
                return
            if self.is_valid_chain(new_chain):
                self.chain = new_chain
                self.utxo_set = UTXOSet()
                for block in self.chain:
                    self.utxo_set.update_with_block(block)
                self.save_chain()
                self.update_metrics()

    def subscribe(self, event: str, callback: Callable) -> None:
        if event in self.listeners:
            self.listeners[event].append(callback)

    def trigger_event(self, event: str, data: Any) -> None:
        for callback in self.listeners[event]:
            callback(data)

    async def validate_transaction(self, tx: Transaction) -> bool:
        if tx.tx_type == TransactionType.COINBASE:
            logger.info(f"Transaction {tx.tx_id[:8]} is coinbase, auto-validated")
            return True
        if not tx.inputs or not tx.outputs:
            logger.info(f"Transaction {tx.tx_id[:8]} failed: no inputs or outputs")
            return False
        input_sum = 0
        for tx_input in tx.inputs:
            utxo = self.utxo_set.get_utxo(tx_input.tx_id, tx_input.output_index)
            if not utxo or not tx_input.public_key or not tx_input.signature:
                logger.info(f"Transaction {tx.tx_id[:8]} failed: UTXO or signature missing")
                return False
            address = SecurityUtils.public_key_to_address(tx_input.public_key)
            if address != utxo.recipient or self.utxo_set.is_nonce_used(address, tx.nonce):
                logger.info(f"Transaction {tx.tx_id[:8]} failed: address mismatch or nonce reused")
                return False
            public_key_obj = ecdsa.VerifyingKey.from_string(bytes.fromhex(tx_input.public_key), curve=ecdsa.SECP256k1)
            try:
                public_key_obj.verify(tx_input.signature, json.dumps(tx.to_dict(), sort_keys=True).encode())
            except ecdsa.BadSignatureError:
                logger.info(f"Transaction {tx.tx_id[:8]} failed: invalid signature")
                return False
            input_sum += utxo.amount
        output_sum = sum(output.amount for output in tx.outputs)
        valid = output_sum <= input_sum and abs(input_sum - output_sum - tx.fee) < 0.0001
        logger.info(f"Transaction {tx.tx_id[:8]} validation: input_sum={input_sum}, output_sum={output_sum}, fee={tx.fee}, valid={valid}")
        return valid

    def add_transaction_to_mempool(self, tx: Transaction) -> bool:
        if not asyncio.run(self.validate_transaction(tx)):
            return False
        success = self.mempool.add_transaction(tx)
        if success:
            self.trigger_event("new_transaction", tx)
            if self.network:
                asyncio.run_coroutine_threadsafe(self.network.broadcast_transaction(tx), self.network.loop)
        return success

    def get_balance(self, address: str) -> float:
        return self.utxo_set.get_balance(address)

    def create_transaction(self, sender_private_key: str, sender_address: str, recipient_address: str, amount: float, fee: float = 0.001) -> Optional[Transaction]:
        private_key = ecdsa.SigningKey.from_string(bytes.fromhex(sender_private_key), curve=ecdsa.SECP256k1)
        public_key = private_key.get_verifying_key().to_string().hex()
        sender_utxos = self.utxo_set.get_utxos_for_address(sender_address)
        total_available = sum(utxo[2].amount for utxo in sender_utxos)
        if total_available < amount + fee:
            return None
        selected_utxos = []
        selected_amount = 0
        for tx_id, output_index, utxo in sender_utxos:
            selected_utxos.append((tx_id, output_index, utxo.amount))
            selected_amount += utxo.amount
            if selected_amount >= amount + fee:
                break
        if selected_amount < amount + fee:
            return None
        inputs = [TransactionInput(tx_id=tx_id, output_index=index, public_key=public_key) for tx_id, index, _ in selected_utxos]
        outputs = [TransactionOutput(recipient=recipient_address, amount=amount)]
        change = selected_amount - amount - fee
        if change > 0:
            outputs.append(TransactionOutput(recipient=sender_address, amount=change))
        tx = Transaction(tx_type=TransactionType.TRANSFER, inputs=inputs, outputs=outputs, fee=fee)
        tx.sign(sender_private_key)
        return tx
    
    