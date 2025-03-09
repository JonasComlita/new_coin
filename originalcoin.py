import threading
import asyncio
import aiohttp
import aiohttp.web
import json
import time
import hashlib
import logging
import ecdsa
from typing import List, Dict, Optional, Any, Callable
from dataclasses import dataclass
from enum import Enum
from queue import Queue
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox, scrolledtext
import tkinter.simpledialog
import random

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Blockchain")

class TransactionType(Enum):
    COINBASE = "coinbase"
    REGULAR = "regular"

@dataclass
class TransactionOutput:
    recipient: str
    amount: float
    script: str = "P2PKH"

    def to_dict(self) -> Dict[str, Any]:
        return {"recipient": self.recipient, "amount": self.amount, "script": self.script}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TransactionOutput':
        return cls(recipient=data["recipient"], amount=data["amount"], script=data.get("script", "P2PKH"))

@dataclass
class TransactionInput:
    tx_id: str
    output_index: int
    signature: Optional[bytes] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"tx_id": self.tx_id, "output_index": self.output_index, "signature": self.signature.hex() if self.signature else None}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TransactionInput':
        signature = bytes.fromhex(data["signature"]) if data.get("signature") else None
        return cls(tx_id=data["tx_id"], output_index=data["output_index"], signature=signature)

class Transaction:
    def __init__(self, tx_type: TransactionType, inputs: List[TransactionInput], outputs: List[TransactionOutput], fee: float = 0.0):
        self.tx_type = tx_type
        self.inputs = inputs
        self.outputs = outputs
        self.fee = fee
        self.tx_id = self.calculate_tx_id()

    def calculate_tx_id(self) -> str:
        data = f"{self.tx_type.value}{[i.to_dict() for i in self.inputs]}{[o.to_dict() for o in self.outputs]}{self.fee}"
        return hashlib.sha256(data.encode()).hexdigest()

    def sign_transaction(self, private_key: ecdsa.SigningKey, public_key: ecdsa.VerifyingKey) -> None:
        message = self.tx_id.encode()
        for tx_input in self.inputs:
            tx_input.signature = private_key.sign(message)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tx_type": self.tx_type.value,
            "inputs": [i.to_dict() for i in self.inputs],
            "outputs": [o.to_dict() for o in self.outputs],
            "fee": self.fee,
            "tx_id": self.tx_id
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Transaction':
        tx_type = TransactionType(data["tx_type"])
        inputs = [TransactionInput.from_dict(i) for i in data["inputs"]]
        outputs = [TransactionOutput.from_dict(o) for o in data["outputs"]]
        return cls(tx_type=tx_type, inputs=inputs, outputs=outputs, fee=data["fee"])

class TransactionFactory:
    @staticmethod
    def create_coinbase_transaction(recipient: str, amount: float, block_height: int) -> Transaction:
        tx_id = hashlib.sha256(f"coinbase_{block_height}_{recipient}".encode()).hexdigest()
        inputs = [TransactionInput(tx_id=tx_id, output_index=-1)]
        outputs = [TransactionOutput(recipient=recipient, amount=amount)]
        return Transaction(tx_type=TransactionType.COINBASE, inputs=inputs, outputs=outputs)

class BlockHeader:
    def __init__(self, index: int, previous_hash: str, timestamp: float, difficulty: int, nonce: int = 0):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.difficulty = difficulty
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self) -> str:
        data = f"{self.index}{self.previous_hash}{self.timestamp}{self.difficulty}{self.nonce}"
        return hashlib.sha256(data.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "difficulty": self.difficulty,
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
            nonce=data["nonce"]
        )

class Block:
    def __init__(self, index: int, transactions: List[Transaction], previous_hash: str, difficulty: int):
        self.index = index
        self.transactions = transactions
        self.header = BlockHeader(index, previous_hash, time.time(), difficulty)

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
        self.utxos: Dict[str, Dict[int, TransactionOutput]] = {}

    def update_with_block(self, block: Block) -> None:
        for tx in block.transactions:
            for i, tx_input in enumerate(tx.inputs):
                if tx.tx_type != TransactionType.COINBASE:
                    if tx_input.tx_id in self.utxos and tx_input.output_index in self.utxos[tx_input.tx_id]:
                        del self.utxos[tx_input.tx_id][tx_input.output_index]
                        if not self.utxos[tx_input.tx_id]:
                            del self.utxos[tx_input.tx_id]
            for i, output in enumerate(tx.outputs):
                if tx.tx_id not in self.utxos:
                    self.utxos[tx.tx_id] = {}
                self.utxos[tx.tx_id][i] = output

    def get_utxos_for_address(self, address: str) -> List[tuple[str, int, TransactionOutput]]:
        utxos = []
        for tx_id, outputs in self.utxos.items():
            for output_index, output in outputs.items():
                if output.recipient == address:
                    utxos.append((tx_id, output_index, output))
        return utxos

    def get_utxo(self, tx_id: str, output_index: int) -> Optional[TransactionOutput]:
        return self.utxos.get(tx_id, {}).get(output_index)

    def get_balance(self, address: str) -> float:
        return sum(utxo[2].amount for utxo in self.get_utxos_for_address(address))

class Mempool:
    def __init__(self):
        self.transactions: Dict[str, Transaction] = {}

    def add_transaction(self, tx: Transaction) -> bool:
        if tx.tx_id not in self.transactions:
            self.transactions[tx.tx_id] = tx
            return True
        return False

    def get_transactions(self, max_txs: int, max_size: int) -> List[Transaction]:
        return list(self.transactions.values())[:max_txs]

    def remove_transactions(self, tx_ids: List[str]) -> None:
        for tx_id in tx_ids:
            self.transactions.pop(tx_id, None)

class SecurityUtils:
    @staticmethod
    def generate_keypair() -> tuple[str, str]:
        private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        public_key = private_key.get_verifying_key()
        return private_key.to_string().hex(), public_key.to_string().hex()

    @staticmethod
    def public_key_to_address(public_key: str) -> str:
        pub_bytes = bytes.fromhex(public_key)
        sha256_hash = hashlib.sha256(pub_bytes).hexdigest()
        ripemd160_hash = hashlib.new('ripemd160', bytes.fromhex(sha256_hash)).hexdigest()
        return f"1{ripemd160_hash[:20]}"

def generate_wallet() -> Dict[str, str]:
    private_key, public_key = SecurityUtils.generate_keypair()
    address = SecurityUtils.public_key_to_address(public_key)
    return {"address": address, "private_key": private_key, "public_key": public_key}

class Miner:
    def __init__(self, blockchain, mempool: Mempool, wallet_address: str):
        self.blockchain = blockchain
        self.mempool = mempool
        self.wallet_address = wallet_address
        self.mining_thread = None
        self.stop_mining_event = threading.Event()
        self.current_block = None
    
    def start_mining(self) -> None:
        if self.mining_thread and self.mining_thread.is_alive():
            return
        self.stop_mining_event.clear()
        self.mining_thread = threading.Thread(target=self._mine_continuously)
        self.mining_thread.daemon = True
        self.mining_thread.start()
    
    def stop_mining(self) -> None:
        self.stop_mining_event.set()
        if self.mining_thread:
            self.mining_thread.join()
    
    def _mine_continuously(self) -> None:
        while not self.stop_mining_event.is_set():
            # Get latest blockchain state before creating a new block
            self._create_new_block()
            if self._mine_current_block():
                success = self.blockchain.add_block(self.current_block)
                if success:
                    tx_ids = [tx.tx_id for tx in self.current_block.transactions]
                    self.mempool.remove_transactions(tx_ids)
                    print(f"Successfully mined block {self.current_block.index}")
                    
                    # Broadcast this block to all peers
                    if hasattr(self.blockchain, 'network'):
                        self.blockchain.network.broadcast_block(self.current_block)
    
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
            difficulty=self.blockchain.difficulty
        )
        logger.info(f"Created block {self.current_block.index} with coinbase to {self.wallet_address}")
    
    def _mine_current_block(self) -> bool:
        if not self.current_block:
            return False
        target = "0" * self.blockchain.difficulty
        max_nonce = 2**32
        for nonce in range(max_nonce):
            if self.stop_mining_event.is_set():
                return False
            self.current_block.header.nonce = nonce
            block_hash = self.current_block.header.calculate_hash()
            if block_hash.startswith(target):
                self.current_block.header.hash = block_hash
                return True
            if nonce % 1000 == 0:
                time.sleep(0.001)
        return False

class Blockchain:
    def __init__(self, storage_path: str = "chain.json"):
        self.chain: List[Block] = []
        self.storage_path = storage_path
        self.difficulty = 10
        self.current_reward = 50.0
        self.halving_interval = 210000
        self.mempool = Mempool()
        self.utxo_set = UTXOSet()
        self.lock = threading.Lock()
        self.listeners = {"new_block": [], "new_transaction": []}  # Event listeners
        self.load_chain()
        logger.info("Blockchain OriginalCoin initialized")

    def subscribe(self, event: str, callback: Callable) -> None:
        if event in self.listeners:
            self.listeners[event].append(callback)
        else:
            raise ValueError(f"Unknown event: {event}")

    def trigger_event(self, event: str, data: Any) -> None:
        if event in self.listeners:
            for callback in self.listeners[event]:
                callback(data)

    def load_chain(self) -> None:
        try:
            with open(self.storage_path, 'r') as f:
                chain_data = json.load(f)
                self.chain = [Block.from_dict(block) for block in chain_data]
                for block in self.chain:
                    self.utxo_set.update_with_block(block)
        except (FileNotFoundError, json.JSONDecodeError):
            genesis_block = Block(index=0, transactions=[], previous_hash="0" * 64, difficulty=self.difficulty)
            self.chain.append(genesis_block)
            self.save_chain()

    def save_chain(self) -> None:
        with open(self.storage_path, 'w') as f:
            json.dump([block.to_dict() for block in self.chain], f)

    def validate_block(self, block: Block) -> bool:
        target = "0" * block.header.difficulty
        return block.header.hash.startswith(target)

    def add_block(self, block: Block) -> bool:
        with self.lock:
            if any(b.header.hash == block.header.hash for b in self.chain):
                logger.info(f"Block {block.header.hash[:8]} already in chain")
                return False
            if not self.validate_block(block):
                logger.warning(f"Block {block.header.hash[:8]} failed validation")
                return False
            if block.index != len(self.chain):
                logger.warning(f"Block index {block.index} doesn't match expected index {len(self.chain)}")
                return False
            expected_index = len(self.chain)
            expected_prev_hash = self.chain[-1].header.hash
            if block.index == expected_index and block.header.previous_hash == expected_prev_hash:
                self.chain.append(block)
                self.utxo_set.update_with_block(block)
                logger.info(f"UTXO set updated with block {block.index}. Transactions: {[tx.tx_id[:8] for tx in block.transactions]}")
                if len(self.chain) % 2016 == 0:
                    self.adjust_difficulty()
                if len(self.chain) % self.halving_interval == 0:
                    self.halve_block_reward()
                self.trigger_event("new_block", block)
                self.save_chain()
                logger.info(f"Added block {block.index} to chain: {block.header.hash[:8]}")
                return True
            else:
                self.handle_potential_fork(block)
                return False

    def create_transaction(self, sender_private_key: str, sender_address: str, recipient_address: str, amount: float, fee: float = 0.001) -> Optional[Transaction]:
        sender_utxos = self.utxo_set.get_utxos_for_address(sender_address)
        logger.info(f"UTXOs for {sender_address}: {[utxo[2].to_dict() for utxo in sender_utxos]}")
        total_available = sum(utxo[2].amount for utxo in sender_utxos)
        logger.info(f"Total available for {sender_address}: {total_available}, Required: {amount + fee}")
        if total_available < amount + fee:
            logger.info(f"Transaction failed: insufficient funds for {sender_address}. Available: {total_available}, Required: {amount + fee}")
            return None
        selected_utxos = []
        selected_amount = 0
        for tx_id, output_index, utxo in sender_utxos:
            selected_utxos.append((tx_id, output_index, utxo.amount))
            selected_amount += utxo.amount
            logger.info(f"Selected UTXO: tx_id={tx_id}, index={output_index}, amount={utxo.amount}, running total={selected_amount}")
            if selected_amount >= amount + fee:
                break
        inputs = [TransactionInput(tx_id, output_index) for tx_id, output_index, _ in selected_utxos]
        outputs = [TransactionOutput(recipient_address, amount)]
        change_amount = selected_amount - amount - fee
        if change_amount > 0:
            outputs.append(TransactionOutput(sender_address, change_amount))
        tx = Transaction(tx_type=TransactionType.REGULAR, inputs=inputs, outputs=outputs, fee=fee)
        private_key = ecdsa.SigningKey.from_string(bytes.fromhex(sender_private_key), curve=ecdsa.SECP256k1)
        public_key = private_key.get_verifying_key()
        tx.sign_transaction(private_key, public_key)
        logger.info(f"Transaction created: {tx.tx_id}")
        return tx

    def validate_transaction(self, tx: Transaction) -> bool:
        if tx.tx_type == TransactionType.COINBASE:
            logger.info(f"Transaction {tx.tx_id[:8]} is coinbase, auto-validated")
            return True
        if not tx.inputs or not tx.outputs:
            logger.info(f"Transaction {tx.tx_id[:8]} failed: no inputs or outputs")
            return False
        input_sum = 0
        for tx_input in tx.inputs:
            utxo = self.utxo_set.get_utxo(tx_input.tx_id, tx_input.output_index)
            if not utxo or not tx_input.signature:
                logger.info(f"Transaction {tx.tx_id[:8]} failed: UTXO {tx_input.tx_id}:{tx_input.output_index} not found or unsigned")
                return False
            input_sum += utxo.amount
        output_sum = sum(output.amount for output in tx.outputs)
        fee_valid = abs(input_sum - output_sum - tx.fee) < 0.0001
        valid = output_sum <= input_sum and fee_valid
        logger.info(f"Transaction {tx.tx_id[:8]} validation: input_sum={input_sum}, output_sum={output_sum}, fee={tx.fee}, fee_valid={fee_valid}, valid={valid}")
        return valid

    def add_transaction_to_mempool(self, tx: Transaction) -> bool:
        if not self.validate_transaction(tx):
            logger.info(f"Transaction {tx.tx_id[:8]} not added to mempool: validation failed")
            return False
        success = self.mempool.add_transaction(tx)
        if success:
            self.trigger_event("new_transaction", tx)
            logger.info(f"Transaction {tx.tx_id[:8]} added to mempool")
        else:
            logger.info(f"Transaction {tx.tx_id[:8]} not added to mempool: mempool addition failed")
        return success

    def get_balance(self, address: str) -> float:
        balance = self.utxo_set.get_balance(address)
        logger.info(f"Balance check for {address}: {balance}")
        return balance

    def adjust_difficulty(self) -> None:
        pass  # Placeholder

    def halve_block_reward(self) -> None:
        self.current_reward /= 2

    def handle_potential_fork(self, block: Block) -> None:
        with self.lock:
            if block.index <= len(self.chain) - 1:
                logger.info(f"Block {block.index} is behind current chain length {len(self.chain)} - ignoring")
                return
            
            # This block is ahead of our chain - request updates
            if hasattr(self, 'network') and self.network:
                asyncio.run_coroutine_threadsafe(self.network.request_chain(), self.network.loop)

    async def request_chain(self) -> None:
        for peer_id, (host, port) in self.network.peers.items():
            try:
                async with aiohttp.ClientSession() as session:
                    url = f"http://{host}:{port}/get_chain"
                    async with session.get(url) as response:
                        if response.status == 200:
                            chain_data = await response.json()
                            new_chain = [Block.from_dict(b) for b in chain_data]
                            if self.validate_and_replace_chain(new_chain):
                                logger.info(f"Replaced chain with longer chain of length {len(new_chain)}")
                                break
            except Exception as e:
                logger.error(f"Error requesting chain from {peer_id}: {e}")

    def validate_and_replace_chain(self, new_chain: List[Block]) -> bool:
        if len(new_chain) <= len(self.chain):
            logger.info(f"New chain length {len(new_chain)} not longer than current {len(self.chain)}")
            return False
        if not self.validate_chain(new_chain):
            logger.warning("New chain failed validation")
            return False
        with self.lock:
            self.chain = new_chain
            self.utxo_set = UTXOSet()
            for block in self.chain:
                self.utxo_set.update_with_block(block)
            self.save_chain()
            logger.info(f"Chain replaced: new length {len(self.chain)}")
            return True

    def validate_chain(self, chain: List[Block]) -> bool:
        if not chain or chain[0].index != 0:
            return False
        for i in range(1, len(chain)):
            if chain[i].index != chain[i-1].index + 1 or chain[i].header.previous_hash != chain[i-1].header.hash:
                return False
            if not self.validate_block(chain[i]):
                return False
        return True

class BlockchainNetwork:
    def __init__(self, blockchain: Blockchain, node_id: str, host: str, port: int):
        self.blockchain = blockchain
        self.node_id = node_id
        self.host = host
        self.port = port
        self.peers: Dict[str, tuple[str, int]] = {}
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.app = aiohttp.web.Application()
        self.app.add_routes([
            aiohttp.web.post('/receive_block', self.receive_block),
            aiohttp.web.post('/receive_transaction', self.receive_transaction),
            aiohttp.web.get('/get_chain', self.get_chain)
        ])
        self.blockchain.network = self

    def add_peer(self, peer_id: str, host: str, port: int):
        """Add a peer to the network."""
        if peer_id in self.peers:
            logger.warning(f"Peer {peer_id} already exists")
            return
        self.peers[peer_id] = (host, port)
        logger.info(f"Added peer {peer_id} at {host}:{port}")

    # ... (rest of the BlockchainNetwork methods like broadcast_transaction, run, etc.)

    def run(self) -> None:
        runner = aiohttp.web.AppRunner(self.app)
        self.loop.run_until_complete(runner.setup())
        site = aiohttp.web.TCPSite(runner, self.host, self.port)
        self.loop.run_until_complete(site.start())
        logger.info(f"Node {self.node_id} listening on {self.host}:{self.port}")
        self.loop.run_forever()

    def broadcast_block(self, block: Block) -> None:
        tasks = []
        for peer_id, (host, port) in self.peers.items():
            if peer_id != self.node_id:
                tasks.append(self.send_block(peer_id, host, port, block))
        if tasks:
            asyncio.run_coroutine_threadsafe(asyncio.gather(*tasks, return_exceptions=True), self.loop)

    async def send_block(self, peer_id: str, host: str, port: int, block: Block) -> None:
        try:
            async with aiohttp.ClientSession() as session:
                url = f"http://{host}:{port}/receive_block"
                data = {"block": block.to_dict()}
                async with session.post(url, json=data) as response:
                    if response.status == 200:
                        logger.info(f"Sent block {block.index} to {peer_id}")
                    else:
                        logger.warning(f"Failed to send block {block.index} to {peer_id}: {response.status}")
        except Exception as e:
            logger.error(f"Error sending block to {peer_id}: {e}")

    async def receive_block(self, request: aiohttp.web.Request) -> aiohttp.web.Response:
        data = await request.json()
        block = Block.from_dict(data["block"])
        logger.info(f"Received block {block.index} from peer")
        success = self.blockchain.add_block(block)
        if not success:
            logger.info(f"Block {block.index} not added directly, checking for fork")
            self.blockchain.handle_potential_fork(block)
        return aiohttp.web.Response(status=200)

    async def broadcast_transaction(self, tx: Transaction) -> None:
        tasks = []
        for peer_id, (host, port) in self.peers.items():
            if peer_id != self.node_id:
                tasks.append(self.send_transaction(peer_id, host, port, tx))
        if tasks:
            try:
                await asyncio.gather(*tasks, return_exceptions=True)
            except Exception as e:
                logger.error(f"Error broadcasting transaction: {e}")

    async def send_transaction(self, peer_id, host, port, tx, max_retries=3):
        for attempt in range(max_retries):
            try:
                # Your existing code to send transaction
                return  # Return on success
            except ConnectionRefusedError:
                wait_time = 1 * (2 ** attempt)  # Exponential backoff: 1, 2, 4 seconds
                logger.warning(f"Connection to {peer_id} refused, retry {attempt+1}/{max_retries} in {wait_time}s")
                if attempt < max_retries - 1:
                    await asyncio.sleep(wait_time)
            except Exception as e:
                logger.error(f"Error sending to {peer_id}: {e}")
                break  # Don't retry for other errors

    async def receive_transaction(self, request: aiohttp.web.Request) -> aiohttp.web.Response:
        data = await request.json()
        tx = Transaction.from_dict(data["transaction"])
        self.blockchain.add_transaction_to_mempool(tx)
        return aiohttp.web.Response(status=200)

    async def get_chain(self, request: aiohttp.web.Request) -> aiohttp.web.Response:
        return aiohttp.web.json_response([block.to_dict() for block in self.blockchain.chain])

    async def request_chain(self) -> None:
        for peer_id, (host, port) in self.peers.items():
            try:
                async with aiohttp.ClientSession() as session:
                    url = f"http://{host}:{port}/get_chain"
                    async with session.get(url) as response:
                        if response.status == 200:
                            chain_data = await response.json()
                            new_chain = [Block.from_dict(b) for b in chain_data]
                            if self.blockchain.validate_and_replace_chain(new_chain):
                                logger.info(f"Replaced chain with longer chain of length {len(new_chain)}")
                                break
            except Exception as e:
                logger.error(f"Error requesting chain from {peer_id}: {e}")

    def start_periodic_sync(self, interval=30):  # sync every 30 seconds
        """Start periodic chain synchronization with peers."""
        async def sync_task():
            while True:
                await self.request_chain()
                await asyncio.sleep(interval)
        
        asyncio.run_coroutine_threadsafe(sync_task(), self.loop)

class BlockchainGUI:
    def __init__(self, blockchain: Blockchain, network: BlockchainNetwork, wallet_file: str = "wallets.json"):
        """Initialize the OriginalCoin GUI with a modern, cohesive design."""
        self.blockchain = blockchain
        self.network = network
        self.wallets = {}
        self.wallet_file = wallet_file
        self.miner = Miner(blockchain, blockchain.mempool, None)
        self.load_wallets()
        self.update_queue = Queue()

        # GUI setup
        self.root = tk.Tk()
        self.root.title("OriginalCoin GUI")
        self.root.geometry("800x900")  # Updated geometry
        self.root.minsize(600, 500)    # Updated minsize

        # Configure the root window's grid to allow content expansion
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        # Main container frame to hold all content
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill='both', expand=True, padx=10, pady=10)

        # Header: Application title
        self.create_header()

        # Wallet Section
        self.create_wallet_section()

        # Mining Controls Section
        self.create_mining_section()

        # Send Transaction Section
        self.create_transaction_section()

        # Peer Management Section
        self.create_peer_section()

        # Status Panel
        self.create_status_panel()

        # Footer: Exit button
        self.create_footer()

        # Event subscriptions
        self.blockchain.subscribe("new_block", self.on_new_block)
        self.blockchain.subscribe("new_transaction", self.on_new_transaction)

        # Start real-time updates
        self.root.after(1000, self.update_ui)
        self.root.protocol("WM_DELETE_WINDOW", self.exit)

    def create_header(self):
        """Create a header with the application title."""
        header_frame = ttk.Frame(self.main_frame)
        header_frame.grid(row=0, column=0, sticky='ew', pady=(0, 10))
        title_label = ttk.Label(
            header_frame,
            text="OriginalCoin",
            font=("Arial", 24, "bold"),
            anchor='center'
        )
        title_label.pack(fill='x')
        self.main_frame.grid_columnconfigure(0, weight=1)

    def create_wallet_section(self):
        """Create the wallet management section."""
        wallet_frame = ttk.LabelFrame(self.main_frame, text="Wallet", padding=10)
        wallet_frame.grid(row=1, column=0, sticky='ew', pady=5)

        # Wallet label and entry
        ttk.Label(wallet_frame, text="Wallet:").grid(row=0, column=0, sticky='w', padx=5)
        self.wallet_entry = ttk.Entry(wallet_frame, width=20)
        self.wallet_entry.grid(row=0, column=1, sticky='ew', padx=5)
        self.wallet_entry.bind("<KeyRelease>", self.on_entry_change)
        self.wallet_var = tk.StringVar(value="")
        self.wallet_dropdown = ttk.OptionMenu(wallet_frame, self.wallet_var, "", *self.wallets.keys(), command=self.on_dropdown_select)
        self.wallet_dropdown.grid(row=0, column=2, sticky='ew', padx=5)

        # Create Wallet button
        self.create_button = ttk.Button(wallet_frame, text="Create Wallet", command=self.create_wallet)
        self.create_button.grid(row=0, column=3, sticky='e', padx=5)

        # Configure grid weights for expansion
        wallet_frame.grid_columnconfigure(1, weight=1)

    def create_mining_section(self):
        """Create the mining controls section."""
        mining_frame = ttk.LabelFrame(self.main_frame, text="Mining Controls", padding=10)
        mining_frame.grid(row=2, column=0, sticky='ew', pady=5)

        # Mining buttons
        self.mine_button = ttk.Button(mining_frame, text="Mine", command=self.start_mining)
        self.mine_button.grid(row=0, column=0, sticky='w', padx=5)
        self.stop_mining_button = ttk.Button(mining_frame, text="Stop Mining", command=self.stop_mining)
        self.stop_mining_button.grid(row=0, column=1, sticky='e', padx=5)

        # Center the buttons by giving equal weight to columns
        mining_frame.grid_columnconfigure(0, weight=1)
        mining_frame.grid_columnconfigure(1, weight=1)

    def create_transaction_section(self):
        """Create the send transaction section."""
        send_frame = ttk.LabelFrame(self.main_frame, text="Send Transaction", padding=10)
        send_frame.grid(row=3, column=0, sticky='ew', pady=5)

        # To Address
        ttk.Label(send_frame, text="To Address:").grid(row=0, column=0, sticky='w', padx=5)
        self.to_entry = ttk.Entry(send_frame, width=40)
        self.to_entry.grid(row=0, column=1, sticky='ew', padx=5)

        # Amount
        ttk.Label(send_frame, text="Amount:").grid(row=1, column=0, sticky='w', padx=5)
        self.amount_entry = ttk.Entry(send_frame)
        self.amount_entry.grid(row=1, column=1, sticky='ew', padx=5)

        # Send button
        self.send_button = ttk.Button(send_frame, text="Send", command=self.send_transaction)
        self.send_button.grid(row=1, column=2, sticky='e', padx=5)

        # Configure grid weights
        send_frame.grid_columnconfigure(1, weight=1)

    def create_peer_section(self):
        """Create the peer management section."""
        peer_frame = ttk.LabelFrame(self.main_frame, text="Peer Management", padding=10)
        peer_frame.grid(row=4, column=0, sticky='ew', pady=5)

        # Host
        ttk.Label(peer_frame, text="Host:").grid(row=0, column=0, sticky='w', padx=5)
        self.peer_host_entry = ttk.Entry(peer_frame)
        self.peer_host_entry.grid(row=0, column=1, sticky='ew', padx=5)
        self.peer_host_entry.insert(0, "127.0.0.1")

        # Port
        ttk.Label(peer_frame, text="Port:").grid(row=1, column=0, sticky='w', padx=5)
        self.peer_port_entry = ttk.Entry(peer_frame)
        self.peer_port_entry.grid(row=1, column=1, sticky='ew', padx=5)

        # Add Peer button
        self.add_peer_button = ttk.Button(peer_frame, text="Add Peer", command=self.add_peer)
        self.add_peer_button.grid(row=1, column=2, sticky='e', padx=5)

        # Configure grid weights
        peer_frame.grid_columnconfigure(1, weight=1)

    def create_status_panel(self):
        """Create the status panel with peer list, output, and mempool text."""
        status_frame = ttk.LabelFrame(self.main_frame, text="Status", padding=10)
        status_frame.grid(row=5, column=0, sticky='nsew', pady=5)

        # Connected Peers Listbox with Scrollbar
        ttk.Label(status_frame, text="Connected Peers:").grid(row=0, column=0, sticky='w', padx=5)
        peers_container = ttk.Frame(status_frame)
        peers_container.grid(row=1, column=0, columnspan=2, sticky='ew', pady=5)
        self.peer_listbox = tk.Listbox(peers_container, height=3)
        self.peer_listbox.pack(side='left', fill='x', expand=True)
        scrollbar = ttk.Scrollbar(peers_container, orient='vertical', command=self.peer_listbox.yview)
        scrollbar.pack(side='right', fill='y')
        self.peer_listbox.config(yscrollcommand=scrollbar.set)
        self.update_peer_list()  # Initialize peer list

        # Balance and Chain Height
        self.balance_label = ttk.Label(status_frame, text="Balance: 0.0")
        self.balance_label.grid(row=2, column=0, sticky='w', padx=5, pady=5)
        self.chain_height_label = ttk.Label(status_frame, text="Chain Height: 0")
        self.chain_height_label.grid(row=2, column=1, sticky='e', padx=5, pady=5)

        # Output Text for Logs
        ttk.Label(status_frame, text="Logs:").grid(row=3, column=0, sticky='w', padx=5, pady=5)
        self.output = scrolledtext.ScrolledText(status_frame, width=70, height=10)
        self.output.grid(row=4, column=0, columnspan=2, sticky='nsew', padx=5, pady=5)

        # Mempool Text
        ttk.Label(status_frame, text="Mempool:").grid(row=5, column=0, sticky='w', padx=5, pady=5)
        self.mempool_text = scrolledtext.ScrolledText(status_frame, width=70, height=3)
        self.mempool_text.grid(row=6, column=0, columnspan=2, sticky='nsew', padx=5, pady=5)

        # Configure grid weights
        status_frame.grid_columnconfigure(0, weight=1)
        status_frame.grid_columnconfigure(1, weight=1)
        self.main_frame.grid_rowconfigure(5, weight=1)  # Allow status panel to expand vertically

    def create_footer(self):
        """Create the footer with the exit button."""
        bottom_frame = ttk.Frame(self.root)
        bottom_frame.pack(side='bottom', fill='x', pady=(0, 10))
        self.exit_button = ttk.Button(bottom_frame, text="Exit", command=self.exit)
        self.exit_button.pack(side='right', padx=10)

    def load_wallets(self):
        """Load wallets from the wallet file."""
        try:
            with open(self.wallet_file, 'r') as f:
                self.wallets = json.load(f)
            logger.info(f"Loaded wallets from {self.wallet_file}")
        except (FileNotFoundError, json.JSONDecodeError):
            logger.info(f"No valid wallet file found at {self.wallet_file}. Starting with empty wallets.")
            self.wallets = {}

    def save_wallets(self):
        """Save wallets to the wallet file."""
        with open(self.wallet_file, 'w') as f:
            json.dump(self.wallets, f)
        logger.info(f"Saved wallets to {self.wallet_file}")
        self.update_wallet_dropdown()

    def update_wallet_dropdown(self):
        """Update the wallet dropdown menu."""
        menu = self.wallet_dropdown["menu"]
        menu.delete(0, "end")
        options = list(self.wallets.keys())
        if not options:
            menu.add_command(label="No wallets", command=lambda: self.wallet_var.set(""))
        else:
            for name in options:
                menu.add_command(label=name, command=lambda n=name: self.wallet_var.set(n))
            current_entry = self.wallet_entry.get().strip()
            if current_entry in options:
                self.wallet_var.set(current_entry)
            elif options and not self.wallet_var.get():
                self.wallet_var.set(options[0])
        logger.info(f"Updated wallet dropdown with options: {options}")

    def on_entry_change(self, event):
        """Update dropdown selection when typing in the wallet entry field."""
        name = self.wallet_entry.get().strip()
        if name in self.wallets:
            self.wallet_var.set(name)
        else:
            self.wallet_var.set("")
        self.update_balance()

    def on_dropdown_select(self, *args):
        """Update entry field when selecting from the dropdown."""
        name = self.wallet_var.get()
        if name and name != "No wallets":
            self.wallet_entry.delete(0, tk.END)
            self.wallet_entry.insert(0, name)
        self.update_balance()

    def update_balance(self):
        """Update the balance display based on the selected wallet."""
        name = self.wallet_entry.get().strip()
        if name and name in self.wallets:
            balance = self.blockchain.get_balance(self.wallets[name]["address"])
            self.balance_label.config(text=f"Balance: {balance}")
        else:
            self.balance_label.config(text="Balance: 0.0")

    def create_wallet(self):
        """Create a new wallet with a user-provided name."""
        name = tkinter.simpledialog.askstring("Input", "Enter wallet name:", parent=self.root)
        if not name or any(n.lower() == name.lower() for n in self.wallets):
            messagebox.showerror("Error", "Wallet name must be unique (case-insensitive)")
            return
        wallet = generate_wallet()
        self.wallets[name] = wallet
        self.save_wallets()
        output = f"Created wallet '{name}':\nAddress: {wallet['address']}\nPrivate Key: {wallet['private_key']}\nPublic Key: {wallet['public_key']}\n"
        self.output.insert(tk.END, output)  # Now works with added self.output
        self.wallet_entry.delete(0, tk.END)
        self.wallet_entry.insert(0, name)
        self.update_balance()

    def add_peer(self):
        """Add a peer to the network based on user input."""
        host = self.peer_host_entry.get().strip()
        port_str = self.peer_port_entry.get().strip()
        if not host or not port_str:
            messagebox.showerror("Error", "Please provide both host and port for the peer")
            return
        try:
            port = int(port_str)
            if port < 1 or port > 65535:
                raise ValueError("Port must be between 1 and 65535")
            peer_id = f"node{port}"
            self.network.add_peer(peer_id, host, port)
            self.update_peer_list()
            self.output.insert(tk.END, f"Added peer {peer_id} at {host}:{port}\n")
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid port: {e}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to add peer: {e}")

    def update_peer_list(self):
        """Update the peer listbox with current peers."""
        self.peer_listbox.delete(0, tk.END)
        for peer_id, (host, port) in self.network.peers.items():
            self.peer_listbox.insert(tk.END, f"{peer_id}: {host}:{port}")

    def start_mining(self):
        """Start mining with the selected wallet."""
        name = self.wallet_entry.get().strip()
        if not name:
            messagebox.showerror("Error", "Please enter or select a wallet name")
            return
        if name not in self.wallets:
            messagebox.showerror("Error", f"Wallet '{name}' does not exist. Please create it first.")
            return
        wallet = self.wallets.get(name)
        self.miner.wallet_address = wallet["address"]
        self.miner.start_mining()
        self.output.insert(tk.END, f"Mining started with wallet '{name}'\n")

    def stop_mining(self):
        """Stop the mining process."""
        self.miner.stop_mining()
        self.output.insert(tk.END, "Mining stopped\n")

    def send_transaction(self):
        """Send a transaction from the selected wallet to a recipient."""
        from_name = self.wallet_entry.get().strip()
        to_address = self.to_entry.get().strip()
        amount = self.amount_entry.get().strip()
        if not from_name or not to_address or not amount:
            messagebox.showerror("Error", "Please provide wallet name, recipient address, and amount")
            return
        if from_name not in self.wallets:
            messagebox.showerror("Error", f"Wallet '{from_name}' does not exist. Please create it first.")
            return
        wallet = self.wallets.get(from_name)
        try:
            amount = float(amount)
            tx = self.blockchain.create_transaction(
                wallet["private_key"],
                wallet["address"],
                to_address,
                amount,
                fee=0.001
            )
            if tx and self.blockchain.add_transaction_to_mempool(tx):
                if self.network.loop.is_running():
                    # Create the coroutine object only once
                    coro = self.network.broadcast_transaction(tx)
                    # Schedule it to run in the event loop
                    asyncio.run_coroutine_threadsafe(coro, self.network.loop)
                    logger.info(f"Transaction {tx.tx_id} broadcast scheduled")
                    self.output.insert(tk.END, f"Transaction sent: {tx.tx_id}\n")
                else:
                    logger.error("Event loop is not running")
                    self.output.insert(tk.END, "Error: Event loop not running, transaction not broadcast.\n")
            else:
                balance = self.blockchain.get_balance(wallet["address"])
                self.output.insert(tk.END, f"Failed to create/add transaction. Balance: {balance}, Required: {amount + 0.001}\n")
        except ValueError:
            messagebox.showerror("Error", "Amount must be a number")
        except Exception as e:
            logger.error(f"Error sending transaction: {e}")
            self.output.insert(tk.END, f"Error sending transaction: {e}\n")

    def on_new_block(self, block: Block):
        """Handle new block event."""
        self.update_queue.put(("block", block))

    def on_new_transaction(self, tx: Transaction):
        """Handle new transaction event."""
        self.update_queue.put(("transaction", tx))

    def update_ui(self):
        """Update the UI with real-time data."""
        while not self.update_queue.empty():
            event_type, data = self.update_queue.get()
            if event_type == "block":
                self.output.insert(tk.END, f"New block mined: {data.index}\n")
                self.chain_height_label.config(text=f"Chain Height: {len(self.blockchain.chain) - 1}")
                self.update_balance()
            elif event_type == "transaction":
                self.output.insert(tk.END, f"New transaction in mempool: {data.tx_id[:8]}\n")
        
        # Update mempool display
        self.mempool_text.delete(1.0, tk.END)
        mempool_txs = self.blockchain.mempool.transactions.values()
        for tx in mempool_txs:
            self.mempool_text.insert(tk.END, f"{tx.tx_id[:8]}: {tx.outputs[0].amount} to {tx.outputs[0].recipient[:8]}...\n")
        
        self.root.after(1000, self.update_ui)

    def exit(self):
        """Handle application exit."""
        self.miner.stop_mining()
        self.root.quit()

    def run(self):
        """Run the GUI main loop."""
        self.update_wallet_dropdown()
        self.root.mainloop()

import socket

def is_port_available(port, host='localhost'):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if s.connect_ex((host, port)) == 0:
            return False  # Port is not available
        else:
            return True  # Port is available

def find_available_port(start_port=1024, end_port=65535, host='localhost'):
    port = random.randint(start_port, end_port)
    while not is_port_available(port, host):
        logger.info(f"Port {port} is not available, trying another...")
        port = random.randint(start_port, end_port)
    logger.info(f"Found available port: {port}")
    return port

if __name__ == "__main__":
    import sys
    port = find_available_port()
    node_id = f"node{port}"
    blockchain = Blockchain()
    network = BlockchainNetwork(blockchain, node_id, "127.0.0.1", port)
    network_thread = threading.Thread(target=network.run)
    network_thread.daemon = True
    network_thread.start()
    network.start_periodic_sync()
    gui = BlockchainGUI(blockchain, network, wallet_file="wallets.json")
    gui.run()