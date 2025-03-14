import threading
import asyncio
import aiohttp
import aiohttp.web
import json
import time
import hashlib
import logging
import logging.handlers
import ecdsa
import os
import base64
import ssl
import re
import psycopg2  # Add this
from typing import List, Dict, Optional, Any, Callable
from dataclasses import dataclass
from enum import Enum
from queue import Queue
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox, scrolledtext
import tkinter.simpledialog
import random
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
import socket
from prometheus_client import Counter, Gauge, start_http_server
from dotenv import load_dotenv
import getpass
from acme import client, messages, challenges
from josepy import JWKRSA
from pathlib import Path

# Configure logging with rotation
handler = logging.handlers.RotatingFileHandler("originalcoin.log", maxBytes=5*1024*1024, backupCount=3)
logging.basicConfig(level=logging.INFO, handlers=[handler], format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Blockchain")

# Define Prometheus metrics
BLOCKS_MINED = Counter('blocks_mined_total', 'Total number of blocks mined')
PEER_COUNT = Gauge('peer_count', 'Number of connected peers')

# Load environment variables
load_dotenv()

class SecureConfigManager:
    def __init__(self, app_name: str = "OriginalCoin", config_dir: Optional[str] = None):
        self.app_name = app_name
        self.config_dir = Path(config_dir) if config_dir else Path.home() / ".originalcoin"
        self.config_dir.mkdir(exist_ok=True, parents=True)
        self.secrets_file = self.config_dir / "secrets.enc"
        self.config_file = self.config_dir / "config.json"
        self.cert_file = self.config_dir / "cert.pem"
        self.key_file = self.config_dir / "key.pem"
        self.account_key_file = self.config_dir / "account_key.pem"
        
        self.default_config = {
            "network": {
                "port": 8443,
                "max_peers": 100,
                "bootstrap_nodes": ["node1.example.com:8443", "node2.example.com:8443"],
                "ssl_enabled": True,
                "max_retries": 3,
                "acme_directory": "https://acme-v02.api.letsencrypt.org/directory"
            },
            "blockchain": {
                "difficulty": 4,
                "target_block_time": 60,
                "halving_interval": 210000,
                "initial_reward": 50,
                "max_block_size": 1000000,
                "sync_interval": 300
            },
            "mempool": {"max_size": 5000, "min_fee_rate": 0.00001},
            "storage": {
                "blockchain_path": str(self.config_dir / "blockchain.db"),
                "wallet_path": str(self.config_dir / "wallets.enc")
            },
            "security": {
                "cert_validity_days": 90,
                "key_rotation_interval": 24 * 3600,
                "domain": os.environ.get("ORIGINALCOIN_DOMAIN", "localhost")
            }
        }
        
        self._load_or_create_config()
        self.secrets_cache = {}
        self.master_key = None
        self._initialize_master_key()
        self._ensure_certificates()

    def _load_or_create_config(self):
        if not self.config_file.exists():
            with open(self.config_file, 'w') as f:
                json.dump(self.default_config, f, indent=4)
        with open(self.config_file, 'r') as f:
            self.config = json.load(f)
        self._deep_update(self.config, self.default_config)

    def _deep_update(self, target: dict, source: dict):
        for key, value in source.items():
            if isinstance(value, dict) and key in target:
                self._deep_update(target[key], value)
            else:
                target.setdefault(key, value)

    def _initialize_master_key(self):
        master_key_env = os.environ.get("ORIGINALCOIN_MASTER_KEY")
        if master_key_env:
            self.master_key = base64.urlsafe_b64decode(master_key_env)
        else:
            self.master_key = Fernet.generate_key()
            logger.warning("No master key in environment; generated temporary key. Set ORIGINALCOIN_MASTER_KEY for persistence.")

    def get_config(self, section: str, key: str, default: Any = None) -> Any:
        return self.config.get(section, {}).get(key, default)

    def set_secret(self, key: str, value: str):
        cipher = Fernet(self.master_key)
        encrypted = cipher.encrypt(value.encode())
        secrets = self._load_secrets()
        secrets[key] = base64.b64encode(encrypted).decode()
        with open(self.secrets_file, 'w') as f:
            json.dump(secrets, f)

    def get_secret(self, key: str) -> Optional[str]:
        if key in self.secrets_cache:
            return self.secrets_cache[key]
        secrets = self._load_secrets()
        if key in secrets:
            cipher = Fernet(self.master_key)
            encrypted = base64.b64decode(secrets[key])
            value = cipher.decrypt(encrypted).decode()
            self.secrets_cache[key] = value
            return value
        return None

    def _load_secrets(self) -> Dict[str, str]:
        try:
            with open(self.secrets_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def encrypt_wallet_data(self, data: Dict[str, Any], password: str) -> tuple[bytes, bytes]:
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        cipher = Fernet(key)
        return cipher.encrypt(json.dumps(data).encode()), salt

    def decrypt_wallet_data(self, encrypted_data: bytes, salt: bytes, password: str) -> Dict[str, Any]:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        cipher = Fernet(key)
        return json.loads(cipher.decrypt(encrypted_data).decode())

    def _ensure_certificates(self):
        if os.environ.get("ORIGINALCOIN_USE_ACME", "false").lower() == "true":
            self._renew_acme_certificate()
        elif not self.cert_file.exists() or not self.key_file.exists() or self._is_cert_expired():
            self._generate_self_signed_certificate()

    def _generate_self_signed_certificate(self):
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.get_config("security", "domain"))])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now())
            .not_valid_after(datetime.now() + timedelta(days=self.get_config("security", "cert_validity_days")))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(self.get_config("security", "domain"))]), critical=False)
            .sign(private_key, hashes.SHA256())
        )
        
        with open(self.cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(self.key_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        logger.info(f"Generated self-signed certificate at {self.cert_file}")

    def _renew_acme_certificate(self):
        domain = self.get_config("security", "domain")
        if domain == "localhost":
            logger.warning("Cannot use ACME with localhost; falling back to self-signed")
            self._generate_self_signed_certificate()
            return
        
        if not self.account_key_file.exists():
            account_key = ec.generate_private_key(ec.SECP256R1())
            with open(self.account_key_file, "wb") as f:
                f.write(account_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
        else:
            with open(self.account_key_file, "rb") as f:
                account_key = serialization.load_pem_private_key(f.read(), password=None)
        
        acme_client = client.ClientV2(
            client.ClientNetwork(JWKRSA(key=account_key), directory=self.get_config("network", "acme_directory"))
        )
        
        order = acme_client.new_order([domain])
        for authz in order.authorizations:
            challenge = next(ch for ch in authz.challenges if isinstance(ch, challenges.HTTP01))
            logger.info(f"Add this to your web server at http://{domain}/.well-known/acme-challenge/{challenge.token}: {challenge.validation}")
            time.sleep(10)  # Simulate manual verification
            acme_client.answer_challenge(challenge, challenge.validation)
        
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, domain)
        ])).sign(account_key, hashes.SHA256())
        
        finalized_order = acme_client.finalize_order(order, datetime.utcnow() + timedelta(days=1), csr)
        with open(self.cert_file, "wb") as f:
            f.write(finalized_order.fullchain_pem.encode())
        with open(self.key_file, "wb") as f:
            f.write(account_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        logger.info(f"Renewed certificate via ACME at {self.cert_file}")

    def _is_cert_expired(self) -> bool:
        try:
            with open(self.cert_file, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
            return cert.not_valid_after_utc < datetime.now()
        except Exception:
            return True

    def get_tls_config(self) -> Dict[str, str]:
        return {"cert": str(self.cert_file), "key": str(self.key_file)}

    def generate_auth_key(self) -> str:
        random_bytes = os.urandom(32)
        auth_key = base64.urlsafe_b64encode(random_bytes).decode('utf-8')
        self.set_secret("auth_key", auth_key)
        return auth_key

    def rotate_auth_key(self) -> str:
        new_key = self.generate_auth_key()
        logger.info("Authentication key rotated")
        return new_key

config_manager = SecureConfigManager()

async def rate_limit_middleware(app, handler):
    async def middleware_handler(request):
        client_ip = request.remote
        if not hasattr(app, '_rate_limit'):
            app._rate_limit = {}
        if client_ip not in app._rate_limit:
            app._rate_limit[client_ip] = {'count': 0, 'reset': time.time() + 60}
        
        now = time.time()
        if now > app._rate_limit[client_ip]['reset']:
            app._rate_limit[client_ip] = {'count': 0, 'reset': now + 60}
        
        if app._rate_limit[client_ip]['count'] >= 100:
            raise aiohttp.web.HTTPTooManyRequests(text="Rate limit exceeded")
        
        app._rate_limit[client_ip]['count'] += 1
        return await handler(request)
    return middleware_handler

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
    public_key: Optional[str] = None
    signature: Optional[bytes] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tx_id": self.tx_id,
            "output_index": self.output_index,
            "public_key": self.public_key,
            "signature": self.signature.hex() if self.signature else None
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TransactionInput':
        signature = bytes.fromhex(data["signature"]) if data.get("signature") else None
        return cls(tx_id=data["tx_id"], output_index=data["output_index"], public_key=data.get("public_key"), signature=signature)

class Transaction:
    def __init__(self, tx_type: TransactionType, inputs: List[TransactionInput], outputs: List[TransactionOutput], fee: float = 0.0, nonce: Optional[int] = None):
        self.tx_type = tx_type
        self.inputs = inputs
        self.outputs = outputs
        self.fee = fee
        self.nonce = nonce or random.randint(0, 2**32)
        self.tx_id = None
        self.tx_id = self.calculate_tx_id()

    def calculate_tx_id(self) -> str:
        data = {
            "tx_type": self.tx_type.value,
            "inputs": [i.to_dict() for i in self.inputs],
            "outputs": [o.to_dict() for o in self.outputs],
            "fee": self.fee,
            "nonce": self.nonce
        }
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

    def sign_transaction(self, private_key: ecdsa.SigningKey, public_key: ecdsa.VerifyingKey) -> None:
        data = json.dumps(self.to_dict(), sort_keys=True).encode()
        for tx_input in self.inputs:
            tx_input.signature = private_key.sign(data)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tx_type": self.tx_type.value,
            "inputs": [i.to_dict() for i in self.inputs],
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

class TransactionFactory:
    @staticmethod
    def create_coinbase_transaction(recipient: str, amount: float, block_height: int) -> Transaction:
        tx_id = hashlib.sha256(f"coinbase_{block_height}_{recipient}".encode()).hexdigest()
        inputs = [TransactionInput(tx_id=tx_id, output_index=-1)]
        outputs = [TransactionOutput(recipient=recipient, amount=amount)]
        return Transaction(tx_type=TransactionType.COINBASE, inputs=inputs, outputs=outputs)

class BlockHeader:
    def __init__(self, index: int, previous_hash: str, timestamp: float, difficulty: int, merkle_root: str, nonce: int = 0):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.difficulty = difficulty
        self.merkle_root = merkle_root
        self.nonce = nonce
        self.hash = self.calculate_hash()

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
            nonce=data.get("nonce", 0)
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
        self.utxos: Dict[str, Dict[int, TransactionOutput]] = {}
        self.used_nonces: Dict[str, set] = {}

    def update_with_block(self, block: Block) -> None:
        for tx in block.transactions:
            if tx.tx_type != TransactionType.COINBASE:
                for tx_input in tx.inputs:
                    if tx_input.tx_id in self.utxos and tx_input.output_index in self.utxos[tx_input.tx_id]:
                        del self.utxos[tx_input.tx_id][tx_input.output_index]
                        if not self.utxos[tx_input.tx_id]:
                            del self.utxos[tx_input.tx_id]
                if tx.inputs and tx.nonce:
                    address = SecurityUtils.public_key_to_address(tx.inputs[0].public_key)
                    if address not in self.used_nonces:
                        self.used_nonces[address] = set()
                    self.used_nonces[address].add(tx.nonce)
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

    def is_nonce_used(self, address: str, nonce: int) -> bool:
        return address in self.used_nonces and nonce in self.used_nonces[address]

class Mempool:
    def __init__(self):
        self.transactions: Dict[str, Transaction] = {}
        self.timestamps: Dict[str, float] = {}
        self.max_size = config_manager.get_config("mempool", "max_size")

    def add_transaction(self, tx: Transaction) -> bool:
        if tx.tx_id not in self.transactions:
            if len(self.transactions) >= self.max_size:
                oldest_tx_id = min(self.timestamps.items(), key=lambda x: x[1])[0]
                del self.transactions[oldest_tx_id]
                del self.timestamps[oldest_tx_id]
            self.transactions[tx.tx_id] = tx
            self.timestamps[tx.tx_id] = time.time()
            return True
        return False

    def get_transactions(self, max_txs: int, max_size: int) -> List[Transaction]:
        sorted_txs = sorted(
            self.transactions.values(),
            key=lambda tx: (tx.fee / (len(json.dumps(tx.to_dict())) / 1024), -self.timestamps[tx.tx_id]),
            reverse=True
        )
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

    def start_mining(self) -> None:
        if self.mining_thread and self.mining_thread.is_alive():
            logger.info("Mining already running")
            return
        logger.info("Starting mining thread")
        self.mining_thread = threading.Thread(target=self._mine_continuously_thread, daemon=True)
        self.mining_thread.start()

    def stop_mining(self) -> None:
        if self.mining_thread:
            logger.info("Stopping mining thread")
            # Daemon thread stops with program exit

    def _mine_continuously_thread(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self._mine_continuously())

    async def _mine_continuously(self) -> None:
        while True:
            self._create_new_block()
            if await self._mine_current_block():
                success = await self.blockchain.add_block(self.current_block)
                if success:
                    tx_ids = [tx.tx_id for tx in self.current_block.transactions]
                    self.mempool.remove_transactions(tx_ids)
                    logger.info(f"Successfully mined block {self.current_block.index}")
                    if hasattr(self.blockchain, 'network'):
                        self.blockchain.network.broadcast_block(self.current_block)
            await asyncio.sleep(0.01)

    async def _mine_current_block(self) -> bool:
        target = "0" * self.blockchain.difficulty
        nonce = 0
        while True:
            self.current_block.header.nonce = nonce
            block_hash = self.current_block.header.calculate_hash()
            if block_hash.startswith(target):
                self.current_block.header.hash = block_hash
                return True
            nonce += 1
            if nonce % 10000 == 0:
                await asyncio.sleep(0)

    def _create_new_block(self) -> None:
        latest_block = self.blockchain.chain[-1]
        transactions = self.mempool.get_transactions(1000, config_manager.get_config("blockchain", "max_block_size"))
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

class Blockchain:
    def __init__(self, db_config: dict = None):
        self.chain: List[Block] = []
        self.db_config = db_config or {
            "dbname": "originalcoin",
            "user": "postgres",
            "password": os.environ.get("PG_PASSWORD", "yourpassword"),
            "host": "localhost",
            "port": "5432"
        }
        self.difficulty = config_manager.get_config("blockchain", "difficulty")
        self.current_reward = config_manager.get_config("blockchain", "initial_reward")
        self.halving_interval = config_manager.get_config("blockchain", "halving_interval")
        self.mempool = Mempool()
        self.utxo_set = UTXOSet()
        self.orphans: Dict[str, Block] = {}
        self.lock = threading.Lock()
        self.listeners = {"new_block": [], "new_transaction": []}
        self.db = psycopg2.connect(**self.db_config)
        self.initialize_db()
        self.load_chain()

    def initialize_db(self):
        with self.db.cursor() as cur:
            cur.execute('''CREATE TABLE IF NOT EXISTS blocks (
                            index INTEGER PRIMARY KEY,
                            data JSONB NOT NULL
                        )''')
            self.db.commit()
        logger.info("Database initialized")

    def subscribe(self, event: str, callback: Callable) -> None:
        if event in self.listeners:
            self.listeners[event].append(callback)

    def trigger_event(self, event: str, data: Any) -> None:
        for callback in self.listeners[event]:
            callback(data)

    def load_chain(self) -> None:
        try:
            with self.db.cursor() as cur:
                cur.execute("SELECT data FROM blocks ORDER BY index")
                rows = cur.fetchall()
                if rows:
                    self.chain = [Block.from_dict(row[0]) for row in rows]
                else:
                    genesis_block = Block(index=0, transactions=[], previous_hash="0" * 64, difficulty=self.difficulty)
                    self.chain.append(genesis_block)
                    self.save_chain()
            for block in self.chain:
                self.utxo_set.update_with_block(block)
        except psycopg2.Error as e:
            logger.error(f"Failed to load chain: {e}")
            raise

    def save_chain(self) -> None:
        with self.lock:
            try:
                with self.db.cursor() as cur:
                    cur.execute("DELETE FROM blocks")
                    for block in self.chain:
                        cur.execute("INSERT INTO blocks (index, data) VALUES (%s, %s)", (block.index, json.dumps(block.to_dict())))
                    self.db.commit()
            except psycopg2.Error as e:
                logger.error(f"Failed to save chain: {e}")
                self.db.rollback()
                raise

    async def validate_block(self, block: Block) -> bool:
        if block.index > 0:
            if block.index > len(self.chain):
                return False
            prev_block = self.chain[block.index - 1]
            if block.header.timestamp <= prev_block.header.timestamp:
                return False
            if block.header.previous_hash != prev_block.header.hash:
                return False

        if block.header.timestamp > time.time() + 2 * 3600:
            return False

        if not block.transactions or block.transactions[0].tx_type != TransactionType.COINBASE:
            return False
        coinbase_amount = sum(o.amount for o in block.transactions[0].outputs)
        if coinbase_amount > self.current_reward:
            return False

        spent_utxos = set()
        for tx in block.transactions[1:]:
            if tx.tx_type == TransactionType.COINBASE:
                return False
            for tx_input in tx.inputs:
                utxo_key = (tx_input.tx_id, tx_input.output_index)
                if utxo_key in spent_utxos:
                    return False
                spent_utxos.add(utxo_key)
                if tx_input.public_key:
                    address = SecurityUtils.public_key_to_address(tx_input.public_key)
                    if self.utxo_set.is_nonce_used(address, tx.nonce):
                        return False

        target = "0" * block.header.difficulty
        if not block.header.hash.startswith(target):
            return False

        calculated_merkle_root = calculate_merkle_root(block.transactions)
        if block.header.merkle_root != calculated_merkle_root:
            return False

        tasks = [asyncio.create_task(self.validate_transaction(tx)) for tx in block.transactions]
        results = await asyncio.gather(*tasks)
        return all(results)

    async def add_block(self, block: Block) -> bool:
        with self.lock:
            if any(b.header.hash == block.header.hash for b in self.chain):
                return False
            if block.index == len(self.chain) and block.header.previous_hash == self.chain[-1].header.hash:
                if await self.validate_block(block):
                    self.chain.append(block)
                    self.utxo_set.update_with_block(block)
                    if len(self.chain) % 2016 == 0:
                        self.adjust_difficulty()
                    if len(self.chain) % self.halving_interval == 0:
                        self.halve_block_reward()
                    self.trigger_event("new_block", block)
                    self.save_chain()
                    self._process_orphans()
                    BLOCKS_MINED.inc()
                    return True
            else:
                self.handle_potential_fork(block)
            return False

    def _process_orphans(self):
        for hash, orphan in list(self.orphans.items()):
            if orphan.header.previous_hash == self.chain[-1].header.hash and orphan.index == len(self.chain):
                if self.validate_block(orphan):
                    self.chain.append(orphan)
                    self.utxo_set.update_with_block(orphan)
                    self.trigger_event("new_block", orphan)
                    self.save_chain()
                    del self.orphans[hash]
                    self._process_orphans()
                    break

    def create_transaction(self, sender_private_key: str, sender_address: str, recipient_address: str, amount: float, fee: float = 0.001) -> Optional[Transaction]:
        private_key = ecdsa.SigningKey.from_string(bytes.fromhex(sender_private_key), curve=ecdsa.SECP256k1)
        public_key = private_key.get_verifying_key()
        public_key_hex = public_key.to_string().hex()
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
        inputs = [TransactionInput(tx_id, output_index, public_key_hex) for tx_id, output_index, _ in selected_utxos]
        outputs = [TransactionOutput(recipient_address, amount)]
        if selected_amount > amount + fee:
            outputs.append(TransactionOutput(sender_address, selected_amount - amount - fee))
        tx = Transaction(tx_type=TransactionType.REGULAR, inputs=inputs, outputs=outputs, fee=fee)
        tx.sign_transaction(private_key, public_key)
        return tx

    async def validate_transaction(self, tx: Transaction) -> bool:
        if tx.tx_type == TransactionType.COINBASE:
            return True
        if not tx.inputs or not tx.outputs:
            return False
        input_sum = 0
        for tx_input in tx.inputs:
            utxo = self.utxo_set.get_utxo(tx_input.tx_id, tx_input.output_index)
            if not utxo or not tx_input.public_key or not tx_input.signature:
                return False
            address = SecurityUtils.public_key_to_address(tx_input.public_key)
            if address != utxo.recipient or self.utxo_set.is_nonce_used(address, tx.nonce):
                return False
            public_key_obj = ecdsa.VerifyingKey.from_string(bytes.fromhex(tx_input.public_key), curve=ecdsa.SECP256k1)
            try:
                public_key_obj.verify(tx_input.signature, json.dumps(tx.to_dict(), sort_keys=True).encode())
            except ecdsa.BadSignatureError:
                return False
            input_sum += utxo.amount
        output_sum = sum(output.amount for output in tx.outputs)
        return output_sum <= input_sum and abs(input_sum - output_sum - tx.fee) < 0.0001

    def add_transaction_to_mempool(self, tx: Transaction) -> bool:
        if not self.validate_transaction(tx):
            return False
        success = self.mempool.add_transaction(tx)
        if success:
            self.trigger_event("new_transaction", tx)
        return success

    def get_balance(self, address: str) -> float:
        return self.utxo_set.get_balance(address)

    def adjust_difficulty(self):
        if len(self.chain) % 2016 != 0:
            return
        period_blocks = self.chain[-2016:]
        time_taken = period_blocks[-1].header.timestamp - period_blocks[0].header.timestamp
        target_time = 2016 * config_manager.get_config("blockchain", "target_block_time")
        if time_taken == 0:
            return
        ratio = target_time / time_taken
        self.difficulty = max(1, min(20, int(self.difficulty * ratio)))

    def halve_block_reward(self) -> None:
        self.current_reward /= 2

    def handle_potential_fork(self, block: Block) -> None:
        with self.lock:
            if block.index <= len(self.chain) - 1:
                return
            if block.index > len(self.chain):
                self.orphans[block.header.hash] = block
            if hasattr(self, 'network') and self.network:
                asyncio.run_coroutine_threadsafe(self.network.request_chain(), self.network.loop)

    async def request_chain(self) -> None:
        for peer_id, (host, port) in self.network.peers.items():
            try:
                async with aiohttp.ClientSession() as session:
                    url = f"https://{host}:{port}/get_chain"
                    async with session.get(url) as response:
                        if response.status == 200:
                            chain_data = await response.json()
                            new_chain = [Block.from_dict(b) for b in chain_data]
                            if self.validate_and_replace_chain(new_chain):
                                break
            except Exception as e:
                logger.error(f"Error requesting chain from {peer_id}: {e}")

    def validate_and_replace_chain(self, new_chain: List[Block]) -> bool:
        current_work = sum(b.header.difficulty for b in self.chain) + len(self.orphans) * self.difficulty
        new_work = sum(b.header.difficulty for b in new_chain)
        if new_work <= current_work or not self.validate_chain(new_chain):
            return False
        with self.lock:
            self.chain = new_chain
            self.utxo_set = UTXOSet()
            for block in self.chain:
                self.utxo_set.update_with_block(block)
            self.save_chain()
            self._process_orphans()
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
        self.peers: Dict[str, tuple[str, int, str]] = {}
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.app = aiohttp.web.Application(middlewares=[rate_limit_middleware])
        self.app.add_routes([
            aiohttp.web.post('/receive_block', self.receive_block),
            aiohttp.web.post('/receive_transaction', self.receive_transaction),
            aiohttp.web.get('/get_chain', self.get_chain),
            aiohttp.web.post('/update_auth_key', self.receive_auth_key),
            aiohttp.web.get('/get_peers', self.get_peers)
        ])
        self.blockchain.network = self
        self.config_manager = config_manager
        self.private_key, self.public_key = self._generate_node_keypair()
        self.public_key_str = self.public_key.to_string().hex()
        self.running = True
        self.peer_file = config_manager.config_dir / "peers.json"
        self.load_peers()

    def _generate_node_keypair(self) -> tuple[ecdsa.SigningKey, ecdsa.VerifyingKey]:
        private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        return private_key, private_key.get_verifying_key()
    
    def load_peers(self):
        try:
            with open(self.peer_file, 'r') as f:
                peers = json.load(f)
                for peer_id, (host, port, pub_key) in peers.items():
                    self.add_peer(peer_id, host, port, self.config_manager.get_secret("auth_key"), pub_key)
        except FileNotFoundError:
            pass

    def add_peer(self, peer_id: str, host: str, port: int, auth_key: str = None, peer_public_key: str = None):
        expected_key = self.config_manager.get_secret("auth_key")
        if not expected_key:
            expected_key = self.config_manager.generate_auth_key()
        if auth_key != expected_key or not peer_public_key:
            logger.warning(f"Peer {peer_id} failed authentication or missing public key")
            return
        self.peers[peer_id] = (host, port, peer_public_key)
        logger.info(f"Authenticated peer {peer_id} added: {host}:{port}")
        PEER_COUNT.set(len(self.peers))
        self.save_peers()

    def save_peers(self):
        with open(self.peer_file, 'w') as f:
            json.dump({peer_id: (host, port, pub_key) for peer_id, (host, port, pub_key) in self.peers.items()}, f)

    def run(self) -> None:
        runner = aiohttp.web.AppRunner(self.app)
        self.loop.run_until_complete(runner.setup())
        
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_config = self.config_manager.get_tls_config()
        ssl_context.load_cert_chain(certfile=tls_config["cert"], keyfile=tls_config["key"])
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        ssl_context.load_verify_locations(cafile=str(config_manager.cert_file))
        
        site = aiohttp.web.TCPSite(runner, self.host, self.port, ssl_context=ssl_context)
        self.loop.run_until_complete(site.start())
        logger.info(f"Network server running on https://{self.host}:{self.port}")
        self.loop.run_forever()
        try:
            self.loop.run_forever()
        except KeyboardInterrupt:
            self.shutdown()

    def shutdown(self):
        self.running = False
        tasks = asyncio.all_tasks(self.loop)
        for task in tasks:
            task.cancel()
        self.loop.run_until_complete(self.app.shutdown())
        self.loop.run_until_complete(self.app.cleanup())
        self.loop.close()
        logger.info("Network server shut down")

    async def send_with_retry(self, url: str, data: dict, method: str = "post", max_retries: int = config_manager.get_config("network", "max_retries")):
        peer_id = next((pid for pid, (h, p, _) in self.peers.items() if f"{h}:{p}" in url), None)
        for attempt in range(max_retries):
            try:
                ssl_context = ssl.create_default_context(cafile=str(config_manager.cert_file))
                ssl_context.verify_mode = ssl.CERT_REQUIRED
                
                for attempt in range(max_retries):
                    try:
                        async with aiohttp.ClientSession() as session:
                            if method == "post":
                                async with session.post(url, json=data, ssl=ssl_context, timeout=aiohttp.ClientTimeout(total=5)) as response:
                                    return response.status == 200
                            elif method == "get":
                                async with session.get(url, ssl=ssl_context, timeout=aiohttp.ClientTimeout(total=5)) as response:
                                    return response.status == 200, await response.json()
                    except Exception as e:
                        if attempt == max_retries - 1:
                            logger.error(f"Failed after {max_retries} attempts to {url}: {e}")
                            return False if method == "post" else (False, None)
                        await asyncio.sleep(0.5 * (2 ** attempt))
                if peer_id:
                    self.peers[peer_id] = (self.peers[peer_id][0], self.peers[peer_id][1], self.peers[peer_id][2])  # Reset failure count implicitly
                return response.status == 200 if method == "post" else (response.status == 200, await response.json())
            except aiohttp.ClientConnectionError as e:
                if peer_id and attempt == max_retries - 1:
                    logger.warning(f"Removing unresponsive peer {peer_id} after {max_retries} attempts")
                    del self.peers[peer_id]
                    self.save_peers()
                    PEER_COUNT.set(len(self.peers))
                await asyncio.sleep(0.5 * (2 ** attempt))
        return False if method == "post" else (False, None)

    def broadcast_block(self, block: Block) -> None:
        tasks = [self.send_block(peer_id, host, port, block) for peer_id, (host, port, _) in self.peers.items() if peer_id != self.node_id]
        if tasks:
            asyncio.run_coroutine_threadsafe(asyncio.gather(*tasks, return_exceptions=True), self.loop)

    async def send_block(self, peer_id: str, host: str, port: int, block: Block) -> None:
        url = f"https://{host}:{port}/receive_block"
        data = {"block": block.to_dict()}
        success = await self.send_with_retry(url, data)
        if success:
            logger.info(f"Sent block {block.index} to {peer_id}")
        else:
            logger.warning(f"Failed to send block {block.index} to {peer_id}")

    async def receive_block(self, request: aiohttp.web.Request) -> aiohttp.web.Response:
        data = await request.json()
        block = Block.from_dict(data["block"])
        success = await self.blockchain.add_block(block)
        if not success:
            self.blockchain.handle_potential_fork(block)
        return aiohttp.web.Response(status=200)

    async def broadcast_transaction(self, tx: Transaction) -> None:
        tasks = [self.send_transaction(peer_id, host, port, tx) for peer_id, (host, port, _) in self.peers.items() if peer_id != self.node_id]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def send_transaction(self, peer_id: str, host: str, port: int, tx: Transaction) -> None:
        url = f"https://{host}:{port}/receive_transaction"
        data = {"transaction": tx.to_dict()}
        success = await self.send_with_retry(url, data)
        if success:
            logger.info(f"Sent transaction {tx.tx_id[:8]} to {peer_id}")
        else:
            logger.error(f"Failed to send transaction to {peer_id}")

    async def receive_transaction(self, request: aiohttp.web.Request) -> aiohttp.web.Response:
        data = await request.json()
        tx = Transaction.from_dict(data["transaction"])
        self.blockchain.add_transaction_to_mempool(tx)
        return aiohttp.web.Response(status=200)

    async def broadcast_auth_key(self, new_key: str):
        tasks = []
        for peer_id, (host, port, peer_public_key) in self.peers.items():
            try:
                peer_pub_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(peer_public_key))
                encrypted_key = peer_pub_key.encrypt(
                    new_key.encode(),
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
                data = {
                    "encrypted_key": base64.b64encode(encrypted_key).decode(),
                    "signature": self.private_key.sign(new_key.encode()).hex()
                }
                tasks.append(self.send_auth_key(peer_id, host, port, data))
            except Exception as e:
                logger.error(f"Failed to encrypt auth key for {peer_id}: {e}")
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def send_auth_key(self, peer_id: str, host: str, port: int, data: dict):
        url = f"https://{host}:{port}/update_auth_key"
        success = await self.send_with_retry(url, data)
        if success:
            logger.info(f"Sent new auth key to {peer_id}")
        else:
            logger.warning(f"Failed to send auth key to {peer_id}")

    async def receive_auth_key(self, request: aiohttp.web.Request) -> aiohttp.web.Response:
        data = await request.json()
        encrypted_key = base64.b64decode(data["encrypted_key"])
        signature = bytes.fromhex(data["signature"])
        
        for peer_id, (_, _, pub_key_str) in self.peers.items():
            try:
                peer_pub_key = ecdsa.VerifyingKey.from_string(bytes.fromhex(pub_key_str), curve=ecdsa.SECP256k1)
                if peer_pub_key.verify(signature, encrypted_key):
                    private_key = ec.EllipticCurvePrivateKey.from_private_numbers(
                        self.private_key.privkey.secret_multiplier, ec.SECP256R1()
                    )
                    new_key = private_key.decrypt(
                        encrypted_key,
                        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                    ).decode()
                    self.config_manager.set_secret("auth_key", new_key)
                    logger.info(f"Received and updated auth key from {peer_id}")
                    break
            except Exception as e:
                logger.debug(f"Failed to verify or decrypt auth key from {peer_id}: {e}")
                continue
        return aiohttp.web.Response(status=200)

    async def get_chain(self, request: aiohttp.web.Request) -> aiohttp.web.Response:
        return aiohttp.web.json_response([block.to_dict() for block in self.blockchain.chain])

    async def request_chain(self) -> None:
        for peer_id, (host, port, _) in self.peers.items():
            try:
                url = f"https://{host}:{port}/get_chain"
                success, chain_data = await self.send_with_retry(url, {}, method="get")
                if success:
                    new_chain = [Block.from_dict(b) for b in chain_data]
                    if self.blockchain.validate_and_replace_chain(new_chain):
                        logger.info(f"Chain updated from peer {peer_id}")
                        break
            except Exception as e:
                logger.error(f"Error requesting chain from {peer_id}: {e}")

    def start_periodic_sync(self, interval=config_manager.get_config("blockchain", "sync_interval")):
        async def sync_task():
            while True:
                await self.request_chain()
                await asyncio.sleep(interval)
        asyncio.run_coroutine_threadsafe(sync_task(), self.loop)

    def start_key_rotation(self, interval=config_manager.get_config("security", "key_rotation_interval")):
        async def rotation_task():
            while True:
                new_key = self.config_manager.rotate_auth_key()
                await self.broadcast_auth_key(new_key)
                logger.info(f"Rotated and broadcasted new auth key: {new_key[:8]}...")
                await asyncio.sleep(interval)
        asyncio.run_coroutine_threadsafe(rotation_task(), self.loop)

    async def discover_peers(self):
        bootstrap_nodes = self.config_manager.get_config("network", "bootstrap_nodes")
        for node in bootstrap_nodes:
            host, port = node.split(":")
            url = f"https://{host}:{port}/get_peers"
            success, peer_data = await self.send_with_retry(url, {}, method="get")
            if success:
                for peer_id, (peer_host, peer_port, pub_key) in peer_data.items():
                    self.add_peer(peer_id, peer_host, int(peer_port), self.config_manager.get_secret("auth_key"), pub_key)
                logger.info(f"Discovered peers from {host}:{port}")
                break
            else:
                logger.warning(f"Failed to discover peers from {host}:{port}")

    async def get_peers(self, request: aiohttp.web.Request) -> aiohttp.web.Response:
        return aiohttp.web.json_response({peer_id: (host, port, pub_key) for peer_id, (host, port, pub_key) in self.peers.items()})

class BlockchainGUI:
    def __init__(self, blockchain: Blockchain, network: BlockchainNetwork):
        self.blockchain = blockchain
        self.network = network
        self.wallets = {}
        self.wallet_path = config_manager.get_config("storage", "wallet_path")
        self.miner = Miner(blockchain, blockchain.mempool, None)
        self.load_wallets()
        self.update_queue = Queue()
        self.root = tk.Tk()
        self.root.title("OriginalCoin GUI")
        self.root.geometry("900x1000")
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        self.create_header()
        self.create_wallet_section()
        self.create_mining_section()
        self.create_transaction_section()
        self.create_peer_section()
        self.create_status_panel()
        self.create_transaction_history()
        self.create_footer()
        self.blockchain.subscribe("new_block", self.on_new_block)
        self.blockchain.subscribe("new_transaction", self.on_new_transaction)
        self.root.after(1000, self.update_ui)
        self.root.protocol("WM_DELETE_WINDOW", self.exit)

    def create_header(self):
        header_frame = ttk.Frame(self.main_frame)
        header_frame.grid(row=0, column=0, sticky='ew', pady=(0, 10))
        ttk.Label(header_frame, text="OriginalCoin", font=("Arial", 24, "bold")).pack(fill='x')
        self.main_frame.grid_columnconfigure(0, weight=1)

    def create_wallet_section(self):
        wallet_frame = ttk.LabelFrame(self.main_frame, text="Wallet", padding=10)
        wallet_frame.grid(row=1, column=0, sticky='ew', pady=5)
        ttk.Label(wallet_frame, text="Wallet:").grid(row=0, column=0, sticky='w', padx=5)
        self.wallet_entry = ttk.Entry(wallet_frame, width=20)
        self.wallet_entry.grid(row=0, column=1, sticky='ew', padx=5)
        self.wallet_entry.bind("<KeyRelease>", self.on_entry_change)
        self.wallet_var = tk.StringVar(value="")
        self.wallet_dropdown = ttk.OptionMenu(wallet_frame, self.wallet_var, "", *self.wallets.keys(), command=self.on_dropdown_select)
        self.wallet_dropdown.grid(row=0, column=2, sticky='ew', padx=5)
        ttk.Button(wallet_frame, text="Create Wallet", command=self.create_wallet).grid(row=0, column=3, sticky='e', padx=5)
        wallet_frame.grid_columnconfigure(1, weight=1)

    def create_mining_section(self):
        mining_frame = ttk.LabelFrame(self.main_frame, text="Mining Controls", padding=10)
        mining_frame.grid(row=2, column=0, sticky='ew', pady=5)
        ttk.Button(mining_frame, text="Mine", command=self.start_mining).grid(row=0, column=0, sticky='w', padx=5)
        ttk.Button(mining_frame, text="Stop Mining", command=self.stop_mining).grid(row=0, column=1, sticky='e', padx=5)
        mining_frame.grid_columnconfigure(0, weight=1)
        mining_frame.grid_columnconfigure(1, weight=1)

    def create_transaction_section(self):
        send_frame = ttk.LabelFrame(self.main_frame, text="Send Transaction", padding=10)
        send_frame.grid(row=3, column=0, sticky='ew', pady=5)
        ttk.Label(send_frame, text="To Address:").grid(row=0, column=0, sticky='w', padx=5)
        self.to_entry = ttk.Entry(send_frame, width=40)
        self.to_entry.grid(row=0, column=1, sticky='ew', padx=5)
        ttk.Label(send_frame, text="Amount:").grid(row=1, column=0, sticky='w', padx=5)
        self.amount_entry = ttk.Entry(send_frame)
        self.amount_entry.grid(row=1, column=1, sticky='ew', padx=5)
        ttk.Button(send_frame, text="Send", command=self.send_transaction).grid(row=1, column=2, sticky='e', padx=5)
        send_frame.grid_columnconfigure(1, weight=1)

    def create_peer_section(self):
        peer_frame = ttk.LabelFrame(self.main_frame, text="Peer Management", padding=10)
        peer_frame.grid(row=4, column=0, sticky='ew', pady=5)
        ttk.Label(peer_frame, text="Host:").grid(row=0, column=0, sticky='w', padx=5)
        self.peer_host_entry = ttk.Entry(peer_frame)
        self.peer_host_entry.grid(row=0, column=1, sticky='ew', padx=5)
        self.peer_host_entry.insert(0, "127.0.0.1")
        ttk.Label(peer_frame, text="Port:").grid(row=1, column=0, sticky='w', padx=5)
        self.peer_port_entry = ttk.Entry(peer_frame)
        self.peer_port_entry.grid(row=1, column=1, sticky='ew', padx=5)
        ttk.Button(peer_frame, text="Add Peer", command=self.add_peer).grid(row=1, column=2, sticky='e', padx=5)
        peer_frame.grid_columnconfigure(1, weight=1)

    def create_status_panel(self):
        status_frame = ttk.LabelFrame(self.main_frame, text="Status", padding=10)
        status_frame.grid(row=5, column=0, sticky='nsew', pady=5)
        ttk.Label(status_frame, text="Connected Peers:").grid(row=0, column=0, sticky='w', padx=5)
        peers_container = ttk.Frame(status_frame)
        peers_container.grid(row=1, column=0, columnspan=2, sticky='ew', pady=5)
        self.peer_listbox = tk.Listbox(peers_container, height=3)
        self.peer_listbox.pack(side='left', fill='x', expand=True)
        scrollbar = ttk.Scrollbar(peers_container, orient='vertical', command=self.peer_listbox.yview)
        scrollbar.pack(side='right', fill='y')
        self.peer_listbox.config(yscrollcommand=scrollbar.set)
        self.balance_label = ttk.Label(status_frame, text="Balance: 0.0")
        self.balance_label.grid(row=2, column=0, sticky='w', padx=5, pady=5)
        self.chain_height_label = ttk.Label(status_frame, text="Chain Height: 0")
        self.chain_height_label.grid(row=2, column=1, sticky='e', padx=5, pady=5)
        self.network_stats_label = ttk.Label(status_frame, text="Peers: 0")
        self.network_stats_label.grid(row=3, column=0, sticky='w', padx=5, pady=5)
        ttk.Label(status_frame, text="Logs:").grid(row=4, column=0, sticky='w', padx=5, pady=5)
        self.output = scrolledtext.ScrolledText(status_frame, width=70, height=10)
        self.output.grid(row=5, column=0, columnspan=2, sticky='nsew', padx=5, pady=5)
        ttk.Label(status_frame, text="Mempool:").grid(row=6, column=0, sticky='w', padx=5, pady=5)
        self.mempool_text = scrolledtext.ScrolledText(status_frame, width=70, height=3)
        self.mempool_text.grid(row=7, column=0, columnspan=2, sticky='nsew', padx=5, pady=5)
        status_frame.grid_columnconfigure(0, weight=1)
        status_frame.grid_columnconfigure(1, weight=1)
        self.main_frame.grid_rowconfigure(5, weight=1)
        self.update_peer_list()

    def create_transaction_history(self):
        history_frame = ttk.LabelFrame(self.main_frame, text="Transaction History", padding=10)
        history_frame.grid(row=6, column=0, sticky='nsew', pady=5)
        self.history_text = scrolledtext.ScrolledText(history_frame, width=70, height=5)
        self.history_text.grid(row=0, column=0, sticky='nsew')
        history_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(6, weight=1)

    def create_footer(self):
        bottom_frame = ttk.Frame(self.root)
        bottom_frame.pack(side='bottom', fill='x', pady=(0, 10))
        ttk.Button(bottom_frame, text="Exit", command=self.exit).pack(side='right', padx=10)

    def load_wallets(self):
        try:
            with open(self.wallet_path, 'rb') as f:
                encrypted_data = f.read()
            password = tkinter.simpledialog.askstring("Password", "Enter wallet password:", show='*', parent=self.root)
            if not password:
                raise ValueError("Password required")
            salt = encrypted_data[:16]
            encrypted_wallet_data = encrypted_data[16:]
            self.wallets = config_manager.decrypt_wallet_data(encrypted_wallet_data, salt, password)
        except FileNotFoundError:
            self.wallets = {}
        except Exception as e:
            logger.error(f"Error loading wallets: {e}")
            self.wallets = {}

    def save_wallets(self):
        password = tkinter.simpledialog.askstring("Password", "Enter wallet password:", show='*', parent=self.root)
        if not password:
            return
        encrypted_data, salt = config_manager.encrypt_wallet_data(self.wallets, password)
        with open(self.wallet_path, 'wb') as f:
            f.write(salt)
            f.write(encrypted_data)
        self.update_wallet_dropdown()

    def update_wallet_dropdown(self):
        menu = self.wallet_dropdown["menu"]
        menu.delete(0, "end")
        options = list(self.wallets.keys())
        if not options:
            menu.add_command(label="No wallets", command=lambda: self.wallet_var.set(""))
        else:
            for name in options:
                menu.add_command(label=name, command=lambda n=name: self.wallet_var.set(n))
            if self.wallet_entry.get().strip() in options:
                self.wallet_var.set(self.wallet_entry.get().strip())
            elif options:
                self.wallet_var.set(options[0])

    def on_entry_change(self, event):
        name = self.wallet_entry.get().strip()
        if name in self.wallets:
            self.wallet_var.set(name)
        else:
            self.wallet_var.set("")
        self.update_balance()

    def on_dropdown_select(self, *args):
        name = self.wallet_var.get()
        if name and name != "No wallets":
            self.wallet_entry.delete(0, tk.END)
            self.wallet_entry.insert(0, name)
        self.update_balance()

    def update_balance(self):
        name = self.wallet_entry.get().strip()
        if name and name in self.wallets:
            balance = self.blockchain.get_balance(self.wallets[name]["address"])
            self.balance_label.config(text=f"Balance: {balance:.8f}")

    def create_wallet(self):
        name = tkinter.simpledialog.askstring("Input", "Enter wallet name (alphanumeric, 3-20 chars):", parent=self.root)
        if not name or not re.match(r'^[a-zA-Z0-9]{3,20}$', name) or any(n.lower() == name.lower() for n in self.wallets):
            messagebox.showerror("Error", "Wallet name must be unique, 3-20 alphanumeric characters")
            return
        wallet = generate_wallet()
        self.wallets[name] = wallet
        self.save_wallets()
        self.output.insert(tk.END, f"Created wallet '{name}': Address: {wallet['address']}\n")
        self.wallet_entry.delete(0, tk.END)
        self.wallet_entry.insert(0, name)
        self.update_balance()

    def add_peer(self):
        host = self.peer_host_entry.get().strip()
        port_str = self.peer_port_entry.get().strip()
        if not host or not port_str or not port_str.isdigit():
            messagebox.showerror("Error", "Host and port must be valid")
            return
        port = int(port_str)
        if not (1 <= port <= 65535):
            messagebox.showerror("Error", "Port must be between 1 and 65535")
            return
        peer_id = f"node{port}"
        auth_key = config_manager.get_secret("auth_key")
        self.network.add_peer(peer_id, host, port, auth_key, self.network.public_key_str)
        self.update_peer_list()

    def update_peer_list(self):
        self.peer_listbox.delete(0, tk.END)
        for peer_id, (host, port, _) in self.network.peers.items():
            self.peer_listbox.insert(tk.END, f"{peer_id}: {host}:{port}")
        self.network_stats_label.config(text=f"Peers: {len(self.network.peers)}")

    def start_mining(self):
        name = self.wallet_entry.get().strip()
        if not name or name not in self.wallets:
            messagebox.showerror("Error", "Select a valid wallet")
            return
        self.miner.wallet_address = self.wallets[name]["address"]
        self.miner.start_mining()
        self.output.insert(tk.END, f"Mining started with wallet '{name}'\n")

    def stop_mining(self):
        self.miner.stop_mining()
        self.output.insert(tk.END, "Mining stopped\n")

    def send_transaction(self):
        from_name = self.wallet_entry.get().strip()
        to_address = self.to_entry.get().strip()
        amount = self.amount_entry.get().strip()
        if not from_name or not to_address or not amount:
            messagebox.showerror("Error", "Provide all fields")
            return
        if from_name not in self.wallets:
            messagebox.showerror("Error", f"Wallet '{from_name}' does not exist")
            return
        try:
            amount = float(amount)
            if amount <= 0:
                raise ValueError("Amount must be positive")
            wallet = self.wallets[from_name]
            tx = self.blockchain.create_transaction(wallet["private_key"], wallet["address"], to_address, amount)
            if tx and self.blockchain.add_transaction_to_mempool(tx):
                asyncio.run_coroutine_threadsafe(self.network.broadcast_transaction(tx), self.network.loop)
                self.output.insert(tk.END, f"Transaction sent: {tx.tx_id[:8]}\n")
            else:
                balance = self.blockchain.get_balance(wallet["address"])
                messagebox.showerror("Error", f"Insufficient funds. Balance: {balance:.8f}, Required: {amount + 0.001:.8f}")
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid amount: {e}")

    def on_new_block(self, block: Block):
        self.update_queue.put(("block", block))

    def on_new_transaction(self, tx: Transaction):
        self.update_queue.put(("transaction", tx))

    def update_ui(self):
        while not self.update_queue.empty():
            event_type, data = self.update_queue.get()
            if event_type == "block":
                self.output.insert(tk.END, f"New block mined: {data.index}\n")
                self.chain_height_label.config(text=f"Chain Height: {len(self.blockchain.chain) - 1}")
                self.update_balance()
            elif event_type == "transaction":
                self.output.insert(tk.END, f"New transaction in mempool: {data.tx_id[:8]}\n")
        self.mempool_text.delete(1.0, tk.END)
        for tx in self.blockchain.mempool.transactions.values():
            status = "Pending"
            for block in self.blockchain.chain[-6:]:
                if any(t.tx_id == tx.tx_id for t in block.transactions):
                    status = "Confirmed"
                    break
            self.mempool_text.insert(tk.END, f"{tx.tx_id[:8]}: {status} - {tx.outputs[0].amount:.8f} to {tx.outputs[0].recipient[:8]}\n")
        name = self.wallet_entry.get().strip()
        if name in self.wallets:
            address = self.wallets[name]["address"]
            self.history_text.delete(1.0, tk.END)
            for block in self.blockchain.chain:
                for tx in block.transactions:
                    if (tx.tx_type != TransactionType.COINBASE and any(i.public_key and SecurityUtils.public_key_to_address(i.public_key) == address for i in tx.inputs)) or any(o.recipient == address for o in tx.outputs):
                        direction = "Sent" if any(i.public_key and SecurityUtils.public_key_to_address(i.public_key) == address for i in tx.inputs) else "Received"
                        self.history_text.insert(tk.END, f"{tx.tx_id[:8]}: {direction} {tx.outputs[0].amount:.8f} at {time.ctime(block.header.timestamp)}\n")
        self.root.after(1000, self.update_ui)

    def exit(self):
        self.miner.stop_mining()
        self.network.shutdown()
        self.root.quit()
        logger.info("GUI shut down")

    def run(self):
        self.update_wallet_dropdown()
        self.root.mainloop()

def is_port_available(port, host='localhost'):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex((host, port)) != 0

def find_available_port(start_port=1024, end_port=65535, host='localhost'):
    port = random.randint(start_port, end_port)
    while not is_port_available(port, host):
        port = random.randint(start_port, end_port)
    return port

import argparse
def main():
    parser = argparse.ArgumentParser(description="OriginalCoin Node")
    parser.add_argument("--port", type=int, help="Network port")
    parser.add_argument("--host", default="127.0.0.1", help="Network host")
    parser.add_argument("--config", help="Path to config file")
    args = parser.parse_args()

    port = args.port or int(os.environ.get("ORIGINALCOIN_NETWORK_PORT", find_available_port()))
    host = args.host
    if args.config:
        config_manager.config_file = Path(args.config)
        config_manager._load_or_create_config()

    db_config = {
        "dbname": "originalcoin",
        "user": "postgres",
        "password": os.environ.get("PG_PASSWORD", "yourpassword"),
        "host": "postgres" if os.environ.get("DOCKERIZED", "false") == "true" else "localhost",
        "port": "5432"
    }
    blockchain = Blockchain(db_config)
    network = BlockchainNetwork(blockchain, f"node{port}", host, port)
    network_thread = threading.Thread(target=network.run)
    network_thread.daemon = True
    network_thread.start()

    network.start_periodic_sync()
    network.start_key_rotation()
    asyncio.run_coroutine_threadsafe(network.discover_peers(), network.loop)

    gui = BlockchainGUI(blockchain, network)
    gui.run()

if __name__ == "__main__":
    def run_prometheus():
        try:
            logger.info("Starting Prometheus metrics server on port 8000")
            start_http_server(8000)
            logger.info("Prometheus server running")
        except Exception as e:
            logger.error(f"Failed to start Prometheus server: {e}")

    prometheus_thread = threading.Thread(target=run_prometheus, daemon=True)
    prometheus_thread.start()
    time.sleep(1)
    main()