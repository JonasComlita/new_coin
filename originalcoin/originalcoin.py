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
import socket
import argparse
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog
from typing import List, Dict, Optional, Any, Callable
from dataclasses import dataclass
from enum import Enum
import random
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from acme import client, challenges
from josepy import JWKRSA
from pathlib import Path
import hmac
import shutil
import re

# Version
PROTOCOL_VERSION = "1.0.0"

# Configure logging with rotation
handler = logging.handlers.RotatingFileHandler("originalcoin.log", maxBytes=5*1024*1024, backupCount=3)
logging.basicConfig(level=logging.INFO, handlers=[handler], format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Blockchain")

class SecureConfigManager:
    def __init__(self, app_name: str = "OriginalCoin"):
        self.app_name = app_name
        self.config_dir = Path.home() / ".originalcoin"
        self.config_dir.mkdir(exist_ok=True, parents=True)
        self.backup_dir = self.config_dir / "backups"
        self.backup_dir.mkdir(exist_ok=True)
        self.secrets_file = self.config_dir / "secrets.enc"
        self.config_file = self.config_dir / "config.json"
        self.cert_file = self.config_dir / "cert.pem"
        self.key_file = self.config_dir / "key.pem"
        self.account_key_file = self.config_dir / "account_key.pem"
        
        self.default_config = {
            "network": {
                "port": 8443,
                "max_peers": 100,
                "bootstrap_nodes": os.environ.get("BOOTSTRAP_NODES", "node1.example.com:8443,node2.example.com:8443").split(","),
                "ssl_enabled": True,
                "max_retries": 3,
                "acme_directory": "https://acme-staging-v02.api.letsencrypt.org/directory"
            },
            "blockchain": {
                "difficulty": 2,
                "target_block_time": 30,
                "halving_interval": 210000,
                "initial_reward": 50,
                "max_block_size": 1000000,
                "sync_interval": 150,
                "min_fee": 0.0001,
                "reorg_depth": 6
            },
            "mempool": {"max_size": 5000, "min_fee_rate": 0.00001},
            "storage": {
                "blockchain_path": str(self.config_dir / "chain.json"),
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
        if not master_key_env:
            logger.warning("ORIGINALCOIN_MASTER_KEY not set. Generating a new one.")
            self.master_key = Fernet.generate_key()
            logger.info(f"New master key generated. Store this securely: {base64.urlsafe_b64encode(self.master_key).decode()}")
        else:
            self.master_key = base64.urlsafe_b64decode(master_key_env)

    def backup_chain(self, chain_file: str):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = self.backup_dir / f"chain_backup_{timestamp}.json"
        shutil.copy(chain_file, backup_file)
        with open(backup_file, "rb") as f:
            checksum = hashlib.sha256(f.read()).hexdigest()
        with open(backup_file.with_suffix(".json.sha256"), "w") as f:
            f.write(checksum)
        backups = sorted(self.backup_dir.glob("chain_backup_*.json"))
        while len(backups) > 5:
            os.remove(backups.pop(0))
            os.remove(backups[0].with_suffix(".json.sha256"))
        logger.info(f"Created chain backup: {backup_file} with checksum {checksum}")

    def _is_cert_near_expiry(self) -> bool:
        with open(self.cert_file, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        days_left = (cert.not_valid_after_utc - datetime.utcnow()).days
        if days_left < 7:
            logger.warning(f"Certificate expires in {days_left} days!")
        return days_left < 0

    def _ensure_certificates(self):
        if os.environ.get("ORIGINALCOIN_USE_ACME", "false").lower() == "true":
            self._renew_acme_certificate()
        elif not self.cert_file.exists() or not self.key_file.exists() or self._is_cert_near_expiry():
            self._generate_self_signed_certificate()

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
        endpoint = request.path
        if not hasattr(app, '_rate_limit'):
            app._rate_limit = {}
        key = f"{client_ip}:{endpoint}"
        if key not in app._rate_limit:
            app._rate_limit[key] = {'count': 0, 'reset': time.time() + 60}
        
        now = time.time()
        if now > app._rate_limit[key]['reset']:
            app._rate_limit[key] = {'count': 0, 'reset': now + 60}
        
        limit = 50 if endpoint in ["/receive_block", "/receive_transaction"] else 100
        if app._rate_limit[key]['count'] >= limit:
            raise aiohttp.web.HTTPTooManyRequests(text="Rate limit exceeded")
        
        app._rate_limit[key]['count'] += 1
        return await handler(request)
    return middleware_handler

class TransactionType(Enum):
    COINBASE = "coinbase"
    REGULAR = "regular"

@dataclass
class TransactionOutput:
    recipient: str
    amount: float

    def to_dict(self) -> Dict[str, Any]:
        return {"recipient": self.recipient, "amount": self.amount}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TransactionOutput':
        return cls(recipient=data["recipient"], amount=data["amount"])
    
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
    def __init__(self, tx_type: TransactionType, inputs: List[TransactionInput], outputs: List[TransactionOutput], fee: float = 0.0, required_signatures: int = 1, nonce: int = None):
        self.tx_type = tx_type
        self.inputs = inputs
        self.outputs = outputs
        self.fee = fee
        self.required_signatures = required_signatures
        self.nonce = nonce if nonce is not None else int(time.time() * 1000)  # Millisecond timestamp nonce
        self.signatures: Dict[str, bytes] = {}
        self.tx_id = self.calculate_tx_id()

    def calculate_tx_id(self) -> str:
        data = {
            "tx_type": self.tx_type.value,
            "inputs": [i.to_dict() for i in self.inputs],
            "outputs": [o.to_dict() for o in self.outputs],
            "fee": self.fee,
            "required_signatures": self.required_signatures,
            "nonce": self.nonce
        }
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

    def sign_transaction(self, private_key: ecdsa.SigningKey, public_key: ecdsa.VerifyingKey) -> None:
        data = json.dumps(self.to_dict(exclude_signatures=True), sort_keys=True).encode()
        pub_key_hex = public_key.to_string().hex()
        self.signatures[pub_key_hex] = private_key.sign(data)

    def to_dict(self, exclude_signatures: bool = False) -> Dict[str, Any]:
        data = {
            "tx_type": self.tx_type.value,
            "inputs": [i.to_dict() for i in self.inputs],
            "outputs": [o.to_dict() for o in self.outputs],
            "fee": self.fee,
            "tx_id": self.tx_id,
            "required_signatures": self.required_signatures,
            "nonce": self.nonce
        }
        if not exclude_signatures:
            data["signatures"] = {k: v.hex() for k, v in self.signatures.items()}
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Transaction':
        tx = cls(
            tx_type=TransactionType(data["tx_type"]),
            inputs=[TransactionInput.from_dict(i) for i in data["inputs"]],
            outputs=[TransactionOutput.from_dict(o) for o in data["outputs"]],
            fee=data["fee"],
            required_signatures=data.get("required_signatures", 1),
            nonce=data.get("nonce")
        )
        if "signatures" in data:
            tx.signatures = {k: bytes.fromhex(v) for k, v in data["signatures"].items()}
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
        self.version = PROTOCOL_VERSION
        self.hash = self.calculate_hash()

    def calculate_hash(self) -> str:
        data = f"{self.index}{self.previous_hash}{self.timestamp}{self.difficulty}{self.merkle_root}{self.nonce}{self.version}"
        return hashlib.sha256(data.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "difficulty": self.difficulty,
            "merkle_root": self.merkle_root,
            "nonce": self.nonce,
            "version": self.version,
            "hash": self.hash
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BlockHeader':
        return cls(
            index=data["index"],
            previous_hash=data["previous_hash"],
            timestamp=data["timestamp"],
            difficulty=data["difficulty"],
            merkle_root=data["merkle_root"],
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

    def update_with_block(self, block: Block) -> None:
        for tx in block.transactions:
            if tx.tx_type != TransactionType.COINBASE:
                for tx_input in tx.inputs:
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
        self.max_size = config_manager.get_config("mempool", "max_size")
        self.min_fee_rate = config_manager.get_config("mempool", "min_fee_rate")

    def add_transaction(self, tx: Transaction) -> bool:
        if tx.fee < config_manager.get_config("blockchain", "min_fee"):
            return False  # DoS protection
        if tx.tx_id not in self.transactions:
            if len(self.transactions) >= self.max_size:
                min_fee_tx = min(self.transactions.items(), key=lambda x: x[1].fee)
                if tx.fee > min_fee_tx[1].fee:
                    del self.transactions[min_fee_tx[0]]
                else:
                    return False
            self.transactions[tx.tx_id] = tx
            return True
        return False

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

class Blockchain:
    def __init__(self):
        self.chain: List[Block] = []
        self.data_dir = os.path.expanduser("~/.originalcoin")
        os.makedirs(self.data_dir, exist_ok=True)
        self.chain_file = config_manager.get_config("storage", "blockchain_path")
        self.difficulty = config_manager.get_config("blockchain", "difficulty")
        self.current_reward = config_manager.get_config("blockchain", "initial_reward")
        self.mempool = Mempool()
        self.utxos = UTXOSet()
        self.lock = threading.Lock()
        self.listeners = {"new_block": [], "new_transaction": [], "hashrate_warning": []}
        self.orphans: Dict[str, Block] = {}
        self.used_nonces: set = set()
        self.load_chain()
        self._setup_logging()

    def adjust_difficulty(self):
        if len(self.chain) % 10 == 0 and len(self.chain) > 10:
            time_diff = self.chain[-1].header.timestamp - self.chain[-10].header.timestamp
            expected_time = config_manager.get_config("blockchain", "target_block_time") * 10
            self.difficulty = max(1, min(8, self.difficulty * expected_time / time_diff))
            logger.info(f"Difficulty adjusted to {self.difficulty}")

    def check_hashrate_distribution(self):
        recent_blocks = self.chain[-100:]
        miners = {}
        for block in recent_blocks:
            miner = block.transactions[0].outputs[0].recipient
            miners[miner] = miners.get(miner, 0) + 1
        for miner, count in miners.items():
            if count > 50:
                logger.warning(f"Potential 51% attack by {miner}: {count}% of recent blocks")
                self.trigger_event("hashrate_warning", {"miner": miner, "percentage": count})

    def _setup_logging(self):
        handler = logging.handlers.RotatingFileHandler("originalcoin.log", maxBytes=5*1024*1024, backupCount=3)
        logging.basicConfig(level=logging.INFO, handlers=[handler], format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        logger.addHandler(handler)

    def load_chain(self) -> None:
        if os.path.exists(self.chain_file):
            with open(self.chain_file, "r") as f:
                chain_data = json.load(f)
                self.chain = [Block.from_dict(block) for block in chain_data]
            for block in self.chain:
                self.utxos.update_with_block(block)
            logger.info(f"Loaded {len(self.chain)} blocks from {self.chain_file}")
        else:
            genesis_block = Block(0, [], "0" * 64, self.difficulty)
            self.chain.append(genesis_block)
            self.utxos.update_with_block(genesis_block)
            self.save_chain()
            logger.info("Created genesis block")

    def save_chain(self) -> None:
        with self.lock:
            try:
                with open(self.chain_file, "w") as f:
                    json.dump([block.to_dict() for block in self.chain], f)
                config_manager.backup_chain(self.chain_file)
            except Exception as e:
                logger.error(f"Failed to save chain: {e}")
                raise

    def subscribe(self, event: str, callback: Callable) -> None:
        if event in self.listeners:
            self.listeners[event].append(callback)

    def trigger_event(self, event: str, data: Any) -> None:
        for callback in self.listeners[event]:
            callback(data)

    async def validate_block(self, block: Block) -> bool:
        if block.header.version != PROTOCOL_VERSION:
            return False
        if block.index > 0:
            if block.header.previous_hash not in [b.header.hash for b in self.chain] and block.header.previous_hash not in self.orphans:
                self.orphans[block.header.hash] = block
                logger.info(f"Block {block.index} is an orphan; storing")
                return False
            prev_block = next((b for b in self.chain if b.header.hash == block.header.previous_hash), None)
            if not prev_block:
                return False
        target = "0" * self.difficulty
        if not block.header.hash.startswith(target):
            return False
        temp_utxos = UTXOSet()
        for b in self.chain[:block.index]:
            temp_utxos.update_with_block(b)
        temp_utxos.update_with_block(block)
        tasks = [self.validate_transaction(tx, temp_utxos) for tx in block.transactions]
        results = await asyncio.gather(*tasks)
        return all(results)

    async def validate_transaction(self, tx: Transaction, utxos: UTXOSet = None) -> bool:
        if not utxos:
            utxos = self.utxos
        if tx.nonce in self.used_nonces and tx.tx_type != TransactionType.COINBASE:
            return False  # Prevent replay
        if tx.tx_type == TransactionType.COINBASE:
            if len(tx.inputs) != 1 or tx.inputs[0].output_index != -1:
                return False
            block_height = self.chain[-1].index + 1 if self.chain else 0
            expected_reward = self.current_reward * (0.5 ** (block_height // config_manager.get_config("blockchain", "halving_interval")))
            return len(tx.outputs) == 1 and tx.outputs[0].amount <= expected_reward
        if len(tx.signatures) < tx.required_signatures:
            return False
        data = json.dumps(tx.to_dict(exclude_signatures=True), sort_keys=True).encode()
        for pub_key, sig in tx.signatures.items():
            vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(pub_key), curve=ecdsa.SECP256k1)
            if not vk.verify(sig, data):
                return False
        input_sum = 0
        spent_utxos = set()
        for tx_input in tx.inputs:
            utxo_key = (tx_input.tx_id, tx_input.output_index)
            if utxo_key in spent_utxos:
                return False
            utxo = utxos.get_utxo(tx_input.tx_id, tx_input.output_index)
            if not utxo:
                return False
            spent_utxos.add(utxo_key)
            input_sum += utxo.amount
        output_sum = sum(output.amount for output in tx.outputs)
        if output_sum <= input_sum and tx.fee >= config_manager.get_config("blockchain", "min_fee"):
            self.used_nonces.add(tx.nonce)
            return True
        return False

    def check_hashrate_distribution(self):
        recent_blocks = self.chain[-100:]  # Look at the last 100 blocks
        miners = {}
        for block in recent_blocks:
            miner = block.transactions[0].outputs[0].recipient  # Coinbase recipient
            miners[miner] = miners.get(miner, 0) + 1
        for miner, count in miners.items():
            if count > 50:  # >50% of last 100 blocks
                logger.warning(f"Potential 51% attack by {miner}: {count}% of recent blocks")
                # Optional: Trigger an alert or halt mining if critical
                # self.trigger_event("hashrate_warning", {"miner": miner, "percentage": count})

    async def add_block(self, block: Block) -> bool:
        with self.lock:
            if any(b.header.hash == block.header.hash for b in self.chain):
                return False
            if block.index == len(self.chain) and await self.validate_block(block):
                self.chain.append(block)
                self.utxos.update_with_block(block)
                self.save_chain()
                tx_ids = [tx.tx_id for tx in block.transactions]
                self.mempool.remove_transactions(tx_ids)
                self.trigger_event("new_block", block)
                self.check_hashrate_distribution()
                logger.info(f"Added block {block.index}")
                await self.process_orphans(block.header.hash)
                return True
            elif block.index > len(self.chain) or block.header.previous_hash != self.chain[-1].header.hash:
                self.orphans[block.header.hash] = block
                await self.handle_fork(block)
            return False
        
    async def process_orphans(self, parent_hash: str):
        orphans_to_process = [block for block_hash, block in self.orphans.items() if block.header.previous_hash == parent_hash]
        for orphan in orphans_to_process:
            if await self.validate_block(orphan):
                self.chain.append(orphan)
                self.utxos.update_with_block(orphan)
                self.save_chain()
                self.mempool.remove_transactions([tx.tx_id for tx in orphan.transactions])
                self.trigger_event("new_block", orphan)
                logger.info(f"Added orphan block {orphan.index}")
                del self.orphans[orphan.header.hash]
                await self.process_orphans(orphan.header.hash)

    async def handle_fork(self, new_block: Block):
        longest_chain = await self.network.fetch_longest_chain(new_block)
        if longest_chain and len(longest_chain) > len(self.chain):
            if await self.validate_chain(longest_chain):
                logger.info(f"Reorganizing chain from {len(self.chain)} to {len(longest_chain)} blocks")
                self.chain = longest_chain
                self.utxos = UTXOSet()
                for block in self.chain:
                    self.utxos.update_with_block(block)
                self.save_chain()
                self.mempool.clear()
                self.trigger_event("new_block", self.chain[-1])
                await self.process_orphans(self.chain[-1].header.hash)

    async def validate_chain(self, chain: List[Block]) -> bool:
        temp_utxos = UTXOSet()
        for i, block in enumerate(chain):
            if i > 0 and block.header.previous_hash != chain[i-1].header.hash:
                return False
            if not await self.validate_block(block):
                return False
            temp_utxos.update_with_block(block)
        return True

    def create_transaction(self, sender_keys: List[tuple[str, str]], sender_address: str, recipient_address: str, amount: float, fee: float = 0.001, required_signatures: int = 1) -> Optional[Transaction]:
        if not self._is_valid_address(sender_address) or not self._is_valid_address(recipient_address):
            return None
        if amount <= 0 or fee < config_manager.get_config("blockchain", "min_fee"):
            return None
        total_available = self.utxos.get_balance(sender_address)
        if total_available < amount + fee:
            return None
        selected_utxos = []
        selected_amount = 0
        for tx_id, output_index, utxo in self.utxos.get_utxos_for_address(sender_address):
            selected_utxos.append((tx_id, output_index, utxo.amount))
            selected_amount += utxo.amount
            if selected_amount >= amount + fee:
                break
        inputs = [TransactionInput(tx_id, output_index) for tx_id, output_index, _ in selected_utxos]
        outputs = [TransactionOutput(recipient_address, amount)]
        if selected_amount > amount + fee:
            outputs.append(TransactionOutput(sender_address, selected_amount - amount - fee))
        tx = Transaction(TransactionType.REGULAR, inputs, outputs, fee, required_signatures)
        for priv_key, pub_key in sender_keys[:required_signatures]:
            sk = ecdsa.SigningKey.from_string(bytes.fromhex(priv_key), curve=ecdsa.SECP256k1)
            vk = sk.get_verifying_key()
            tx.sign_transaction(sk, vk)
        return tx

    def _is_valid_address(self, address: str) -> bool:
        return bool(re.match(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$', address))

    def add_transaction_to_mempool(self, tx: Transaction) -> bool:
        if asyncio.run(self.validate_transaction(tx)) and self.mempool.add_transaction(tx):
            self.trigger_event("new_transaction", tx)
            return True
        return False

    def get_balance(self, address: str) -> float:
        return self.utxos.get_balance(address)

class BlockchainNetwork:
    def __init__(self, blockchain: Blockchain, host: str, port: int):
        self.blockchain = blockchain
        self.host = host
        self.port = port
        self.peers: Dict[str, tuple[str, int, str]] = {}
        self.blacklist: set = set()  # Track misbehaving peers
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.app = aiohttp.web.Application(middlewares=[rate_limit_middleware])
        self.app.add_routes([
            aiohttp.web.post('/receive_block', self.receive_block),
            aiohttp.web.post('/receive_transaction', self.receive_transaction),
            aiohttp.web.get('/get_chain', self.get_chain),
            aiohttp.web.post('/update_auth_key', self.receive_auth_key),
            aiohttp.web.get('/get_peers', self.get_peers),
            aiohttp.web.get('/version', self.get_version)
        ])
        self.blockchain.network = self
        self.private_key, self.public_key = self._generate_node_keypair()
        self.public_key_str = self.public_key.to_string().hex()
        self.running = True
        self.peer_file = config_manager.config_dir / "peers.json"
        self.load_peers()
        self.ssl_context = self._create_ssl_context()

    async def get_version(self, request: aiohttp.web.Request) -> aiohttp.web.Response:
        return aiohttp.web.json_response({"version": PROTOCOL_VERSION})

    def _create_ssl_context(self):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_config = config_manager.get_tls_config()
        ssl_context.load_cert_chain(certfile=tls_config["cert"], keyfile=tls_config["key"])
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        ssl_context.load_verify_locations(cafile=str(config_manager.cert_file))
        return ssl_context

    def _generate_node_keypair(self) -> tuple[ecdsa.SigningKey, ecdsa.VerifyingKey]:
        private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        return private_key, private_key.get_verifying_key()

    def load_peers(self):
        try:
            with open(self.peer_file, 'r') as f:
                peers = json.load(f)
                for peer_id, (host, port, pub_key) in peers.items():
                    self.add_peer(peer_id, host, port, config_manager.get_secret("auth_key"), pub_key)
        except FileNotFoundError:
            pass

    def add_peer(self, peer_id: str, host: str, port: int, auth_key: str = None, peer_public_key: str = None):
        expected_key = config_manager.get_secret("auth_key")
        if not expected_key:
            expected_key = config_manager.generate_auth_key()
        if auth_key != expected_key or not peer_public_key:
            logger.warning(f"Peer {peer_id} failed authentication or missing public key")
            return
        self.peers[peer_id] = (host, port, peer_public_key)
        logger.info(f"Authenticated peer {peer_id} added: {host}:{port}")
        self.save_peers()

    def save_peers(self):
        with open(self.peer_file, 'w') as f:
            json.dump({peer_id: (host, port, pub_key) for peer_id, (host, port, pub_key) in self.peers.items()}, f)

    def run(self) -> None:
        runner = aiohttp.web.AppRunner(self.app)
        self.loop.run_until_complete(runner.setup())
        
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_config = config_manager.get_tls_config()
        ssl_context.load_cert_chain(certfile=tls_config["cert"], keyfile=tls_config["key"])
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        ssl_context.load_verify_locations(cafile=str(config_manager.cert_file))
        
        site = aiohttp.web.TCPSite(runner, self.host, self.port, ssl_context=ssl_context)
        self.loop.run_until_complete(site.start())
        logger.info(f"Network server running on https://{self.host}:{self.port}")
        try:
            self.loop.run_forever()
        except asyncio.CancelledError:
            logger.info("Network loop cancelled")
        finally:
            self.loop.run_until_complete(self.app.shutdown())
            self.loop.run_until_complete(self.app.cleanup())
            self.loop.close()
            logger.info("Network server shut down")

    def shutdown(self):
        self.running = False
        # Cancel all tasks in the loop from the network thread
        def stop_loop():
            for task in asyncio.all_tasks(self.loop):
                task.cancel()
            self.loop.stop()
        
        # Schedule shutdown in the network's event loop
        asyncio.run_coroutine_threadsafe(asyncio.to_thread(stop_loop), self.loop)

    async def send_with_retry(self, url: str, data: dict, method: str = "post", max_retries: int = config_manager.get_config("network", "max_retries")):
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
            for attempt in range(max_retries):
                try:
                    ssl_context = ssl.create_default_context(cafile=str(config_manager.cert_file))
                    ssl_context.verify_mode = ssl.CERT_REQUIRED
                    if method == "post":
                        async with session.post(url, json=data, ssl=ssl_context) as response:
                            return response.status == 200
                    elif method == "get":
                        async with session.get(url, ssl=ssl_context) as response:
                            return response.status == 200, await response.json()
                except Exception as e:
                    logger.exception(f"Attempt {attempt + 1} failed for {url}: {e}")
                    if attempt == max_retries - 1:
                        return False if method == "post" else (False, None)
                    await asyncio.sleep(0.5 * (2 ** attempt))

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
        peer_ip = request.remote
        if not await self.blockchain.add_block(block):
            self.blacklist.add(peer_ip)
            logger.warning(f"Blacklisted peer {peer_ip} for sending invalid block")
            return aiohttp.web.Response(status=400)
        return aiohttp.web.Response(status=200)
    
    async def fetch_longest_chain(self, trigger_block: Block) -> Optional[List[Block]]:
        max_length = len(self.blockchain.chain)
        longest_chain = None
        for peer_id, (host, port, _) in self.peers.items():
            if f"{host}:{port}" in self.blacklist:
                continue
            url = f"https://{host}:{port}/get_chain"
            success, chain_data = await self.send_with_retry(url, {}, method="get")
            if success:
                peer_chain = [Block.from_dict(b) for b in chain_data]
                if (peer_chain[-1].header.hash == trigger_block.header.hash or
                    any(b.header.hash == trigger_block.header.previous_hash for b in peer_chain)):
                    if len(peer_chain) > max_length and len(peer_chain) <= len(self.blockchain.chain) + config_manager.get_config("blockchain", "reorg_depth"):
                        max_length = len(peer_chain)
                        longest_chain = peer_chain
        return longest_chain

    def broadcast_transaction(self, tx: Transaction) -> None:
        tasks = [self.send_transaction(peer_id, host, port, tx) for peer_id, (host, port, _) in self.peers.items()]
        if tasks:
            asyncio.run_coroutine_threadsafe(asyncio.gather(*tasks, return_exceptions=True), self.loop)

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
                peer_pub_key = ecdsa.VerifyingKey.from_string(bytes.fromhex(peer_public_key), curve=ecdsa.SECP256k1)
                data = {
                    "key": new_key,
                    "signature": self.private_key.sign(new_key.encode()).hex()
                }
                tasks.append(self.send_auth_key(peer_id, host, port, data))
            except Exception as e:
                logger.error(f"Failed to prepare auth key for {peer_id}: {e}")
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
        new_key = data["key"]
        signature = bytes.fromhex(data["signature"])
        
        for peer_id, (_, _, pub_key_str) in self.peers.items():
            try:
                peer_pub_key = ecdsa.VerifyingKey.from_string(bytes.fromhex(pub_key_str), curve=ecdsa.SECP256k1)
                if peer_pub_key.verify(signature, new_key.encode()):
                    config_manager.set_secret("auth_key", new_key)
                    logger.info(f"Received and updated auth key from {peer_id}")
                    break
            except Exception as e:
                logger.debug(f"Failed to verify auth key from {peer_id}: {e}")
                continue
        return aiohttp.web.Response(status=200)

    async def get_chain(self, request: aiohttp.web.Request) -> aiohttp.web.Response:
        return aiohttp.web.json_response([block.to_dict() for block in self.blockchain.chain])

    async def get_peers(self, request: aiohttp.web.Request) -> aiohttp.web.Response:
        return aiohttp.web.json_response({peer_id: (host, port, pub_key) for peer_id, (host, port, pub_key) in self.peers.items()})

    async def discover_peers(self):
        bootstrap_nodes = config_manager.get_config("network", "bootstrap_nodes")
        for node in bootstrap_nodes:
            host, port = node.split(":")
            version_url = f"https://{host}:{port}/version"
            success, version_data = await self.send_with_retry(version_url, {}, method="get")
            if success and version_data["version"] == PROTOCOL_VERSION:
                url = f"https://{host}:{port}/get_peers"
                success, peer_data = await self.send_with_retry(url, {}, method="get")
                if success:
                    for peer_id, (peer_host, peer_port, pub_key) in peer_data.items():
                        self.add_peer(peer_id, peer_host, int(peer_port), config_manager.get_secret("auth_key"), pub_key)

    def start_key_rotation(self, interval=config_manager.get_config("security", "key_rotation_interval")):
        async def rotation_task():
            while self.running:
                new_key = config_manager.rotate_auth_key()
                await self.broadcast_auth_key(new_key)
                logger.info(f"Rotated and broadcasted new auth key: {new_key[:8]}...")
                await asyncio.sleep(interval)
        asyncio.run_coroutine_threadsafe(rotation_task(), self.loop)

class Miner:
    async def mine(self):
        self.running = True
        while self.running:
            self.blockchain.adjust_difficulty()
            latest_block = self.blockchain.chain[-1]
            transactions = list(self.blockchain.mempool.transactions.values())[:1000]
            coinbase_tx = TransactionFactory.create_coinbase_transaction(
                self.wallet_address, self.blockchain.current_reward, latest_block.index + 1
            )
            transactions.insert(0, coinbase_tx)
            block = Block(latest_block.index + 1, transactions, latest_block.header.hash, self.blockchain.difficulty)

            target = "0" * self.blockchain.difficulty
            nonce = random.randint(0, 1000000)
            while self.running:
                block.header.nonce = nonce
                block.header.hash = block.header.calculate_hash()
                if block.header.hash.startswith(target):
                    if await self.blockchain.add_block(block):
                        self.blockchain.network.broadcast_block(block)
                        logger.info(f"Mined block {block.index}")
                    break
                nonce += 1
                if nonce % 5000 == 0:
                    await asyncio.sleep(0.001)
            await asyncio.sleep(0.001)

    def start_mining(self):
        self.running = True
        asyncio.create_task(self.mine())

    def stop_mining(self):
        self.running = False

class BlockchainGUI:
    def __init__(self, blockchain: Blockchain, network: BlockchainNetwork):
        self.blockchain = blockchain
        self.network = network
        self.wallets = {}
        self.wallet_path = config_manager.get_config("storage", "wallet_path")
        self.miner = Miner(blockchain, None)
        self.load_wallets()
        self.root = tk.Tk()
        self.root.title("OriginalCoin GUI")
        self.root.geometry("900x1000")
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        self.update_queue = asyncio.Queue()
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
        self.blockchain.subscribe("hashrate_warning", self.on_hashrate_warning)

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
        attempts = 0
        max_attempts = 3
        while attempts < max_attempts:
            try:
                with open(self.wallet_path, 'rb') as f:
                    encrypted_data = f.read()
                password = simpledialog.askstring("Password", "Enter wallet password:", show='*', parent=self.root)
                if not password:
                    raise ValueError("Password required")
                salt = encrypted_data[:16]
                encrypted_wallet_data = encrypted_data[16:]
                self.wallets = config_manager.decrypt_wallet_data(encrypted_wallet_data, salt, password)
                break
            except Exception as e:
                attempts += 1
                logger.error(f"Wallet load attempt {attempts} failed: {e}")
                if attempts < max_attempts:
                    time.sleep(2 ** attempts)
                    messagebox.showerror("Error", f"Invalid password. {max_attempts - attempts} attempts left.")
                else:
                    messagebox.showerror("Error", "Max attempts reached. Exiting.")
                    self.root.quit()
    
    def on_hashrate_warning(self, data):
        self.output.insert(tk.END, f"WARNING: Miner {data['miner'][:8]} controls {data['percentage']:.1f}% of recent blocks!\n")

    def save_wallets(self):
        password = simpledialog.askstring("Password", "Enter wallet password:", show='*', parent=self.root)
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
        name = simpledialog.askstring("Input", "Enter wallet name:", parent=self.root)
        if not name or name in self.wallets:
            messagebox.showerror("Error", "Wallet name must be unique and non-empty")
            return
        multisig = messagebox.askyesno("Multi-Signature", "Create a multi-signature wallet?")
        keys = []
        required_signatures = 1
        if multisig:
            num_keys = simpledialog.askinteger("Input", "Number of keys (2-5):", minvalue=2, maxvalue=5)
            required_signatures = simpledialog.askinteger("Input", f"Required signatures (1-{num_keys}):", minvalue=1, maxvalue=num_keys)
            for i in range(num_keys):
                priv_key, pub_key = SecurityUtils.generate_keypair()
                keys.append((priv_key, pub_key))
        else:
            priv_key, pub_key = SecurityUtils.generate_keypair()
            keys.append((priv_key, pub_key))
        address = SecurityUtils.public_key_to_address(keys[0][1])  # First key for simplicity
        self.wallets[name] = {"address": address, "keys": keys, "required_signatures": required_signatures}
        self.save_wallets()

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
        amount_str = self.amount_entry.get().strip()
        if not from_name or not to_address or not amount_str:
            messagebox.showerror("Error", "Provide all fields")
            return
        if from_name not in self.wallets:
            messagebox.showerror("Error", f"Wallet '{from_name}' does not exist")
            return
        try:
            amount = float(amount_str)
            if not (0 < amount <= 1000000):
                raise ValueError("Amount must be between 0 and 1,000,000")
            if not self.blockchain._is_valid_address(to_address):
                raise ValueError("Invalid recipient address")
            wallet = self.wallets[from_name]
            tx = self.blockchain.create_transaction(
                wallet["keys"],
                wallet["address"],
                to_address,
                amount,
                fee=0.001,
                required_signatures=wallet["required_signatures"]
            )
            if tx and self.blockchain.add_transaction_to_mempool(tx):
                self.network.broadcast_transaction(tx)
                self.output.insert(tk.END, f"Transaction sent: {tx.tx_id[:8]}\n")
            else:
                balance = self.blockchain.get_balance(wallet["address"])
                messagebox.showerror("Error", f"Insufficient funds or invalid transaction. Balance: {balance:.8f}")
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid input: {e}")

    def on_new_block(self, block: Block):
        asyncio.run_coroutine_threadsafe(self.update_queue.put(("block", block)), self.network.loop)

    def on_new_transaction(self, tx: Transaction):
        asyncio.run_coroutine_threadsafe(self.update_queue.put(("transaction", tx)), self.network.loop)

    def update_ui(self):
        while not self.update_queue.empty():
            event_type, data = self.update_queue.get_nowait()
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
        self.network.shutdown()  # Signal shutdown
        # Give the network thread a moment to stop
        self.root.after(1000, self.root.quit)  # Delay quit to allow cleanup
        logger.info("Initiating GUI shutdown")

    def run(self):
        self.update_wallet_dropdown()
        self.root.mainloop()

def is_port_available(port, host='0.0.0.0'):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex((host, port)) != 0

def find_available_port(start_port=1024, end_port=65535, host='0.0.0.0'):
    port = random.randint(start_port, end_port)
    while not is_port_available(port, host):
        port = random.randint(start_port, end_port)
    return port

def main():
    parser = argparse.ArgumentParser(description=f"OriginalCoin Node v{PROTOCOL_VERSION}")
    parser.add_argument("--port", type=int, default=find_available_port(), help="Network port")
    parser.add_argument("--host", default="0.0.0.0", help="Network host")
    parser.add_argument("--gui", action="store_true", help="Run with GUI")
    args = parser.parse_args()

    blockchain = Blockchain()
    network = BlockchainNetwork(blockchain, args.host, args.port)
    network_thread = threading.Thread(target=network.run, daemon=True)
    network_thread.start()

    time.sleep(1)
    asyncio.run_coroutine_threadsafe(network.discover_peers(), network.loop)
    network.start_key_rotation()

    if args.gui:
        gui = BlockchainGUI(blockchain, network)
        gui.run()
    else:
        logger.info(f"Blockchain node running on {args.host}:{args.port}")
        try:
            network_thread.join()
        except KeyboardInterrupt:
            network.shutdown()
            network_thread.join()

if __name__ == "__main__":
    main()