import tkinter as tk
import tkinter.simpledialog  
from tkinter import ttk, messagebox, scrolledtext
import threading
import asyncio
import os
import re  
from cryptography.fernet import Fernet 
import json  
import time  
from blockchain import Blockchain, Transaction, Miner, Block, PEER_COUNT 
from network import BlockchainNetwork
from utils import derive_key, generate_wallet, TransactionType, SecurityUtils, TransactionInput, TransactionOutput
from cryptography.fernet import Fernet, InvalidToken

class BlockchainGUI:
    """Graphical interface for interacting with the blockchain."""
    def __init__(self, blockchain: Blockchain, network: BlockchainNetwork, wallet_file: str = "wallets.json"):
        self.blockchain = blockchain
        self.network = network
        self.wallets = {}
        self.wallet_file = wallet_file
        self.miner = Miner(blockchain, blockchain.mempool, None)
        self.load_wallets()
        
        # Initialize the Tkinter window
        self.root = tk.Tk()
        self.root.title("OriginalCoin GUI")
        self.root.geometry("800x600")  # Set a reasonable window size

        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        ttk.Label(self.main_frame, text="Wallet:").grid(row=0, column=0, sticky=tk.W)
        self.wallet_var = tk.StringVar()
        self.wallet_dropdown = ttk.Combobox(self.main_frame, textvariable=self.wallet_var, state="readonly")
        self.wallet_dropdown.grid(row=0, column=1, sticky=(tk.W, tk.E))
        self.update_wallet_dropdown()
        ttk.Button(self.main_frame, text="Create Wallet", command=self.create_wallet).grid(row=0, column=2, padx=5)
        ttk.Button(self.main_frame, text="Save Wallets", command=self.save_wallets).grid(row=0, column=3, padx=5)

        ttk.Button(self.main_frame, text="Start Mining", command=self.start_mining).grid(row=1, column=0, pady=5)
        ttk.Button(self.main_frame, text="Stop Mining", command=self.stop_mining).grid(row=1, column=1, pady=5)

        ttk.Label(self.main_frame, text="Recipient:").grid(row=2, column=0, sticky=tk.W)
        self.recipient_entry = ttk.Entry(self.main_frame)
        self.recipient_entry.grid(row=2, column=1, sticky=(tk.W, tk.E))
        ttk.Label(self.main_frame, text="Amount:").grid(row=3, column=0, sticky=tk.W)
        self.amount_entry = ttk.Entry(self.main_frame)
        self.amount_entry.grid(row=3, column=1, sticky=(tk.W, tk.E))
        ttk.Button(self.main_frame, text="Send Transaction", command=self.send_transaction).grid(row=3, column=2, padx=5)

        self.output = scrolledtext.ScrolledText(self.main_frame, height=20, width=80)
        self.output.grid(row=4, column=0, columnspan=4, pady=10)

        self.blockchain.listeners["new_block"].append(self.on_new_block)
        self.blockchain.listeners["new_transaction"].append(self.on_new_transaction)

        self.root.after(1000, self.update_ui)
        
    def load_wallets(self):
        try:
            if not os.path.exists(self.wallet_file):
                self.wallets = {}
                return
            with open(self.wallet_file, 'r') as f:
                data = json.load(f)
                password = tk.simpledialog.askstring("Password", "Enter wallet password to decrypt:", show='*', parent=self.root)
                if not password:
                    raise ValueError("Password required to decrypt wallets")
                key, _ = derive_key(password, bytes.fromhex(data["salt"]))
                cipher = Fernet(key)
                self.wallets = {
                    name: {
                        "address": w["address"],
                        "private_key": cipher.decrypt(w["private_key"].encode()).decode(),
                        "public_key": w["public_key"]
                    }
                    for name, w in data["wallets"].items()
                }
        except (json.JSONDecodeError, ValueError, InvalidToken) as e:
            messagebox.showerror("Error", f"Failed to load wallets: {e}")
            self.wallets = {}

    def save_wallets(self):
        password = tk.simpledialog.askstring("Password", "Enter wallet password (min 8 chars, 1 upper, 1 lower, 1 digit):", show='*', parent=self.root)
        if not password or not re.match(r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).{8,}$", password):
            messagebox.showerror("Error", "Password must be at least 8 characters with 1 uppercase, 1 lowercase, and 1 digit")
            return
        key, salt = derive_key(password)
        cipher = Fernet(key)
        encrypted_wallets = {
            name: {**w, "private_key": cipher.encrypt(w["private_key"].encode()).decode()}
            for name, w in self.wallets.items()
        }
        with open(self.wallet_file, 'w') as f:
            json.dump({"key": key.decode(), "salt": salt.hex(), "wallets": encrypted_wallets}, f)
        self.update_wallet_dropdown()

    def update_wallet_dropdown(self):
        self.wallet_dropdown['values'] = list(self.wallets.keys())
        if self.wallets and not self.wallet_var.get():
            self.wallet_var.set(list(self.wallets.keys())[0])

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
            self.balance_label.config(text=f"Balance: {balance}")

    def create_wallet(self):
        name = tk.simpledialog.askstring("Wallet Name", "Enter a name for the new wallet:", parent=self.root)
        if not name:
            return
        if name in self.wallets:
            messagebox.showerror("Error", "Wallet name already exists")
            return
        self.wallets[name] = generate_wallet()
        self.update_wallet_dropdown()
        self.output.insert(tk.END, f"Created wallet '{name}'\n")

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
        self.network.add_peer(peer_id, host, port, "some_shared_secret")
        self.update_peer_list()

    def update_peer_list(self):
        self.peer_listbox.delete(0, tk.END)
        for peer_id, (host, port) in self.network.peers.items():
            self.peer_listbox.insert(tk.END, f"{peer_id}: {host}:{port}")
        self.network_stats_label.config(text=f"Peers: {len(self.network.peers)}")
        PEER_COUNT.set(len(self.network.peers))  # NEW: Update peer count metric

    def start_mining(self):
        name = self.wallet_var.get()
        if not name or name not in self.wallets:
            messagebox.showerror("Error", "Select a valid wallet")
            return
        try:
            self.miner.wallet_address = self.wallets[name]["address"]
            self.miner.start_mining()
            self.output.insert(tk.END, f"Mining started with wallet '{name}'\n")
        except Exception as e:
            messagebox.showerror("Error", f"Mining failed: {e}")

    def stop_mining(self):
        self.miner.stop_mining()
        self.output.insert(tk.END, "Mining stopped\n")

    def send_transaction(self):
        name = self.wallet_var.get()
        recipient = self.recipient_entry.get()
        try:
            amount = float(self.amount_entry.get())
            if not name or name not in self.wallets:
                messagebox.showerror("Error", "Select a valid wallet")
                return
            if not recipient or amount <= 0:
                messagebox.showerror("Error", "Invalid recipient or amount")
                return
            wallet = self.wallets[name]
            utxos = self.blockchain.utxo_set.get_utxos_for_address(wallet["address"])
            total_input = sum(utxo[2].amount for utxo in utxos)
            if total_input < amount + 0.1:  # Fee = 0.1
                messagebox.showerror("Error", "Insufficient funds")
                return
            inputs = [TransactionInput(tx_id, index, wallet["public_key"]) for tx_id, index, _ in utxos[:max(1, int(amount / total_input * len(utxos)))]]
            outputs = [TransactionOutput(recipient, amount)]
            if total_input > amount + 0.1:
                outputs.append(TransactionOutput(wallet["address"], total_input - amount - 0.1))  # Change
            tx = Transaction(TransactionType.REGULAR, inputs, outputs, fee=0.1)
            tx.sign(wallet["private_key"])
            if not tx.verify():
                messagebox.showerror("Error", "Transaction signature verification failed")
                return
            self.blockchain.mempool.add_transaction(tx)
            asyncio.run_coroutine_threadsafe(self.network.broadcast_transaction(tx), self.network.loop)
            self.output.insert(tk.END, f"Transaction sent to {recipient} for {amount} (tx_id: {tx.tx_id})\n")
            self.recipient_entry.delete(0, tk.END)
            self.amount_entry.delete(0, tk.END)
        except ValueError:
            messagebox.showerror("Error", "Amount must be a number")


    def on_new_block(self, block: Block):
        self.output.insert(tk.END, f"New block mined: {block.header.hash}\n")

    def on_new_transaction(self, tx: Transaction):
        self.output.insert(tk.END, f"New transaction: {tx.tx_id}\n")

    def update_ui(self):
        self.output.insert(tk.END, f"Chain length: {len(self.blockchain.chain)}\n")
        PEER_COUNT.set(len(self.network.peers))
        self.output.insert(tk.END, f"Connected peers: {len(self.network.peers)}\n")
        self.root.after(1000, self.update_ui)

    def exit(self):
        self.miner.stop_mining()
        self.root.quit()

    def run(self):
        self.root.mainloop()