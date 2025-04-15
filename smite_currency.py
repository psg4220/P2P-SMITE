import os
import subprocess
import sys
import time
import json
from threading import Thread
import requests

from microcurrency import (
    generate_key_pair,
    create_root_certificate,
    create_node_certificate,
    Certificate,
    Permission,
    load_block,
    verify_block_authority,
    verify_transaction
)

from cryptography.hazmat.primitives import serialization

APP_FILE = "app.py"
CERT_FILE = "blocks/certificate.dat"
NODES_FILE = "nodes.txt"
MAX_NODES = 20
BLOCKS_DIR = "blocks"

# Global variable to track the app.py process
app_process = None

def start_app():
    """Start app.py as a subprocess."""
    global app_process
    if app_process is None or app_process.poll() is not None:
        try:
            app_process = subprocess.Popen([sys.executable, APP_FILE])
            print(f"[✓] app.py started, PID: {app_process.pid}")
        except Exception as e:
            print(f"[!] Failed to start app.py: {e}")
    else:
        print("[*] app.py is already running.")

def stop_app():
    """Stop the currently running app.py process."""
    global app_process
    if app_process and app_process.poll() is None:
        try:
            app_process.terminate()
            app_process.wait(timeout=5)
            print("[✓] app.py stopped.")
            app_process = None
        except Exception as e:
            print(f"[!] Failed to stop app.py: {e}")
    else:
        print("[*] app.py is not running.")

def manage_app_process():
    """Menu for managing app.py process."""
    while True:
        print("\n[App Process Menu]")
        print("[1] Start app.py")
        print("[2] Stop app.py")
        print("[0] Back to main menu")
        choice = input("Choose: ").strip()
        if choice == "0":
            return
        elif choice == "1":
            start_app()
        elif choice == "2":
            stop_app()
        else:
            print("[!] Unknown option")

def load_certificate():
    try:
        with open(CERT_FILE, 'rb') as f:
            return Certificate.deserialize(f.read())
    except Exception as e:
        print(f"[!] Failed to load certificate: {e}")
        return None

def private_key_hex_to_obj(hex_key):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    try:
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(hex_key))
    except Exception as e:
        print(f"[!] Invalid private key format: {e}")
        return None

def create_certificate():
    while True:
        print("\n[1] Create ROOT certificate")
        print("[2] Create STANDARD certificate (requires ROOT key)")
        print("[0] Back to main menu")
        choice = input("Choose: ").strip()

        if choice == "0":
            return

        try:
            # User-provided private key
            private_key_hex = input("Enter your private key (hex): ").strip()
            private_key = private_key_hex_to_obj(private_key_hex)
            if not private_key:
                print("[!] Invalid private key.")
                return

            public_key = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ).hex()
            print(f"[*] Public key derived: {public_key}")

            if choice == "1":
                fee_percentage = float(input("Transaction fee percentage (e.g. 0.01 for 1%): ").strip())
                currency_name = input("Currency name (e.g. MyCoin): ").strip()
                currency_ticker = input("Currency ticker (e.g. MYC): ").strip()

                # Update .env PRIVATE_KEY
                try:
                    env_file = ".env"
                    lines = []
                    if os.path.exists(env_file):
                        with open(env_file, "r") as f:
                            lines = f.readlines()
                    updated = False
                    with open(env_file, "w") as f:
                        for line in lines:
                            if line.startswith("PRIVATE_KEY="):
                                f.write(f"PRIVATE_KEY={private_key_hex}\n")
                                updated = True
                            else:
                                f.write(line)
                        if not updated:
                            f.write(f"PRIVATE_KEY={private_key_hex}\n")
                    print("[✓] .env PRIVATE_KEY updated")
                except Exception as e:
                    print(f"[!] Failed to update .env PRIVATE_KEY: {e}")

                cert = create_root_certificate(
                    public_key=public_key,
                    private_key=private_key,
                    fee_percentage=fee_percentage,
                    currency_name=currency_name,
                    currency_ticker=currency_ticker
                )
            elif choice == "2":
                issuer_private_key = input("Issuer private key: ").strip()
                issuer_pub = input("Issuer public key: ").strip()
                issuer_obj = private_key_hex_to_obj(issuer_private_key)
                if not issuer_obj:
                    return
                cert = create_node_certificate(public_key, Permission.CAN_VERIFY.value, issuer_pub, issuer_obj)
            else:
                print("[!] Invalid choice")
                continue

            with open(CERT_FILE, 'wb') as f:
                f.write(cert.serialize())
            print("[✓] Certificate saved to:", CERT_FILE)
            return
        except Exception as e:
            print(f"[!] Error creating certificate: {e}")
            return

def manage_wallet():
    while True:
        print("\n[Wallet Menu]")
        print("[1] Generate New Wallet")
        print("[0] Back to main menu")
        choice = input("Choose: ").strip()

        if choice == "0":
            return
        elif choice == "1":
            try:
                private_key, public_key = generate_key_pair()
                print(f"Generated Wallet:\nPrivate Key: {private_key}\nPublic Key: {public_key}")
            except Exception as e:
                print(f"[!] Error generating wallet: {e}")
        else:
            print("[!] Invalid choice")

def send_transaction(tx_type="OUTPUT"):
    cert = load_certificate()
    if not cert:
        return

    while True:
        print("\n[Send Transaction Menu]")
        print("[0] Back to main menu")
        sender = input("Sender public key: ").strip()
        if sender == "0": return
        recipient = input("Recipient public key: ").strip()
        if recipient == "0": return
        amount = input("Amount: ").strip()
        if amount == "0": return
        privkey = input("Sender private key: ").strip()
        if privkey == "0": return

        from microcurrency import Transaction, TransactionType
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        try:
            amount = int(amount)
            private_obj = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(privkey))

            # Primary transaction signature
            tx_data = f"{sender}{recipient}{amount}{TransactionType[tx_type].value}"
            signature = private_obj.sign(tx_data.encode()).hex()

            payload = {
                "sender": sender,
                "recipient": recipient,
                "amount": amount,
                "tx_type": tx_type,
                "signature": signature
            }

            # Calculate fee and fee signature if OUTPUT
            if tx_type == "OUTPUT":
                # Fetch fee_percentage from node to estimate fee
                url = get_active_node()
                status = requests.get(f"{url}/status", timeout=5).json()
                fee_percentage = float(status.get("certificate", {}).get("fee_percentage", cert.fee_percentage))
                fee = int(amount * fee_percentage)
                if fee > 0:
                    fee_recipient = status.get("certificate", {}).get("fee_recipient", cert.fee_recipient or sender)
                    fee_tx_data = f"{sender}{fee_recipient}{fee}{TransactionType.OUTPUT.value}"
                    payload["fee_signature"] = private_obj.sign(fee_tx_data.encode()).hex()

            url = get_active_node()
            res = requests.post(f"{url}/transaction", json=payload, timeout=5)
            print(res.json())
            return
        except ValueError:
            print("[!] Invalid amount format. Must be an integer.")
        except Exception as e:
            print(f"[!] Transaction failed: {e}")
            return
def view_balance():
    """View the balance of a specified public key."""
    print("\n[View Balance Menu]")
    print("[0] Back to main menu")
    address = input("Enter public key to check balance: ").strip()
    if address == "0":
        return

    try:
        url = get_active_node()
        response = requests.get(f"{url}/balance/{address}", timeout=5)
        data = response.json()
        if response.status_code == 200:
            print(f"\n[✓] Balance for {data['address']}:\n{data['balance']} {load_certificate().currency_ticker}")
        else:
            print(f"[!] Error: {data.get('error', 'Unknown error')}")
    except Exception as e:
        print(f"[!] Failed to retrieve balance: {e}")

def get_active_node():
    try:
        if not os.path.exists(NODES_FILE):
            return "http://localhost:5000"
        with open(NODES_FILE) as f:
            nodes = [line.strip() for line in f.readlines()[:MAX_NODES]]
            return nodes[0] if nodes else "http://localhost:5000"
    except Exception as e:
        print(f"[!] Error loading nodes: {e}")
        return "http://localhost:5000"

def manage_nodes():
    while True:
        print("\n[Node Menu]")
        print("[1] View Nodes")
        print("[2] Add Node")
        print("[3] Remove Node")
        print("[4] Switch Active Node")
        print("[0] Back to main menu")
        choice = input("Choose: ").strip()

        if choice == "0":
            return
        elif choice == "1":
            try:
                with open(NODES_FILE) as f:
                    nodes = f.readlines()
                for i, node in enumerate(nodes[:MAX_NODES]):
                    print(f"{i+1}: {node.strip()}")
            except Exception as e:
                print(f"[!] Error reading nodes: {e}")
        elif choice == "2":
            node = input("Enter new node URL: ").strip()
            try:
                with open(NODES_FILE, 'a') as f:
                    f.write(node + "\n")
                print("[✓] Node added")
            except Exception as e:
                print(f"[!] Failed to add node: {e}")
        elif choice == "3":
            try:
                with open(NODES_FILE) as f:
                    nodes = f.readlines()
                for i, node in enumerate(nodes[:MAX_NODES]):
                    print(f"{i+1}: {node.strip()}")
                idx = int(input("Index to remove: ")) - 1
                if 0 <= idx < len(nodes):
                    nodes.pop(idx)
                    with open(NODES_FILE, 'w') as f:
                        f.writelines(nodes)
                    print("[✓] Node removed")
                else:
                    print("[!] Invalid index")
            except Exception as e:
                print(f"[!] Error removing node: {e}")
        elif choice == "4":
            try:
                with open(NODES_FILE) as f:
                    nodes = f.readlines()
                for i, node in enumerate(nodes[:MAX_NODES]):
                    print(f"{i+1}: {node.strip()}")
                idx = int(input("Index to move to top: ")) - 1
                if 0 <= idx < len(nodes):
                    nodes.insert(0, nodes.pop(idx))
                    with open(NODES_FILE, 'w') as f:
                        f.writelines(nodes)
                    print("[✓] Node switched")
                else:
                    print("[!] Invalid index")
            except Exception as e:
                print(f"[!] Error switching node: {e}")
        else:
            print("[!] Invalid option")

def display_block_info():
    url = get_active_node()
    try:
        print("\n[Block Info Menu]")
        current = requests.get(f"{url}/get_current_block").json()
        pending = requests.get(f"{url}/get_pending_block").json()
        print("\n[*] Current Block:")
        print(json.dumps(current, indent=2))
        print("\n[*] Pending Block:")
        print(json.dumps(pending, indent=2))
    except Exception as e:
        print("[!] Failed to retrieve block info:", e)

def verify_chain():
    print("\n[*] Verifying blockchain...")
    index = 0
    previous_hash = "0" * 64
    while True:
        path = os.path.join(BLOCKS_DIR, f"blk{index}.dat")
        if not os.path.exists(path):
            break
        try:
            block = load_block(index, BLOCKS_DIR)
            if not block:
                print(f"[!] Failed to load block {index}")
                return
            if block.previous_hash != previous_hash:
                print(f"[!] Block {index} has invalid previous hash")
                return
            if not verify_block_authority(block, block.node_certificate.issued_by):
                print(f"[!] Block {index} failed verification")
                return
            for tx in block.transactions:
                if not verify_transaction(tx, block.node_certificate, block.node_certificate.issued_by):
                    print(f"[!] Invalid transaction in block {index}")
                    return
            print(f"[\u2713] Block {index} verified")
            previous_hash = block.block_hash
            index += 1
        except Exception as e:
            print(f"[!] Error verifying block {index}: {e}")
            return
    print("[\u2713] Blockchain verification completed successfully")

def main_menu():
    # Do not auto-start the node now; the user can manage it manually.
    while True:
        print("\n[smite_currency Menu]")
        print("[1] Create Certificate")
        print("[2] Manage Wallet")
        print("[3] Mint Funds (ROOT only)")
        print("[4] Send Funds (OUTPUT)")
        print("[5] Manage Nodes")
        print("[6] Display Block Info")
        print("[7] Verify Blockchain")
        print("[8] Manage App Process")
        print("[9] View Balance")
        print("[0] Exit")

        choice = input("Choose: ").strip()
        if choice == "1":
            create_certificate()
        elif choice == "2":
            manage_wallet()
        elif choice == "3":
            send_transaction(tx_type="MINT")
        elif choice == "4":
            send_transaction(tx_type="OUTPUT")
        elif choice == "5":
            manage_nodes()
        elif choice == "6":
            display_block_info()
        elif choice == "7":
            verify_chain()
        elif choice == "8":
            manage_app_process()
        elif choice == "9":
            view_balance()
        elif choice == "0":
            print("Exiting...")
            break
        else:
            print("[!] Unknown option")

if __name__ == "__main__":
    main_menu()