import time
import hashlib
import json
import os
from flask import Flask, jsonify, request
import requests
from urllib.parse import urlparse

BLOCKCHAIN_FILE = "blockchain.json"  # File to store blockchain data

class Blockchain:
    def __init__(self):
        self.chain = []
        self.nodes = set()
        self.nodes.add("127.0.0.1:5111")

        # Load blockchain from file if it exists
        self.load_chain()

    def create_block(self, proof, previous_hash, sender, receiver, file_hash):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.strftime("%d %B %Y , %I:%M:%S %p", time.localtime()),
            'proof': proof,
            'previous_hash': previous_hash,
            'sender': sender,
            'receiver': receiver,
            'shared_files': file_hash
        }
        self.chain.append(block)

        # Save updated blockchain to file
        self.save_chain()
        return block

    def get_previous_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False
        while not check_proof:
            hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] == '0000':
                check_proof = True
            else:
                new_proof += 1
        return new_proof

    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def is_chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash(previous_block):
                return False
            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha256(str(proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] != '0000':
                return False
            previous_block = block
            block_index += 1
        return True

    def add_file(self, sender, receiver, file_hash):
        previous_block = self.get_previous_block()
        previous_proof = previous_block['proof']
        proof = self.proof_of_work(previous_proof)
        previous_hash = self.hash(previous_block)
        return self.create_block(proof, previous_hash, sender, receiver, file_hash)

    def save_chain(self):
        """Saves blockchain data to a file."""
        with open(BLOCKCHAIN_FILE, 'w') as f:
            json.dump(self.chain, f, indent=4)

    def load_chain(self):
        """Loads blockchain data from a file if it exists."""
        if os.path.exists(BLOCKCHAIN_FILE):
            try:
                with open(BLOCKCHAIN_FILE, 'r') as f:
                    self.chain = json.load(f)
                print("✅ Blockchain loaded from file.")
            except (json.JSONDecodeError, IOError):
                print("⚠️ Error loading blockchain, creating a new one.")
                self.create_genesis_block()
        else:
            self.create_genesis_block()

    def create_genesis_block(self):
        """Creates the first block if the blockchain file is missing or corrupted."""
        print("🌱 Creating Genesis Block...")
        self.create_block(proof=1, previous_hash='0', sender='N.A', receiver='N.A', file_hash='N.A')

    def replace_chain(self):
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)
        for node in network:
            response = requests.get(f'http://{node}/get_chain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                if length > max_length and self.is_chain_valid(chain):
                    max_length = length
                    longest_chain = chain
        if longest_chain:
            self.chain = longest_chain
            self.save_chain()
            return True
        return False
