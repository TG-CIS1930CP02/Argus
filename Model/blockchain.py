import hashlib
import json
from time import time
from datetime import datetime
from threading import Timer

import requests
from urllib.parse import urlparse
from ordered_set import OrderedSet

TIME_SLICE_SECONDS = 1.0


class Blockchain(object):
    print("creating class BC")

    def __init__(self, node_identifier):
        print("... Initializing constructor")
        self.current_transactions = []
        self.chain = []
        # TODO: Change nodes for mining_nodes
        self.nodes = set(node_identifier)
        # Reminder: we need to sort the mining_nodes to get the desired behaviour
        self.mining_nodes = OrderedSet(self.nodes)

        self.node_identifier = node_identifier
        # create genesis block
        self.new_block(previous_hash=1, proof=100)
        # start mining process
        print("GOING TO RUN")
        self.mining_task()

    def register_node(self, address):
        """
        Adds a node to list of nodes
        :param address: <str> Address of new node
        """
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)

    def mining_task(self):
        time_in_seconds = int(datetime.now().timestamp())
        # TODO: We need to access the list of nodes thread safe
        # if time_in_seconds % len(self.mining_nodes) == self.mining_nodes.index(self.node_identifier):
        if True:
            # TODO: Create the block correctly
            print("MINING in second {}".format(time_in_seconds))
        Timer(TIME_SLICE_SECONDS, self.mining_task).start()

    def new_block(self, proof, previous_hash=None):
        # Creates a new block and adds it to the bc
        """
        Creates a new block
        :param proof: <int> The proof given by the Proof of Work algorithm
        :param previous_hash: (Optional) <str> Hash of previous Block
        :return: <dict> New Block
        """
        block = {
            'index': len(self.chain) + 1,  # chains lenght +1
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        # Reset the current list of transactions
        self.current_transactions = []

        self.chain.append(block)
        return block

    def new_transaction(self, institution, medic, patient, operation):
        """
        This method creates a new transaction and adds it to the
        transaction list of the current latest block, this method recives:
        :param: institution: <str> adress of the institution
        :param: medic <str> id of the medic responsable for operation
        :param: patient <str> adress of patient ? or patient id
        :param: operation <str> operation performed to database
        """
        self.current_transactions.append({
            'institution': institution,
            'medic': medic,
            'patient': patient,
            'operation': operation,
        })
        return self.last_block['index'] + 1

    def valid_chain(self, chain):
        """
        Determine if a blockchain is valid
        :param chain: <list> this node copy of the blockchain
        :return: <bool> true valid chain, false not
        """

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            # Check that the hash of the block is correct
            last_block_hash = self.hash(last_block)
            if block['previous_hash'] != self.hash(last_block):
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['proof'], block['proof'], last_block_hash):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        This is our Consensus Algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.
        :return: <bool> True if our chain was replaced, False if not
        """

        neighbours = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            response = requests.get(f'http://{node}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # Replace chain if discovered a valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False

    @staticmethod
    def hash(block):  # hashblock
        """
        Creates a SHA-256 hash of a Block
        :param block: <dict> Block
        :return: <str>
        """

        # We must make sure that the Dictionary is Ordered,
        #  or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def valid_proof(last_proof, proof, last_hash):
        """
        Validates wheter the proof is acceptable
        which means, if the hash (last_proof, proof) contains 2 leading zeroes
        :param: last_proof <int>
        :param: proof <int>
        :return: <bool> True if correct, False otherwhise
        """
        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:2] == "00"
