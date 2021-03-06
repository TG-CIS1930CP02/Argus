import json
from datetime import datetime
from threading import Timer, Thread
import time
import socket
from ordered_set import OrderedSet
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import requests
import random

import binascii

TIME_SLICE_SECONDS = 1
TIME_NEW_BLOCK = 5
PORT = 3222
BROADCAST_IP = None
RAS_IP = None
SERVICE_PORT = None

class Blockchain(object):
    print("creating class BC")

    def __init__(self, key_pair):
        print("... Initializing constructor")
        self.current_transactions = []
        self.chain = []
        dict_config = json.loads(open('config.json', 'r').read())
        global BROADCAST_IP
        BROADCAST_IP = dict_config.get('broadcastIp')
        global RAS_IP
        RAS_IP = dict_config.get('rasIp')
        global SERVICE_PORT
        SERVICE_PORT = dict_config.get('port')
        pub_key = key_pair.public_key().export_key(format='OpenSSH')
        json_post = {'publicKey': pub_key, 'port': SERVICE_PORT}
        requests.post("http://{}/node".format(RAS_IP), json=json_post)
        self.key_pair = key_pair
        self.node_identifier = pub_key

        self.boot_node_list = []
        self.last_update = int(datetime.now().timestamp())
        self.mining_nodes_list = OrderedSet()
        self.ask_for_nodes()

        # create genesis block
        if len(self.mining_nodes) <= 1:
            genesis = self.new_block(previous_hash=1)
            self.chain.append(genesis)
        else:
            # TODO : generate random number...
            my_list = self.boot_node_list
            address = my_list[0].get('ip')
            self.chain = json.loads(requests.get("http://{}/chain".format(address)).content).get('chain')
            print("Select random forom boot_node_list and ask him for chain")

        # start mining process
        print("GOING TO RUN")
        Thread(target=self.mining_task).start()
        Thread(target=self.listen_broadcast).start()

    @property
    def mining_nodes(self):
        time_in_seconds = int(datetime.now().timestamp())
        if abs(self.last_update - time_in_seconds) >= 2.5:
            self.last_update = time_in_seconds
            Thread(target=self.ask_for_nodes).start()

        return self.mining_nodes_list

    def ask_for_nodes(self):
        nodes_list = requests.get("http://{}/node".format(RAS_IP))
        nodes_list = json.loads(nodes_list.content)
        self.boot_node_list = nodes_list
        m_set = OrderedSet()
        for node in nodes_list:
            m_set.add(node.get('publicKey'))
        m_set = sorted(m_set)
        self.mining_nodes_list = m_set

    def mining_task(self):
        while True:
            time_in_seconds = int(datetime.now().timestamp())
            time_div = time_in_seconds//TIME_NEW_BLOCK
            temp = self.mining_nodes
            # concurrent access to mining nodes by mining task, and add/remove nodes
            if self.node_identifier in temp and time_in_seconds % TIME_NEW_BLOCK == 0 and\
                    time_div % len(temp) == temp.index(self.node_identifier):
                Thread(target=Blockchain.send_broadcast, args=[json.dumps({
                    'dataop': 'block',
                    'data': self.new_block(time_in_seconds)
                }).encode()]).start()
            time.sleep(TIME_SLICE_SECONDS)

    def add_block(self, json_block):
        # TODO : verify all required values are on the Block
        block = json_block.get('data')

        try:
            o_pub_key = block.get('meta_data').get('public_key')
            if o_pub_key not in self.mining_nodes:
                raise ValueError('No dataop found')
            recv_public_key = ECC.import_key(o_pub_key)
            signed_hash_hex = block.get('meta_data').get('signed_hash')
            signed_hash = binascii.unhexlify(signed_hash_hex)
            my_block_txs = block.get('transactions')
            my_merkle_root = Blockchain.merkle_root(my_block_txs, 0, len(my_block_txs))
            if my_merkle_root != block.get('block_data').get('merkle_root'):
                raise ValueError("Merkle root is inconsistent")
            my_hash = Blockchain.hash_object(block.get('block_data'))
            verifier = DSS.new(recv_public_key, 'deterministic-rfc6979')
            verifier.verify(my_hash, signed_hash)
            self.chain.append(block)
            self.current_transactions = [el for el in self.current_transactions if el not in block.get('transactions')]
        except Exception as e:
            print("Not valid block, inconsistent hash, exception {}".format(e))

    def listen_broadcast(self):
        listen_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen_socket.bind(('', PORT))
        while True:
            try:
                data, addr = listen_socket.recvfrom(65507)
                data = json.loads(data)
                data_op = data.get('dataop')
                if data_op is None:
                    raise ValueError('No dataop found')
                switch = {
                    'transaction': self.new_transaction,
                    'block': self.add_block
                }
                fun = switch.get(data_op)
                if fun is None:
                    raise ValueError('No operation supported')
                fun(data)
            except Exception as e:
                print("Packet couldn't be interpreted or overflow {}".format(e))

    @staticmethod
    def send_broadcast(message_encoded):
        """
        :param message_encoded: <bytes> the message to be broadcast in bytes
        :return: <bool> Broadcast status
        """
        try:
            send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            send_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            send_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            send_socket.sendto(message_encoded, (BROADCAST_IP, PORT))
            send_socket.close()
            return True
        except Exception as e:
            print("Failed with exception {}".format(e))
            return False

    def new_block(self, block_time=int(datetime.now().timestamp()), previous_hash=None):
        """
        Creates a new block
        :param block_time: <int> Time when the block is done
        :param previous_hash: (Optional) <str> Hash of previous Block
        :return: <dict> New Block
        """
        tx_copy = list(self.current_transactions)
        self.current_transactions = []

        block_data = {
            'merkle_root': Blockchain.merkle_root(tx_copy, 0, len(tx_copy)),
            'index': len(self.chain) + 1,
            'timestamp': block_time,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }
        block_hash = Blockchain.hash_object(block_data)
        signer = DSS.new(self.key_pair, 'deterministic-rfc6979')
        signature = signer.sign(block_hash)
        block = {
            'meta_data': {
                "public_key": self.node_identifier,
                "signed_hash": signature.hex()
            },
            'block_data': block_data,
            'transactions': tx_copy
        }
        # TODO : test block
        return block

    def new_transaction(self, json_data):
        # TODO: create filter function to validate json keys, and define valid types
        """
        This method creates a new transaction and adds it to the
        transaction list of the current latest block, this method recives:
        :param: institution: <str> adress of the institution
        :param: medic <str> id of the medic responsable for operation
        :param: patient <str> adress of patient ? or patient id
        :param: operation <str> operation performed to database
        """
        # TODO : verify all required values are on the Tx
        data_dict = json_data.get('data')
        # print("json data is {}".format(json_data))
        o_pub_key = data_dict.get('meta_data').get('public_key')
        try:
            if o_pub_key not in self.mining_nodes:
                raise ValueError('No dataop found')
            recv_public_key = ECC.import_key(o_pub_key)
            signed_hash_hex = data_dict.get('meta_data').get('signed_hash')
            signed_hash = binascii.unhexlify(signed_hash_hex)
            my_hash = Blockchain.hash_object(data_dict.get('data'))
            verifier = DSS.new(recv_public_key, 'deterministic-rfc6979')
            verifier.verify(my_hash, signed_hash)
            self.current_transactions.append(data_dict)
            height_added = self.last_block['block_data']['index'] + 1
        except Exception as e:
            height_added = -1
            print("Not valid node or transaction hash, exception {}".format(e))
        return height_added

    def valid_chain(self, chain):
        """
        Determine if a blockchain is valid
        :param chain: <list> this node copy of the blockchain
        :return: <bool> true valid chain, false not
        """
        # TODO : Verify
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
        # TODO: Fix the blockchain score mechanism
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
        """
        return True

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
        return SHA256.new(block_string).hexdigest()

    @staticmethod
    def hash_object(block):
        """
        Creates a SHA-256 hash of a Block
        :param block: <dict> Block
        :return: <SHA256 object>
        """
        # We must make sure that the Dictionary is Ordered,
        #  or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return SHA256.new(block_string)

    @staticmethod
    def merkle_root(tx_list, a, b):
        """
        :param tx_list: [list] tx_list
        :param a: <int> beginning of list
        :param b: <int> end of list
        :return: <str> the root hash of merkle tree
        """
        # a is inclusive, b is exclusive
        if b == a:
            return ""

        m = (a + b) // 2
        if a == b-1:
            # Base case, we have only 1 element
            return Blockchain.hash(tx_list[a])
        else:
            # check if we can sum, both hashes :p or need to use hexdigest
            return SHA256.new(
                bytes(Blockchain.merkle_root(tx_list, a, m) +
                      Blockchain.merkle_root(tx_list, m, b), 'utf-8')).hexdigest()  # this is [a,m) [m,b)

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
        # TODO: change it for veryfing tat the node that signs is a valid one, ak for nodes and verify
        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = SHA256.new(guess).hexdigest()
        return guess_hash[:2] == "00"

    def search_transaction(self, transaction, chain):
        """
        Searches for a given transaction
        """
        current_index = 0
        while current_index < len(chain):
            block = chain[current_index]
            for block_transaction in block["transactions"]:
                if block_transaction == transaction:
                    return True
            current_index += 1
        return False

    def search_history(self, param,  chain):
        """
        Search for the medical history of a patient
        :param: id <str>
        :param: chain <block>
        :return: <dict> list of all transactions for a patient
        """
        current_index = 0
        result = []
        while current_index < len(chain):
            block = chain[current_index]
            for block_transaction in block["transactions"]:
                transaction_data = block_transaction["data"] 
                if param == transaction_data["recipient"]:
                    result.append(transaction_data)
            current_index += 1
        if len(result) == 0:
            response =  {'message': f' Patient transactions not found'}
            return response
        else:
            return result

    def search_emergency(self, patient_id,  chain):
        """
        Search for the parameters needed in an emergency
        :param: id <str>
        :param: chain <block>
        :return: <dict> list of transactions for emergency 
        """
        current_index = 0
        result = []
        while current_index < len(chain):
            block = chain[current_index]
            for block_transaction in block["transactions"]: 
                transaction_data = block_transaction["data"]
                if patient_id == transaction_data["recipient"]:
                    if transaction_data["operation"] == "ADD":
                        if transaction_data["resourceType"]== "AllergyIntolerance" or transaction_data["resourceType"]== "Patient" or transaction_data["resourceType"]== "Condition":
                            result.append(transaction_data)
            current_index += 1

        if len(result) == 0:
            response =  {'message': f' Patient transactions not found'}
            return response
        else:
            return result

    def search_resources(self, patient_id,  chain):
        """
        Search for all the creation transactions in a patient history
        :param: id <str>
        :param: chain <block>
        :return: <dict> list of transactions  
        """
        current_index = 0
        result = []
        while current_index < len(chain):
            block = chain[current_index]
            for block_transaction in block["transactions"]:
                transaction_data = block_transaction["data"]
                if patient_id == transaction_data["recipient"]:
                    if transaction_data["operation"] == "ADD":
                        result.append(transaction_data)
            current_index += 1
        if len(result) == 0:
            response =  {'message': f' Patient transactions not found'}
            return response
        else:
            return result
