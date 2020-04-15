import hashlib
import json
from datetime import datetime
from threading import Timer, Thread
import socket
from ordered_set import OrderedSet

TIME_SLICE_SECONDS = 1.0
TIME_NEW_BLOCK = 5
PORT = 3222
BROADCAST_IP = None
RAS_IP = None


class Blockchain(object):
    print("creating class BC")

    def __init__(self, node_identifier):
        print("... Initializing constructor")
        self.current_transactions = []
        self.chain = []
        dict_config = json.loads(open('config.json', 'r').read())
        global BROADCAST_IP
        BROADCAST_IP = dict_config.get('broadcastIp')
        global RAS_IP
        RAS_IP = dict_config.get('rasIp')
        # Reminder: we need to sort the mining_nodes to get the desired behaviour
        self.mining_nodes = OrderedSet()
        self.mining_nodes.add(node_identifier)
        sorted(self.mining_nodes)
        self.node_identifier = node_identifier
        # create genesis block
        genesis = self.new_block(previous_hash=1)
        self.chain.append(genesis)
        # start mining process
        print("GOING TO RUN")
        Thread(target=self.mining_task).start()
        Thread(target=self.listen_broadcast).start()

    def register_node(self, node_public_key):
        """
        Adds a node to list of nodes
        :param node_public_key: <str> Address of new node
        """
        # parsed_url = urlparse(address)
        self.mining_nodes.add(node_public_key)
        sorted(self.mining_nodes)

    def mining_task(self):
        time_in_seconds = int(datetime.now().timestamp())
        time_div = time_in_seconds//TIME_NEW_BLOCK
        # concurrent access to mining nodes by mining task, and add/remove nodes
        if time_in_seconds % TIME_NEW_BLOCK == 0 and\
                time_div % len(self.mining_nodes) == self.mining_nodes.index(self.node_identifier):
            # TODO: Create the block correctly
            # self.new_block(time_in_seconds)
            Thread(target=Blockchain.send_broadcast,args=[json.dumps({
                'dataop': 'block',
                'data': self.new_block(time_in_seconds)
            }).encode()]).start()

        Timer(TIME_SLICE_SECONDS, self.mining_task).start()

    def add_block(self, block):
        self.chain.append(block.get('data'))

    def listen_broadcast(self):
        listen_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen_socket.bind(('', PORT))
        # TODO: try to put in is json mode, catch if not possible, then check for operation and decide what to do
        while True:
            data, addr = listen_socket.recvfrom(4096)
            try:
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
                print("Packet couldn't be interpreted {}".format(e))

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
        block = {
            'index': len(self.chain) + 1,
            'timestamp': block_time,
            'transactions': self.current_transactions,
            # 'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }
        # Reset the current list of transactions
        self.current_transactions = []

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

        """
        with self.thread_lock:
            self.current_transactions.append({
                'institution': institution,
                'medic': medic,
                'patient': patient,
                'operation': operation,
            })
            height_added = self.last_block['index'] + 1

        return height_added
        """
        # print("json data is {}".format(json_data))
        self.current_transactions.append(json_data.get('data'))
        height_added = self.last_block['index'] + 1

        return height_added

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

