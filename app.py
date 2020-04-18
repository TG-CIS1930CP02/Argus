from uuid import uuid4

from flask import Flask, jsonify, request, json
from Model.blockchain import Blockchain

# Instantiate our node
app = Flask(__name__)

# TODO: create public-private key value
# Creates an unique address for the node
node_identifier = str(uuid4()).replace('-', '')

print("node identified")

# Instantiate the blockchain
blockchain = Blockchain(node_identifier)

print("blockchain created succesfuly")

"""
@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: invalid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201
"""


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()

    # Check that the required fields are into the posted data
    # TODO : Create API guide
    required = ['sender', 'sender_role', 'recipient', 'recipient_role', 'operation',
                'timestamp', 'institution', 'resource_path', 'resource_integrity', 'resource_type']
    required = sorted(required)
    if not all(k in values for k in required):
        return 'Missing values', 400

    data = dict([(x, values[x]) for x in required])
    tx_hash = Blockchain.hash(data)
    # Creates new transaction
    # TODO : Meta data
    # TODO : encrypt tx_hash
    transaction = {
        'dataop': 'transaction',
        'data': {
            'meta-data': {
                'encrypted_hash': tx_hash,
                'public_key': "",
            },
            'data': data
        }
    }
    json_encoded = json.dumps(transaction, ensure_ascii=False).encode('utf-8')
    blockchain.send_broadcast(json_encoded)
    response = {'message': f'Transaction succesfully commited'}
    return jsonify(response), 201


@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

# based on blockchain tutorial on python
# available at https://github.com/dvf/blockchain/blob/master/blockchain.py
