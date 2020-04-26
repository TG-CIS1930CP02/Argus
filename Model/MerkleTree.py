import math
import hashlib


class MerkleNode:
    def __init__(self, node1, node2):
        self.left = node1
        self.right = node2
        self.leaf = False
        combined_hash = f'{node1.hash}{node2.hash}'.encode()

        self.hash = hashlib.sha256(combined_hash).hexdigest()
    
    def check_node(self):
        combined_hash_test = f'{self.left.hash}{self.right.hash}'.encode()
        hash_test = hashlib.sha256(combined_hash_test).hexdigest()
        if self.hash == hash_test:
            return True
        return False

class Leaf:
    def __init__(self, transaction):
        self.transaction = transaction
        self.leaf = True
        content = f'{self.transaction["sender"]}{self.transaction["sender_role"]}{self.transaction["recipient"]}{self.transaction["recipient_role"]}{self.transaction["operation"]}{self.transaction["timestamp"]}{self.transaction["institution"]}{self.transaction["resource_path"]}{self.transaction["resource_integrity"]}{self.transaction["resource_type"]}'.encode()
        self.hash = hashlib.sha256(content).hexdigest()



class MerkleTree:
    def __init__(self, transactions):
        self.root = self.create_tree(transactions)

    def create_tree(self, transactions):
        leafs = []
        for transaction in transactions:
            leafs.append( Leaf(transaction) )

        if math.remainder(len(leafs),2) != 0:
            leafs.append(leafs[-1])
        
        nodes = leafs
        while len(nodes) != 1:
            nodes=self.set_nodes(nodes)
        
        return nodes[0]

    def set_nodes(self, nodes):
        stack = []
        new_nodes = []

        if math.remainder(len(nodes),2) != 0:
            nodes.append(nodes[-1])

        for node in nodes:
            stack.append(node)

            if len(stack) == 2:
                node2 = stack.pop()
                node1 = stack.pop()
                new_nodes.append(MerkleNode(node1,node2))

        return new_nodes

    def check_tree(self, node):
        if node.leaf == False:
            if node.check_node() == False:
                return False
            else:
                if self.check_tree(node.right) == False:
                    return False
                if self.check_tree(node.left) == False:
                    return False
        #else:
        #   print("Leaf")
        #   print(node.transaction["patient"])
        return True

