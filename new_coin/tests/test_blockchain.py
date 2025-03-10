import unittest
from blockchain import Blockchain

class TestBlockchain(unittest.TestCase):
    def setUp(self):
        self.blockchain = Blockchain()

    def test_create_transaction(self):
        tx = self.blockchain.create_transaction("private_key", "address1", "address2", 10.0)
        self.assertIsNotNone(tx)

if __name__ == '__main__':
    unittest.main()