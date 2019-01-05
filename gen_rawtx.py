# coding: utf-8
import sys
sys.path.append('.')
from gen_keypair import *
import opcodes
import binascii
import ecdsa
import requests
import time
import socket

def der_encode(r, s):
    """
    DER-encodes a signed tx. https://bitcoin.stackexchange.com/questions/12554/why-the-signature-is-always-65-13232-bytes-long
    https://github.com/bitcoin/bitcoin/blob/ce74799a3c21355b35fed923106d13a0f8133721/src/script/interpreter.cpp#L108
    """
    r_len = sizeof(r)
    s_len = sizeof(s)
    total_len = (4 + r_len + s_len) # 5 = 02 + r_len + 02 + s_len (all 1 byte)
    return b'\x30' + total_len.to_bytes(sizeof(total_len), 'big') + b'\x02' + r_len.to_bytes(sizeof(r_len), 'big') \
            + r.to_bytes(sizeof(r), 'big') + b'\x02' + s_len.to_bytes(sizeof(s_len), 'big') + s.to_bytes(sizeof(s), 'big')


class Bitcoind:
    """
    An interface to the Bitcoin daemon (or Insacoin one).
    """
    def __init__(self, url, user, password):
        self.url = url
        self.session = requests.Session()
        self.session.auth = (user, password)
        self.session.headers.update({'content-type' : 'text/plain'})

    def send(self, call, params=[]):
        """
        Makes a RPC call to the daemon.

        :param call: The method to send, as string.
        :param params: The parameters to send with the method.
        :return: The JSON response.
        """
        payload = {'jsonrpc':'1.0',
                   'id':call,
                   'method':call,
                   'params':params}
        r = self.session.post(self.url, json=payload)
        try:
            return r.json()
        except:
            raise Exception('An error occured while parsing daemon response as json. Is the node up and synced ? ', r.text)

class Script:
    """
    This class represents a Bitcoin script.
    """
    def __init__(self, script):
        """
        :param script: The script as a string.
        """
        self.script = script
        self.serialized = self.parse()
        self.size = len(self.serialized)

    def parse(self):
        """
        Parses and serializes a script.

        :return: The serialized script, as bytes.
        """
        # Parsing the string
        instructions = self.script.split(' ')
        serialized = b''
        # Filling with the corresponding OPCODEs
        for i in instructions:
            if i in opcodes.OPCODE_NAMES:
                op = opcodes.OPCODE_NAMES.index(i)
                serialized += op.to_bytes(sizeof(op), 'big')
            else:
                # There may be some hex numbers in the script which are not OPCODE
                try:
                    value = int(i, 16)
                    length = sizeof(value)
                    serialized += length.to_bytes(sizeof(length), 'big') + value.to_bytes(sizeof(value), 'big')
                except:
                    raise Exception('Unexpected instruction in script : {}'.format(i))
        if len(serialized) > 10000:
            raise Exception('Serialized script should be less than 10,000 bytes long')
        return serialized


class Output:
    """
    Represents a Bitcoin input from a transaction.
    This is an output in the view of the previous tx, because it becomes an input of the current one.
    """
    def __init__(self, txid, index):
        """
        :param txid: The hash of the transaction which formed this output.
        :param index: The place of the output in the output list.
        """
        if isinstance(txid, int):
            self.txid = txid.to_bytes(32, 'big')
        elif isinstance(txid, bytes):
            self.txid = txid
        else:
            raise Exception('txid for output should be specified as bytes or int')
        if isinstance(index, int):
            self.index = index.to_bytes(4, 'little')
        elif isinstance(index, bytes):
            self.index = index
        else:
            raise Exception('index should be bytes or int for output')
        self.script_pubkey = None # We'll fetch it later with the function below

    def fetch_script(self, bitcoind):
        """
        Fetches the script which locks this output.

        :param bitcoind: The instance to ask the script from.
        :return: The script as bytes.
        """
        txid = hex(int.from_bytes(self.txid, 'big'))[2:]
        index = int.from_bytes(self.index, 'little')
        return binascii.unhexlify(bitcoind.send('getrawtransaction', [txid, 1])['result']['vout'][index]['scriptPubKey']['hex'])

    def get_value(self, bitcoind):
        """
        Fetches the amount of coins this output locks.

        :param bitcoind: The instance to ask the script from.
        :return: The amount as satoshis.
        """
        txid = hex(int.from_bytes(self.txid, 'big'))[2:]
        index = int.from_bytes(self.index, 'little')
        amount = bitcoind.send('getrawtransaction', [txid, 1])['result']['vout'][index]['value']
        return int(amount * 100000000) # In sat


class Transaction:
    """
    Represents a Bitcoin transaction.
    For simplicity this transaction just spends one output and creates one input.
    """
    def __init__(self, daemon, vin, value, script_pubkey, fees=0, addr_change=None):
        """
        :param daemon: An instance of the Bitcoind class.
        :param vin: The list of instances of Output.
        :param value: The value spent from the output.
        :param script_pubkey: The locking script of the output created by this transaction.
        :param fees: The fees included in the tx.
        :param addr_change: The address to give back the change to.
        """
        self.network = daemon
        self.id = None
        self.serialized = None
        self.script_pubkey = script_pubkey
        self.vin = vin
        for input in self.vin:
            input.script_pubkey = input.fetch_script(self.network)
            input.script_sig = None
        len_vin = len(vin)
        self.input_cout = len_vin.to_bytes(1, 'little')
        if isinstance(value, int):
            self.value = value.to_bytes(8, 'little')
        elif isinstance(value, bytes):
            self.value = value
        else:
            raise Exception('value must be specified as int or bytes, not {}'.format(type(value)))
        # Calculating the change and the address to send it to
        input_sum = 0
        for input in vin:
            input_sum += input.get_value(self.network)
        self.change = input_sum - (int.from_bytes(self.value, 'little') + fees)
        self.addr_change = decode_check(addr_change) if addr_change else None

    def serialize(self):
        """
        Serializes the transaction.
        :return: The serialized transaction, as bytes.
        """
        tx = b'\x01\x00\x00\x00'  # version
        tx += self.input_cout
        for input in self.vin:
            tx += input.txid[::-1] # txid is stocked as big endian
            tx += input.index
            script_length = len(input.script_sig)
            tx += script_length.to_bytes(sizeof(script_length), 'big')
            tx += input.script_sig
            tx += b'\xff\xff\xff\xff'  # sequence
        if not self.change or not self.addr_change:
            tx += b'\x01'  # output count
            tx += self.value
            script_length = len(self.script_pubkey)
            tx += script_length.to_bytes(sizeof(script_length), 'big')
            tx += self.script_pubkey
        else:
            tx += b'\x02'  # output count
            # The actual output
            tx += self.value
            script_length = len(self.script_pubkey)
            tx += script_length.to_bytes(sizeof(script_length), 'big')
            tx += self.script_pubkey
            # The change output
            tx += self.change.to_bytes(8, 'little')
            script_pubkey = Script('OP_DUP OP_HASH160').parse()
            script_pubkey += len(self.addr_change).to_bytes(1, 'big')
            script_pubkey += self.addr_change
            script_pubkey += Script('OP_EQUALVERIFY OP_CHECKSIG').parse()
            script_length = len(script_pubkey)
            tx += script_length.to_bytes(sizeof(script_length), 'big')
            tx += script_pubkey
        tx += b'\x00\x00\x00\x00'  # timelock
        self.serialized = tx
        return binascii.hexlify(tx)

    def print(self):
        """
        Displays the decoded transaction in a JSON-like way.
        This method is quite messy. Actually, this function IS messy.
        """
        assert self.serialized is not None
        tx = self.serialized
        print('{')
        print(' version : ', binascii.hexlify(tx[:4]), ',')
        print(' input_count : ', tx[4], ',')
        i = 0
        for input in self.vin:
            print(' input : ')
            print('     prev_hash : ', binascii.hexlify(tx[i+5:i+37]), ',')
            print('     index : ', binascii.hexlify(tx[i+37:i+41]), ',')
            scriptsig_len = tx[i+41]
            print('     scriptsig_len : ', scriptsig_len, ',')
            print('     scriptsig : ', binascii.hexlify(tx[i+42:i+42 + scriptsig_len]), ',')
            print('     sequence', binascii.hexlify(tx[i+42 + scriptsig_len:i + 42 + scriptsig_len + 4]), ',')
            i = i + 42 + scriptsig_len - 1
        i = i + 5
        output_count = tx[i]
        print(' output_count :', output_count, ',')
        j = 0
        while j < output_count:
            print(' output ' + str(j) + ' :')
            print('     value : ', binascii.hexlify(tx[i+1:i+9]), int.from_bytes(tx[i+1:i+9], 'little'), ',')  # aie aie aie
            script_length = tx[i+9]
            print('     script_length : ', script_length, ',')
            print('     scriptpubkey : ', binascii.hexlify(tx[i+10:i+10+script_length]), ',')  # ouie
            j += 1
            i = i+9+script_length
        print(' locktime : ', binascii.hexlify(tx[i+1:i+5]), ',')
        print('}')

    def sign_outputs(self, key, pubkey):
        """
        Signs the transaction.

        :param key: The private key with which to sign the transaction.
        :param pubkey: The public key which will be added to the scriptsig.
        :return: The DER-encoded signature.
        """
        signed_vin = []
        # Signing each input
        for input in self.vin:
            # We set every other script_sig to null
            for input in self.vin:
                input.script_sig = b''
            # And the one we are actually signing to its script_pubkey
            input.script_sig = input.script_pubkey
            # To sign the transaction, we serialize it with the script_sig being the script_pubkey of the outputs spent.
            tx = binascii.unhexlify(self.serialize())
            # Then we hash this serialized transaction, giving us the payload to sign
            tx_hash = double_sha256(tx + b'\x01\x00\x00\x00', True) # + the hash_code byte
            secexp = int.from_bytes(key, 'big')
            sk = ecdsa.SigningKey.from_secret_exponent(secexp, curve=ecdsa.SECP256k1)
            # The byte appended is the hash_code byte, signifying we will use SIGHASH_ALL
            sig = sk.sign_digest(tx_hash, sigencode=ecdsa.util.sigencode_der_canonize) + b'\x01'
            sig_len = len(sig)
            pub_len = len(pubkey)
            input.script_sig = sig_len.to_bytes(sizeof(sig_len), 'big') + sig + pub_len.to_bytes(sizeof(pub_len), 'big') + pubkey
            # Everything passed by reference, I need a better algorithm
            input2 = Output(input.txid, input.index)
            input2.script_sig = input.script_sig
            input2.script_pubkey = input2.fetch_script(self.network)
            signed_vin.append(input2)
        self.vin = signed_vin

    def create_and_sign(self, privkey, pubkey):
        """
        Creates a raw transaction and signs it.

        :param privkey: The key to sign the tx with.
        :param pubkey: The corresponding public key.
        :return: A serialized and signed Bitcoin transaction.
        """
        self.sign_outputs(privkey, pubkey)
        return self.serialize()

    def send(self):
        """
        Sends the transaction to the network.
        """
        # Monkey patching of hex() erasing leading 0s
        tx = '0' + hex(int.from_bytes(self.serialized, 'big'))[2:]
        response = self.network.send('sendrawtransaction', params=[tx])
        if not response['error']:
            self.id = response['result']
            return True
        else:
            return response['error']

    def send_the_hard_way(self, ip):
        """
        Sends a transaction to the network without using RPC, just a raw network message.
        https://en.bitcoin.it/wiki/Protocol_documentation

        :param ip: The node to which send the message. A string.
        """
        # First the version message
        # https://en.bitcoin.it/wiki/Version_Handshake
        magic = 0xddb8c2fd.to_bytes(4, 'little')
        version = int(70003).to_bytes(4, 'little')
        services = int(1).to_bytes(8, 'little')
        timestamp = int(time.time()).to_bytes(8, 'little')
        myip = socket.inet_aton(requests.get('https://api.ipify.org').text)
        nodeip = socket.inet_aton(ip)
        # 7333 -> insacoin
        addr_recv = services + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff' + myip + int(7333).to_bytes(2, 'big')
        addr_from = services + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff' + nodeip + int(7333).to_bytes(2, 'big')
        nonce = 0x00.to_bytes(8, 'little')
        user_agent = 0x00.to_bytes(1, 'big')
        start_height = 0x00.to_bytes(4, 'little')
        payload = version + services + timestamp + addr_recv + addr_from + nonce + user_agent + start_height
        checksum = double_sha256(payload, bin=True)[:4]
        payload_length = len(payload)
        # NULL padded ascii command
        version_message = magic + 'version'.encode('ascii') + b'\x00\x00\x00\x00\x00' + payload_length.to_bytes(4, 'little') + checksum + payload
        # Now the tx message
        checksum = double_sha256(self.serialized, bin=True)[:4]
        tx_length = len(self.serialized)
        tx_message = magic + 'tx'.encode('ascii') + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + tx_length.to_bytes(4, 'little') + checksum + self.serialized
        # Now the verack message
        checksum = double_sha256(b'', bin=True)[:4]
        verack_message = magic + 'verack'.encode('ascii') + b'\x00\x00\x00\x00\x00\x00' + 0x00.to_bytes(4, 'little') + checksum
        # Now let's connect to the node and send it our messages
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, 7333))
        s.send(version_message)
        s.recv(1000) # receive version + verack
        s.send(verack_message)
        s.send(tx_message)
        print('Error message : ')
        print(s.recv(1000))


if __name__ == '__main__':
    # Initiating a connection to the local Insacoin running daemon
    insacoind = Bitcoind('http://127.0.0.1:7332', 'darosior', 'password')

    # A list of all the inputs my transaction is spending. Before being spent by a transaction, they are still unspent
    # outputs and are identified by the transaction which created them (txid) and their position (index in the list of
    # outputs this transaction created). In the "Transaction" class they are called inputs because they are inputs this
    # transaction is spending.
    output1 = Output(0x8913619c99a960bd1c5c75c0cf2ce3935d90387eaac86210a30417821edc5754, 0)
    #output2 = Output(0x6aacd50035834f4144ff5509137657bcf1cf830062eca06e5f6ade73a85ab1d8, 0)
    outputs = [output1]

    # The private key which will be used to sign inputs of the transaction.
    pk = wif_decode('T7KWF59taogFXEVxxDEmRy4RhcP2a98tzdfCtnxfoGr2HTJM8Mw7')
    # The public key is needed to form the scriptsig
    pub = get_pubkey(pk + b'\x01')

    # The receiver of the output, as a non-encoded address : just the hash160 of the public key.
    pub_hash = decode_check('iNFYoidN53bBM2YE2qT57SVVr8f6gF6t1g')
    # How many satoshis to send to the receiver. 1BTC=100000000sat
    value = 40000000

    # The script which will lock the coins (the script has to be standard do not put something non-standard or the tx
    # won't be accepted.
    script_pubkey = Script('OP_DUP OP_HASH160').parse() + len(pub_hash).to_bytes(1, 'big') + pub_hash + Script('OP_EQUALVERIFY OP_CHECKSIG').parse()

    # The creation of the actual transaction, an instance of the Transaction class.
    # The change is calculated automatically, if the amount sent + the fees is less than the sum of the value of every
    # inputs, then another output will be created to the change address.
    #               the daemon-the list-amount-the lock script-fees in sat-address for change
    tx = Transaction(insacoind, outputs, value, script_pubkey, 10000000, 'iFGCfMKKBmjYowmFj3vroVdcK3srzTR2Pq')
    tx.create_and_sign(pk, pub)
    response = tx.send()
    if response == True:
        print(tx.id)
    else:
        print(response)
        print(binascii.hexlify(tx.serialized))
        tx.print()