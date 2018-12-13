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
        return r.json()

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


class Transaction:
    """
    Represents a Bitcoin transaction.
    For simplicity this transaction just spends one output and creates one input.
    """
    def __init__(self, daemon, prev_hash, index, script_sig, value, script_pubkey):
        """
        :param daemon: An instance of the Bitcoind class.
        :param prev_hash: The id of the transaction which contains the output spent by this transaction.
        :param index: The index of the output spent by this transaction in the output list of the precedent one.
        :param script_sig: The unlocking script of the output of this transaction.
        :param value: The value spent from the output.
        :param script_pubkey: The locking script of the output created by this transaction.
        """
        self.network = daemon
        self.id = None
        self.serialized = None
        self.script_pubkey = script_pubkey
        if isinstance(prev_hash, int):
            self.prev_hash = prev_hash.to_bytes(sizeof(prev_hash), 'big')
        elif isinstance(prev_hash, bytes):
            self.prev_hash = prev_hash
        else:
            raise Exception('prev_hash must be specified as int or bytes, not {}'.format(type(prev_hash)))
        if isinstance(index, int):
            self.index = index.to_bytes(4, 'little', )
        elif isinstance(index, bytes):
            self.index = index
        else:
            raise Exception('index must be specified as int or bytes, not {}'.format(type(index)))
        # For P2PKH We generate script_sig in sign() so it's not needed
        if not script_sig:
            self.script_sig = self.get_prev_pubkey()
        else:
            self.script_sig = script_sig
        if isinstance(value, int):
            self.value = value.to_bytes(8, 'little')
        elif isinstance(value, bytes):
            self.value = value
        else:
            raise Exception('value must be specified as int or bytes, not {}'.format(type(value)))

    def serialize(self, script_sig=None):
        """
        Serializes the transaction.
        :return: The serialized transaction, as bytes.
        """
        if not script_sig:
            script_sig = self.script_sig
        tx = b'\x01\x00\x00\x00'  # version
        tx += b'\x01'  # input count
        tx += self.prev_hash[::-1]
        tx += self.index
        script_length = len(script_sig)
        tx += script_length.to_bytes(sizeof(script_length), 'big')
        tx += script_sig
        tx += b'\xff\xff\xff\xff'  # sequence
        tx += b'\x01'  # output count
        tx += self.value
        script_length = len(self.script_pubkey)
        tx += script_length.to_bytes(sizeof(script_length), 'big')
        tx += self.script_pubkey
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
        print(' prev_hash : ', binascii.hexlify(tx[5:37]), ',')
        print(' index : ', binascii.hexlify(tx[37:41]), ',')
        scriptsig_len = tx[41]
        print(' scriptsig_len : ', scriptsig_len, ',')
        print(' scriptsig : ', binascii.hexlify(tx[42:42 + scriptsig_len]), ',')
        print(' sequence', binascii.hexlify(tx[42 + scriptsig_len:42 + scriptsig_len + 4]), ',')
        print(' output_count', tx[42 + scriptsig_len + 4], ',')
        print(' value : ', binascii.hexlify(tx[42 + scriptsig_len + 4:42 + scriptsig_len + 12]), ',')  # aie aie aie
        output_length = tx[42 + scriptsig_len + 13]
        print(' output_length : ', output_length, ',')
        print(' output : ', binascii.hexlify(tx[42 + scriptsig_len + 14:42 + scriptsig_len + 13 + output_length + 1]),
              ',')  # ouie
        print(' locktime : ',
              binascii.hexlify(tx[42 + scriptsig_len + 13 + output_length + 1:42 + scriptsig_len + output_length + 18]),
              ',')
        print('}')

    def get_prev_pubkey(self):
        """
        Fetches the script_pubkey from the ouput spent by this tx.

        :return: The script as bytes.
        """
        txid = hex(int.from_bytes(self.prev_hash, 'big'))[2:]
        index = int.from_bytes(self.index, 'little')
        return binascii.unhexlify(self.network.send('getrawtransaction', [txid, 1])['result']['vout'][index]['scriptPubKey']['hex'])

    def sign(self, key):
        """
        Signs the transaction.

        :param key: The private key with which to sign the transaction.
        :return: The DER-encoded signature.
        """
        # To sign the transaction, we serialize it with the script_sig being the script_pubkey of the output spent.
        tx = binascii.unhexlify(self.serialize(script_sig=self.get_prev_pubkey()))
        # Then we hash this serialized transaction, giving us the payload to sign
        tx_hash = double_sha256(tx + b'\x01\x00\x00\x00', True) # + the hash_code byte
        secexp = int.from_bytes(key, 'big')
        sk = ecdsa.SigningKey.from_secret_exponent(secexp, curve=ecdsa.SECP256k1)
        # The byte appended is the hash_code byte, signifying we will use SIGHASH_ALL
        sig = sk.sign_digest(tx_hash, sigencode=ecdsa.util.sigencode_der_canonize) + b'\x01'
        return sig

    def create_and_sign(self, privkey, pubkey):
        """
        Creates a raw transaction and signs it.

        :param privkey: The key to sign the tx with.
        :param pubkey: The corresponding public key.
        :return: A serialized and signed Bitcoin transaction.
        """
        # self.sign creates the raw tx so we don't have to do it before
        sig = self.sign(privkey)
        # We build the final script_sig
        sig_len = len(sig)
        pub_len = len(pubkey)
        script_sig = sig_len.to_bytes(sizeof(sig_len), 'big') + sig + pub_len.to_bytes(sizeof(pub_len), 'big') + pubkey
        return self.serialize(script_sig=script_sig)

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
        #print('Error message : ')
        #print(s.recv(1000))


if __name__ == '__main__':
    insacoind = Bitcoind('http://127.0.0.1:7332', 'darosior', 'password')
    txid = 0xdba755d0607b15ebc550f9a6ce733494f5d821eae5000f03b7853236827a7983
    index = 0
    script_sig = None
    pk = wif_decode('T3BU3Q7fA5ixgqox2MdeCSyLrE7Lw3y3LRMXup4FfwDDPbcSWy14')
    pub = get_pubkey(pk + b'\x01')
    value = 0
    # Creating an OP_RETURN
    text = 'DOGECOIN THE NEW BITCOIN'.encode('ascii')
    text_len = len(text)
    script_pubkey = Script('OP_RETURN').parse()
    script_pubkey += text_len.to_bytes(1, 'big') # PUSH
    script_pubkey += text

    tx = Transaction(insacoind, txid, index, script_sig, value, script_pubkey)
    tx.create_and_sign(pk, pub)
    response = tx.send()
    if response == True:
        print(tx.id)
    else:
        print(response)