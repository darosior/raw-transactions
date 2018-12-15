# coding: utf-8
import os
import uuid
import time
import hashlib
from math import log
import sys
sys.path.append('.')
import secp256k1


# From https://github.com/darosior/bitcoineasy/blob/master/bitcoineasy/utils.py
def sizeof(n):
    """
    get the size in bytes of an integer, https://stackoverflow.com/questions/14329794/get-size-of-integer-in-python

    :param n: the integer to get the size from
    :return: the size in bytes of the int passed as the first parameter.
    """
    if n == 0:
        return 1
    return int(log(n, 256)) + 1


def hash160(bytes, bin=False):
    """
    Returns the ripemd160(sha256(data)), used a lot in Bitcoin.

    :param bin: If set to true, returns bytes.
    """
    rip = hashlib.new('ripemd160')
    rip.update(hashlib.sha256(bytes).digest())
    if bin:
        return rip.digest()  # type : bytes
    else:
        return rip.hexdigest()  # type : str


def double_sha256(bytes, bin=False):
    """
    Returns the sha256(sha256(data)), used a lot in Bitcoin.

    :param bin: If set to true, returns bytes.
    """
    h = hashlib.sha256(bytes)
    if bin:
        return hashlib.sha256(h.digest()).digest()  # type : bytes
    else:
        return hashlib.sha256(h.digest()).hexdigest()  # type : str


def gen_random():
    """
    Generates a random number from a CSRNG.
    """
    seconds = int(time.time())
    entrop1 = double_sha256(seconds.to_bytes(sizeof(seconds), 'big'), True)
    entrop2 = double_sha256(os.urandom(256), True)
    entrop3 = double_sha256(uuid.uuid4().bytes, True)
    return double_sha256(entrop1 + entrop2 + entrop3, True)


def b58encode(payload):
    """
    Takes a number (int or bytes) and returns its base58_encoding.

    :param payload: The data to encode, can be bytes or int
    :return: the number passed as first parameter as a base58 encoded str.
    """
    if isinstance(payload, bytes):
        n = int.from_bytes(payload, 'big')
    elif isinstance(payload, int):
        n = payload
    else:
        raise ValueError('b58encode takes bytes or int')

    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    x = n % 58
    rest = n // 58
    if rest == 0:
        return alphabet[x]
    else:
        return b58encode(rest) + alphabet[x]


def b58decode(string):
    """Takes a base58-encoded number and returns it in base10.
    :param string: the number to base58_decode (as str).
    :return: the number passed as first parameter, base10 encoded.
    """
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    # Populating a dictionary with base58 symbol chart
    dict = {}
    k = 0
    for i in alphabet:
        dict[i] = k
        k += 1
    n = 0  # Result
    pos = 0  # Cf https://www.dcode.fr/conversion-base-n
    for i in string:
        for y in alphabet:
            if i == y:
                n = n * 58 + dict[i]
        pos += 1
    return n


def encode_check(payload):
    """Returns the base58 encoding with a 4-byte checksum.

    :param payload: The data (as bytes) to encode.
    """
    checksum = double_sha256(payload, True)[:4]
    if payload[0] == 0x00:
        # Again, the leading 0 problem which results in nothing during int conversion
        return b58encode(b'\x00') + b58encode(payload[1:] + checksum)
    else:
        return b58encode(payload + checksum)


def decode_check(string):
    """Returns the base58 decoded value, verifying the checksum.

    :param string: The data to decode, as a string.
    """
    number = b58decode(string)
    # Converting to bytes in order to verify the checksum
    payload = number.to_bytes(sizeof(number), 'big')
    if payload and double_sha256(payload[:-4], True)[:4] == payload[-4:]:
        return payload[1:-4]
    else:
        return None


def wif_encode(data, prefix=b'\x80'):
    """
    WIF-encode the data (which would likely be a Bitcoin private key) provided.

    :param data: The bytes to WIF-encode.
    """
    return encode_check(prefix + data) # str


def wif_decode(string):
    """
    WIF-decode the provided string (which would likely be a WIF-encoded Bitcoin private key).
    """
    dec = decode_check(string)
    if string[0] == 'T': # For Bitcoin the condition is if string[0] == 'K' or 'L'
        return dec[:-1] # bytes
    else:
        return dec # bytes


def gen_privkey():
    while True:
        n = int.from_bytes(gen_random(), 'big')
        if 0 < n < 115792089237316195423570985008687907852837564279074904382605163141518161494337:
            return n.to_bytes(sizeof(n), 'big')


def get_pubkey(privkey):
    if len(privkey) == 33:
        (x, y) = secp256k1.privtopub(privkey[:32])
        return b'\x03' + x.to_bytes(sizeof(x), 'big') if y % 2 else b'\x02' + x.to_bytes(sizeof(x), 'big')
    else:
        (x, y) = secp256k1.privtopub(privkey)
        return b'\x04' + x.to_bytes(sizeof(x), 'big') + y.to_bytes(sizeof(y), 'big')


def get_address(pubkey):
    version_byte = b'\x30'
    hash = hash160(pubkey, True)
    return encode_check(version_byte + hash)


def get_keypair():
    privkey = gen_privkey()
    address = get_address(get_pubkey(privkey))
    print('Privkey : ', hex(int.from_bytes(privkey, 'big')))
    print('Address : ', address)


if __name__ == '__main__':
    # get_keypair()
    import binascii
    pk = wif_decode('T9z15bnpSN4hoyDx5JvgirFEYoyNUtcCfmSY7Vm3nUUUCwAuAYpD') + b'\x01'
    print(pk)
    print(binascii.hexlify(pk))
    print(binascii.hexlify(get_pubkey(pk)))