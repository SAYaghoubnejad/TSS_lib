from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

from fastecdsa.encoding.sec1 import SEC1Encoder
from fastecdsa import keys, curve
from fastecdsa.curve import Curve
from fastecdsa.point import Point
from typing import List, Dict
from web3 import Web3

import math
import json
import base64


class Polynomial:
    """
    A class representing a polynomial for use in cryptographic schemes such as
    Shamir's Secret Sharing and Threshold Signature Scheme. This polynomial is 
    defined over a given elliptic curve.

    Attributes:
        threshold (int): The minimum number of points needed to reconstruct
                         the polynomial. (The degree of polynomial + 1)
        curve (Curve): The elliptic curve over which the polynomial is defined.
        coefficients (list[ECPrivateKey]): The list of coefficients as elliptic
                                            curve private keys.

    Methods:
        calculate(x): Evaluates the polynomial at a given point x.
        coef_pub_keys(): Returns the public keys corresponding to the private
                         coefficient keys.
    """

    def __init__(self, threshold: int, curve: Curve, coefficient0: str = None) -> None:
        """
        Initializes the Polynomial instance.

        Parameters:
            threshold (int): The threshold number of shares needed to reconstruct
                             the polynomial. (The degree of polynomial + 1)
            curve (Curve): The elliptic curve over which the polynomial is defined.
            coefficient0 (str, optional): The first coefficient of the polynomial,
                                          represented as a hexadecimal string. If not
                                          provided, a random coefficient will be generated.
        """
        self.threshold: int = threshold
        self.curve: Curve = curve
        self.coefficients: List[int] = []

        # If an initial coefficient is provided, convert it to an integer from a hex string if necessary
        # and add it as the first coefficient of the polynomial.
        if coefficient0 is not None:
            if type(coefficient0) == str:
                coefficient0 = int(coefficient0, 16)
            self.coefficients.append(coefficient0)

        # Generate the remaining random coefficients such that the number of coefficients
        # matches the threshold value.
        for _ in range(threshold - len(self.coefficients)):
            self.coefficients.append(keys.gen_private_key(self.curve))

    def evaluate(self, x: int) -> int:
        """
        Evaluates the polynomial at a given point x.

        Parameters:
            x (int): The x-value at which to evaluate the polynomial.

        Returns:
            ECPrivateKey: The evaluation of the polynomial at point x, represented as
                          an elliptic curve private key.
        """
        result = 0
        # Convert x to an integer if it is provided as a string.
        if type(x) == str:
            x = int(x)

        # Evaluate the polynomial using Horner's method for efficiency.
        for i in range(len(self.coefficients)):
            result += self.coefficients[i] * pow(x, i)

        # Return the result as an elliptic curve private key.
        return result

    def coef_pub_keys(self) -> List[Point]:
        """
        Retrieves the public keys corresponding to the private coefficient keys.

        Returns:
            list[ECPublicKey]: A list of elliptic curve public keys corresponding
                               to the coefficients of the polynomial.
        """
        result = []
        for coefficient in self.coefficients:
            # Convert each private key coefficient to its corresponding public key.
            result.append(keys.get_public_key(coefficient, self.curve))
        return result


ecurve: Curve = curve.secp256k1
N: int = ecurve.q
Half_N: int = ((N >> 1) % N + 1) % N


def mod_inverse(number: int, modulus: int) -> int:
    original_modulus = modulus
    inverse = 1
    intermediate = 0
    number = number % modulus

    if modulus == 1:
        return 0

    while number > 1:
        quotient = number // modulus
        temp = modulus
        modulus = number % modulus
        number = temp
        temp = intermediate
        intermediate = inverse - quotient * intermediate
        inverse = temp

    if inverse < 0:
        inverse += original_modulus

    return inverse


def pub_to_addr(public_key: Point) -> str:
    pub_key_hex = str(hex(public_key.x))[
        2:] + str(hex(public_key.y))[2:]
    pub_hash = Web3.keccak(int(pub_key_hex, 16))
    return Web3.to_checksum_address('0x'+str(pub_hash.hex())[-40:])


def pub_to_code(public_key: Point) -> int:
    comp_pub = SEC1Encoder.encode_public_key(public_key, True)
    return int(comp_pub.hex(), 16)


def code_to_pub(key: int) -> Point:
    key_byte = bytes.fromhex(hex(key).replace('x', ''))
    return SEC1Encoder.decode_public_key(key_byte, ecurve)


def private_to_point(private_key: int) -> Point:
    return keys.get_public_key(private_key, ecurve)


def pub_compress(public_key: Point) -> Dict:
    coded = SEC1Encoder.encode_public_key(public_key, True)
    x = '0x' + coded.hex()[2:]
    y = int(coded.hex()[1]) - 2
    return {'x': x, 'y_parity': y}


def pub_decompress(pub_dict: Dict) -> Point:
    x = pub_dict['x']
    y = pub_dict['y_parity'] + 2
    coded = '0' + str(y) + x[2:]
    publicKey = SEC1Encoder.decode_public_key(
        bytes.fromhex(coded), ecurve)
    return publicKey


def calc_poly_point(polynomial: List[Point], x: int) -> Point:
    x = int(x)
    coefs = []
    for i in range(len(polynomial)):
        coefs.append(pow(x, i) % N)
    result = coefs[0] * polynomial[0]
    for i in range(1, len(polynomial)):
        result = result + coefs[i] * polynomial[i]
    return result


def generate_random_private() -> int:
    return keys.gen_private_key(ecurve)


def langrange_coef(index: int, threshold: int, shares: List[Dict], x: int) -> int:
    x_j = int(shares[index]['id'])
    nums = []
    denums = []
    for k in list(filter(lambda i: i != index, range(0, threshold))):
        x_k = int(shares[k]['id'])
        nums.append(x - x_k)
        denums.append(x_j - x_k)
    num = math.prod(nums)
    denum = math.prod(denums)
    return mod_inverse(denum, N) * num


def reconstruct_share(shares: List[Dict], threshold: int, x: int) -> int:
    assert len(shares) == threshold, 'Number of shares must be t.'
    sum = 0
    for j in range(threshold):
        coef = langrange_coef(j, threshold, shares, x)
        key = shares[j]['key']
        sum = (sum + (key * coef % N)) % N
    return sum % N


def schnorr_hash(public_key: Point, message: int) -> str:
    address = pub_to_addr(public_key)
    addressBuff = str(address)[2:]
    msgBuff = str(hex(message))[2:]
    totalBuff = addressBuff + msgBuff
    return Web3.keccak(int(totalBuff, 16))


def schnorr_sign(shared_private_key: int, nounce_private: int, nounce_public: Point, message: int) -> Dict[str, int]:
    e = int.from_bytes(schnorr_hash(nounce_public, message), 'big')
    s = (nounce_private - e * shared_private_key) % N
    return {'s': s, 'e': e}


def stringify_signature(signature: Dict[str, int]) -> str:
    S = f'{hex(signature["s"])[2:]:0>64}'
    E = f'{hex(signature["e"])[2:]:0>64}'
    return '0x' + E + S


def split_signature(string_signature: str) -> Dict[str, int]:
    raw_bytes = string_signature[2:]
    assert len(raw_bytes) == 128, 'Invalid schnorr signature string'
    e = '0x' + raw_bytes[0:64]
    s = '0x' + raw_bytes[64:]
    return {'s': int(s, 16), 'e': int(e, 16)}


def schnorr_verify(public_key: Point, message: str, signature: str) -> bool:
    if type(signature) == str:
        signature = split_signature(signature)
    if type(message) != int:
        message = int(message)
    assert signature['s'] < N, 'Signature must be reduced modulo N'
    r_v = (signature['s'] * ecurve.G) + (signature['e'] * public_key)
    e_v = schnorr_hash(r_v, message)
    return int.from_bytes(e_v, 'big') == signature['e']


def schnorr_aggregate_signatures(threshold: int, signatures: List[Dict[str, int]], party: List[str]) -> Dict[str, int]:
    assert len(signatures) >= threshold, 'At least t signatures are needed'
    aggregated_signature = 0

    for j in range(threshold):
        coef = langrange_coef(
            j, threshold, [{'id': i} for i in party], 0)
        aggregated_signature += signatures[j]['s'] * coef
    s = aggregated_signature % N
    e = signatures[0]['e']
    return {'s': s, 'e': e}

# To Remove


def complaint_sign(private_key: int, nonce: int, hash: int):
    return (nonce + private_key * hash) % N

# What is this for?


def complaint_verify(public_complaintant: Point, public_malicious: Point, encryption_key: Point, proof, hash: int):
    public_nonce = proof['public_nonce']
    public_commitment = proof['commitment']
    signature = proof['signature']

    point1 = public_nonce + (hash * public_complaintant)
    point2 = signature * ecurve.G
    verification1 = (point1 == point2)

    point1 = public_commitment + (hash * encryption_key)
    point2 = signature * public_malicious
    verification2 = (point1 == point2)

    return verification1 and verification2


def generate_hkdf_key(key: int) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32,
                salt=b'', info=b'', backend=default_backend())
    return hkdf.derive(bytes.fromhex(str(key)))


def encrypt(data: str, key: bytes) -> str:
    if type(data) != str:
        data = json.dumps(data)
    key = base64.b64encode(key)
    fernet = Fernet(key)
    return fernet.encrypt(data.encode()).decode(encoding='utf-8')


def decrypt(data: str, key: bytes) -> str:
    data = bytes(data, encoding='utf-8')
    key = base64.b64encode(key)
    fernet = Fernet(key)
    return fernet.decrypt(data).decode()
