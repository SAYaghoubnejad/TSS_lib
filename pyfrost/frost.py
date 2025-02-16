from fastecdsa import keys
from hashlib import sha256

from .btc_utils import (
    btc_challenge,
    calculate_tweaked,
    btc_generate_signature_share,
    btc_verify_single_sign,
    btc_verify_group_signature,
)
from .crypto_utils import (
    pub_to_code,
    ecurve,
    schnorr_sign,
    stringify_signature,
    Polynomial,
    schnorr_verify,
    code_to_pub,
    generate_hkdf_key,
    encrypt,
    decrypt,
    calc_poly_point,
    pub_compress,
    pub_to_addr,
    lagrange_coef,
    taproot_tweak_pubkey,
    generate_random_private,
    N,
    pub_decompress,
    complaint_sign,
)
from typing import List, Dict, Tuple
import json
from fastecdsa.point import Point

from .eth_utils import (
    eth_challenge,
    eth_generate_signature_share,
    eth_verify_single_sign,
    eth_verify_group_sign,
)


class KeyGen:
    def __init__(
        self,
        dkg_id: str,
        threshold: int,
        node_id: str,
        partners: List[str],
        coefficient0: str = None,
        key_type: str = "ETH",
    ) -> None:
        self.threshold: int = threshold
        self.dkg_id: str = dkg_id
        self.node_id: str = node_id
        self.partners: List[str] = partners
        self.coefficient0 = coefficient0
        self.malicious: List = []
        self.key_type = key_type
        self.status = "STARTED"

    def round1(self) -> List[Dict]:
        self.secret_key, public_key = keys.gen_keypair(ecurve)
        secret_nonce, public_nonce = keys.gen_keypair(ecurve)
        secret_pop_hash = sha256(
            self.node_id.encode()
            + self.dkg_id.encode()
            + pub_to_code(public_key).to_bytes(33, "big")
            + pub_to_code(public_nonce).to_bytes(33, "big")
        ).digest()

        secret_pop_sign = schnorr_sign(
            self.secret_key,
            secret_nonce,
            public_nonce,
            int.from_bytes(secret_pop_hash, "big"),
        )

        secret_signature = {
            "nonce": pub_to_code(public_nonce),
            "signature": stringify_signature(secret_pop_sign),
        }

        # Generate DKG polynomial
        self.fx = Polynomial(self.threshold, ecurve, self.coefficient0)
        self.public_fx = self.fx.coef_pub_keys()
        coef0_nonce, public_coef0_nonce = keys.gen_keypair(ecurve)
        coef0_pop_hash = sha256(
            self.node_id.encode()
            + self.dkg_id.encode()
            + pub_to_code(self.public_fx[0]).to_bytes(33, "big")
            + pub_to_code(public_coef0_nonce).to_bytes(33, "big")
        ).digest()
        coef0_pop_sign = schnorr_sign(
            self.fx.coefficients[0],
            coef0_nonce,
            public_coef0_nonce,
            int.from_bytes(coef0_pop_hash, "big"),
        )

        self.coef0_signature = {
            "nonce": pub_to_code(public_coef0_nonce),
            "signature": stringify_signature(coef0_pop_sign),
        }

        self.status = "ROUND1"
        return {
            "sender_id": self.node_id,
            "public_fx": [pub_to_code(s) for s in self.public_fx],
            "coefficient0_signature": self.coef0_signature,
            "public_key": pub_to_code(public_key),
            "secret_signature": secret_signature,
            "key_type": self.key_type,
        }

    def round2(self, round1_broadcasted_data) -> List[Dict]:
        self.round1_broadcasted_data = round1_broadcasted_data
        fx: Polynomial = self.fx
        self.partners_public_keys = {}
        secret_key = self.secret_key
        for data in round1_broadcasted_data:
            sender_id = data["sender_id"]
            if sender_id == self.node_id:
                continue
            sender_public_fx = data["public_fx"]
            sender_coef0_nonce = data["coefficient0_signature"]["nonce"]
            sender_coef0_signature = data["coefficient0_signature"]["signature"]
            coef0_pop_hash = sha256(
                sender_id.encode()
                + self.dkg_id.encode()
                + sender_public_fx[0].to_bytes(33, "big")
                + sender_coef0_nonce.to_bytes(33, "big")
            ).digest()
            coef0_verification = schnorr_verify(
                code_to_pub(sender_public_fx[0]),
                int.from_bytes(coef0_pop_hash, "big"),
                sender_coef0_signature,
            )
            sender_public_key = data["public_key"]
            sender_public_nonce = data["secret_signature"]["nonce"]
            sender_secret_signature = data["secret_signature"]["signature"]

            secret_pop_hash = sha256(
                sender_id.encode()
                + self.dkg_id.encode()
                + sender_public_key.to_bytes(33, "big")
                + sender_public_nonce.to_bytes(33, "big")
            ).digest()

            secret_verification = schnorr_verify(
                code_to_pub(sender_public_key),
                int.from_bytes(secret_pop_hash, "big"),
                sender_secret_signature,
            )

            # TODO: add these checking in gateway in addition to nodes
            if not secret_verification or not coef0_verification:
                # TODO: how to handle complaint
                self.malicious.append({"id": sender_id, "complaint": data})
            self.partners_public_keys[sender_id] = sender_public_key
        qualified = self.partners
        for node in self.malicious:
            try:
                qualified.remove(node["id"])
            except:
                # TODO: Raise error or something
                pass
        result_data = []
        for id in qualified:
            encryption_joint_key = pub_to_code(
                secret_key * code_to_pub(self.partners_public_keys[id])
            )
            encryption_key = generate_hkdf_key(encryption_joint_key)
            id_as_int = int(id)
            data = {
                "receiver_id": id,
                "sender_id": self.node_id,
                "data": encrypt(
                    {"receiver_id": id, "f": fx.evaluate(id_as_int)}, encryption_key
                ),
            }
            result_data.append(data)
        self.status = "ROUND2"
        return result_data

    def round3(self, round2_encrypted_data) -> Dict:
        secret_key = self.secret_key
        partners_public_keys = self.partners_public_keys
        round2_data = []
        complaints = []
        for message in round2_encrypted_data:
            sender_id = message["sender_id"]
            receiver_id = message["receiver_id"]
            encrypted_data = message["data"]
            encryption_joint_key = pub_to_code(
                secret_key * code_to_pub(partners_public_keys[sender_id])
            )
            encryption_key = generate_hkdf_key(encryption_joint_key)

            assert receiver_id == self.node_id, "ERROR: receiver_id does not match."
            data = json.loads(decrypt(encrypted_data, encryption_key))
            round2_data.append(data)
            for round1_data in self.round1_broadcasted_data:
                if round1_data["sender_id"] == sender_id:
                    public_fx = round1_data["public_fx"]

                    point1 = calc_poly_point(
                        list(map(code_to_pub, public_fx)), int(self.node_id)
                    )

                    point2 = data["f"] * ecurve.G

                    if point1 != point2:
                        complaints.append(
                            self.complain(
                                secret_key, sender_id, partners_public_keys[sender_id]
                            )
                        )

        if len(complaints) > 0:
            self.status = "COMPLAINT"
            return {"status": "COMPLAINT", "data": complaints}

        fx: Polynomial = self.fx
        my_fragment = fx.evaluate(int(self.node_id))
        share_fragments = [my_fragment]
        for data in round2_data:
            share_fragments.append(data["f"])

        public_fx = [self.public_fx[0]]
        for data in self.round1_broadcasted_data:
            if data["sender_id"] in self.partners:
                public_fx.append(code_to_pub(data["public_fx"][0]))

        dkg_public_key = public_fx[0]
        for i in range(1, len(public_fx)):
            dkg_public_key = dkg_public_key + public_fx[i]

        share = sum(share_fragments)
        self.dkg_key_pair = {
            "share": share,
            "dkg_public_key": pub_to_code(dkg_public_key),
        }

        result = {
            "data": {
                "dkg_public_key": pub_to_code(dkg_public_key),
                "public_share": pub_to_code(keys.get_public_key(share, ecurve)),
            },
            "dkg_key_pair": self.dkg_key_pair,
            "key_type": self.key_type,
            "status": "SUCCESSFUL",
        }
        self.status = "COMPLETED"
        return result


class Key:
    def __init__(self, dkg_key: Dict, node_id: str) -> None:
        self.dkg_key_pair = dkg_key
        self.dkg_key_pair["dkg_public_key"] = code_to_pub(
            self.dkg_key_pair["dkg_public_key"]
        )
        self.node_id = node_id
        self.key_type = self.dkg_key_pair["key_type"]

    def sign(self, nonces_dict: Dict, message: str, nonce_pair: Dict) -> Dict:
        assert isinstance(message, str), "Message should be of string type."

        signature = single_sign(
            int(self.node_id),
            self.dkg_key_pair["share"],
            nonce_pair["nonce_d"],
            nonce_pair["nonce_e"],
            message,
            nonces_dict,
            pub_to_code(self.dkg_key_pair["dkg_public_key"]),
            self.key_type,
        )
        return signature


def single_sign(
    id: str,
    share: int,
    nonce_d: int,
    nonce_e: int,
    message: str,
    nonces_dict: Dict[str, Dict[str, int]],
    group_key: Point,
    key_type: str = "ETH",
) -> Dict[str, int]:
    # Prepare bytes and list
    message_bytes = message.encode("utf-8")
    nonces_list = list(nonces_dict.values())
    nonces_hash = sha256(json.dumps(nonces_list).encode()).digest()

    # Aggregate public nonces and find the relevant row and index
    aggregated_public_nonce = None
    my_row, index = 0, 0
    for idx, nonce in enumerate(nonces_list):
        # Convert codes to public nonces and validate
        nonce_d_public = code_to_pub(nonce["public_nonce_d"])
        nonce_e_public = code_to_pub(nonce["public_nonce_e"])
        for nonce_public, nonce_name in [(nonce_d_public, "D"), (nonce_e_public, "E")]:
            assert ecurve.is_point_on_curve(
                (nonce_public.x, nonce_public.y)
            ), f'Nonce {nonce_name} from Node {nonce["id"]} Not on Curve'

        # Compute public nonce
        row = sha256(
            nonce["id"].to_bytes(32, "big") + message_bytes + nonces_hash
        ).digest()
        public_nonce = nonce_d_public + (int.from_bytes(row, "big") * nonce_e_public)
        aggregated_public_nonce = (
            public_nonce
            if aggregated_public_nonce is None
            else aggregated_public_nonce + public_nonce
        )

        # Check for the current party's nonce
        if id == nonce["id"]:
            my_row, index = row, idx

    # Calculate challenge
    group_key_pub = pub_compress(code_to_pub(group_key))
    if key_type == "ETH":
        challenge = eth_challenge(group_key_pub, message, aggregated_public_nonce)
        coef = lagrange_coef(index, len(nonces_list), nonces_list, 0)
        signature_share = eth_generate_signature_share(
            share, coef, challenge, nonce_d, nonce_e, my_row
        )
    elif key_type == "BTC":
        share, tweaked_pubkey = calculate_tweaked(share, group_key_pub)
        challenge = btc_challenge(tweaked_pubkey, message, aggregated_public_nonce)
        coef = lagrange_coef(index, len(nonces_list), nonces_list, 0) % ecurve.q
        signature_share = btc_generate_signature_share(
            share,
            coef,
            challenge,
            aggregated_public_nonce,
            nonce_d,
            nonce_e,
            my_row,
        )
    return {
        "id": id,
        "signature": signature_share,
        "public_key": pub_to_code(keys.get_public_key(share, ecurve)),
        "aggregated_public_nonce": pub_to_code(aggregated_public_nonce),
        "key_type": key_type,
    }


def create_nonces(
    node_id: int, number_of_nonces: int = 10
) -> Tuple[List[Dict], List[Dict]]:
    nonce_publics, nonce_privates = [], []

    for _ in range(number_of_nonces):
        # Generate nonce pairs (private and public)
        nonce_d, nonce_e = generate_random_private(), generate_random_private()
        public_nonce_d = pub_to_code(keys.get_public_key(nonce_d, ecurve))
        public_nonce_e = pub_to_code(keys.get_public_key(nonce_e, ecurve))

        # Append private nonce pairs
        nonce_privates.append(
            {
                "nonce_d_pair": {public_nonce_d: nonce_d},
                "nonce_e_pair": {public_nonce_e: nonce_e},
            }
        )

        # Append public nonce pairs
        nonce_publics.append(
            {
                "id": node_id,
                "public_nonce_d": public_nonce_d,
                "public_nonce_e": public_nonce_e,
            }
        )

    return nonce_publics, nonce_privates


def verify_single_signature(signature_data: Dict) -> bool:
    # Prepare hashes and list
    nonces_dict = list(signature_data["nonces_dict"].values())
    nonces_hash = sha256(json.dumps(nonces_dict).encode()).digest()
    message_bytes = signature_data["message"].encode("utf-8")

    # Find the relevant nonce and calculate the public nonce
    public_nonce, index = None, 0
    for idx, nonce in enumerate(nonces_dict):
        if nonce["id"] == signature_data["id"]:
            nonce_d_public = code_to_pub(nonce["public_nonce_d"])
            nonce_e_public = code_to_pub(nonce["public_nonce_e"])
            row = sha256(
                nonce["id"].to_bytes(32, "big") + message_bytes + nonces_hash
            ).digest()
            public_nonce = nonce_d_public + (
                int.from_bytes(row, "big") * nonce_e_public
            )
            index = idx
            break

    # Calculate challenge
    group_key_pub = pub_compress(code_to_pub(signature_data["group_key"]))
    if signature_data["key_type"] == "ETH":
        challenge = eth_challenge(
            group_key_pub,
            signature_data["message"],
            signature_data["aggregated_public_nonce"],
        )
        coef = lagrange_coef(index, len(nonces_dict), nonces_dict, 0)
        return eth_verify_single_sign(coef, challenge, public_nonce, signature_data)

    elif signature_data["key_type"] == "BTC":
        tweaked_pubkey_has_even_y, tweaked_pubkey = taproot_tweak_pubkey(
            group_key_pub, b""
        )
        challenge = btc_challenge(
            tweaked_pubkey,
            signature_data["message"],
            signature_data["aggregated_public_nonce"],
        )
        coef = lagrange_coef(index, len(nonces_dict), nonces_dict, 0) % ecurve.q
        return btc_verify_single_sign(coef, challenge, public_nonce, signature_data)


def aggregate_nonce(message: str, nonces_dict: Dict[str, Dict[str, int]]) -> Point:
    # Convert nonces to a list and get bytes of the message
    nonces_list = list(nonces_dict.values())
    nonces_hash = sha256(json.dumps(nonces_list).encode()).digest()
    message_bytes = message.encode("utf-8")

    # Initialize aggregated public nonce
    aggregated_public_nonce = None

    for nonce in nonces_list:
        # Convert codes to public nonces
        nonce_d_public = code_to_pub(nonce["public_nonce_d"])
        nonce_e_public = code_to_pub(nonce["public_nonce_e"])

        # Calculate row hash
        row_hash = sha256(
            nonce["id"].to_bytes(32, "big") + message_bytes + nonces_hash
        ).digest()

        # Calculate public nonce
        public_nonce = nonce_d_public + (
            int.from_bytes(row_hash, "big") * nonce_e_public
        )

        # Aggregate public nonces
        if aggregated_public_nonce is None:
            aggregated_public_nonce = public_nonce
        else:
            aggregated_public_nonce += public_nonce
    return aggregated_public_nonce


def aggregate_signatures(
    message: str,
    single_signatures: List[Dict[str, int]],
    aggregated_public_nonce: Point,
    group_key: int,
    key_type: str = "ETH",
) -> Dict:
    # Aggregate signatures
    aggregated_signature = sum(sign["signature"] for sign in single_signatures) % N

    return {
        "nonce": pub_to_addr(aggregated_public_nonce),
        "public_nonce": pub_compress(aggregated_public_nonce),
        "public_key": pub_compress(code_to_pub(group_key)),
        "signature": aggregated_signature,
        "message": message,
        "key_type": key_type,
    }


def verify_group_signature(aggregated_signature: Dict) -> bool:
    group_pub_key = aggregated_signature["public_key"]
    message = aggregated_signature["message"]
    # Calculate the challenge
    if aggregated_signature["key_type"] == "ETH":
        return eth_verify_group_sign(group_pub_key, message, aggregated_signature)

    elif aggregated_signature["key_type"] == "BTC":
        return btc_verify_group_signature(aggregated_signature)


# TODO : exclude complaint

# =======================================================================================
# ================================== Private Functions ==================================
# =======================================================================================


def __create_complaint(
    node_id: str, secret_key: int, partner_id: str, partner_public: Point
) -> Dict:
    # Calculate joint encryption key and public key
    encryption_joint_key = pub_to_code(secret_key * partner_public)
    public_key = keys.get_public_key(secret_key, ecurve)

    # Generate keypair
    random_nonce, public_nonce = keys.gen_keypair()

    # Calculate nonce
    nonce = random_nonce * partner_public

    # Create the hash for the Proof of Complaint (PoC)
    complaint_pop_hash = sha256(
        pub_to_code(public_key).to_bytes(33, "big"),
        pub_to_code(partner_public).to_bytes(33, "big"),
        encryption_joint_key.to_bytes(33, "big"),
        pub_to_code(public_nonce).to_bytes(33, "big"),
        pub_to_code(nonce).to_bytes(33, "big"),
    ).digest()

    # Sign the PoC
    complaint_pop_sign = complaint_sign(
        secret_key, random_nonce, int.from_bytes(complaint_pop_hash, "big")
    )

    # Assemble the Proof of Complaint
    complaint_pop = {
        "public_nonce": pub_to_code(public_nonce),
        "nonce": pub_to_code(nonce),
        "signature": complaint_pop_sign,
    }

    # Return the complete complaint structure
    return {
        "complaintant": node_id,
        "malicious": partner_id,
        "encryption_key": encryption_joint_key,
        "proof": complaint_pop,
    }
