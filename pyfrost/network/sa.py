from typing import List, Dict
from fastecdsa.encoding.sec1 import SEC1Encoder
from fastecdsa import curve
from .abstract import NodesInfo
from .dkg_handler import post_request
from ..crypto_utils import get_frost;
import pyfrost
import logging
import json
import uuid
import asyncio
import aiohttp


async def sign_request(url: str, dkg_key: Dict, data: Dict, timeout: int = 10):
	async with aiohttp.ClientSession() as session:
		async with session.post(url, json=data, timeout=timeout) as response:
			try:
				result = await response.json()
				if result["status"] != "SUCCESSFUL":
					return result
				key_type = dkg_key["key_type"]
				sign = result["signature_data"]
				msg = result["hash"]
				node_id = data["node_id"]
				nonces_commitments = data["nonces_dict"]
				pubkey_package = dkg_key["pubkey_data"]["pubkey_package"]
				
				signing_package = get_frost(key_type).signing_package_new(
					signing_commitments= nonces_commitments, 
					msg= msg
				);
				verified = get_frost(key_type).verify_share(
					identifier= node_id, 
					verifying_share= pubkey_package["verifying_shares"][node_id], 
					signature_share= sign, 
					signing_package= signing_package, 
					verifying_key= pubkey_package["verifying_key"]
				)
				
				if not verified:
					result["status"] = "MALICIOUS"
				return result
			except asyncio.TimeoutError:
				return {
					"status": "TIMEOUT",
					"error": "Communication timed out",
				}
			except Exception as e:
				logging.error(
					f"An exception occurred: {type(e).__name__}: {e}", exc_info=True
				)
				return {
					"status": "ERROR",
					"error": f"An exception occurred: {type(e).__name__}: {e}",
				}


class SA:
	def __init__(self, nodes_info: NodesInfo, default_timeout: int = 200) -> None:
		self.nodes_info: NodesInfo = nodes_info
		self.default_timeout = default_timeout

	async def request_nonces(self, party: List, dkg_pub_key: str, number_of_nonces: int = 10):
		call_method = self.nodes_info.prefix + "/v1/generate-nonces"
		request_data = {
			"dkg_pub_key": dkg_pub_key,
			"number_of_nonces": number_of_nonces,
		}
		node_info = [self.nodes_info.lookup_node(node_id) for node_id in party]
		urls = [
			f'http://{node["host"]}:{node["port"]}' + call_method for node in node_info
		]
		request_tasks = [
			post_request(url, request_data, self.default_timeout) for url in urls
		]
		responses = await asyncio.gather(*request_tasks)
		nonces_response = dict(zip(party, responses))

		logging.debug(
			f"Nonces dictionary response: \n{json.dumps(nonces_response, indent=4)}"
		)
		return nonces_response

	async def request_signature(
		self, dkg_key: Dict, nonces_dict: Dict, sa_data: Dict, sign_party: List
	) -> Dict:
		key_type = dkg_key["key_type"]
		call_method = self.nodes_info.prefix + "/v1/sign"
		if not set(sign_party).issubset(set(dkg_key["party"])):
			response = {"result": "FAILED", "signatures": None}
			return response
		request_id = str(uuid.uuid4())
		node_info = [self.nodes_info.lookup_node(node_id) for node_id in sign_party]
		urls = [
			f'http://{node["host"]}:{node["port"]}' + call_method for node in node_info
		]
		# collect signature shares
		request_tasks = [
			sign_request(
				url, dkg_key, 
				{
					"node_id": sign_party[i],
					"key_type": key_type,
					"request_id": request_id,
					"dkg_public_key": dkg_key["public_key"],
					"nonces_dict": nonces_dict,
					"data": sa_data,
				}, 
				self.default_timeout
			)
			for i, url in enumerate(urls)
		]
		responses = await asyncio.gather(*request_tasks)
		signatures = dict(zip(sign_party, responses))

		logging.debug(
			f"Signatures dictionary response: \n{json.dumps(signatures, indent=4)}"
		)

		# check malicious behaviour
		response = {"result": "SUCCESSFUL", "signatures": None}
		for data in signatures.values():
			if not data["status"] == "SUCCESSFUL":
				response["result"] = "FAILED"
				break

		if response["result"] == "FAILED":
			response = {"result": "FAILED", "signatures": signatures}
			logging.info(f"Signature response: {json.dumps(response, indent=4)}")
			return response

		# =============== aggregate final signature ===============

		commitments_map = dict(zip(
			sign_party,
			[nonces_dict[id] for id in sign_party]
		))
		signature_shares = dict(zip(
			sign_party,
			[signatures[id]["signature_data"] for id in sign_party]
		))
		hash = signatures[sign_party[0]]["hash"]

		signing_package = get_frost(key_type).signing_package_new(
			signing_commitments= commitments_map, 
			msg= hash
		);
		aggregated_sign = get_frost(key_type).aggregate(
			signing_package= signing_package,
			signature_shares= signature_shares,
			pubkey_package= dkg_key["pubkey_data"]["pubkey_package"]
		)

		aggregated_result = {}

		if get_frost(key_type).verify_group_signature(aggregated_sign, hash, dkg_key["pubkey_data"]["pubkey_package"]):
			aggregated_result["result"] = "SUCCESSFUL"
			aggregated_result["message_hash"] = hash
			aggregated_result["signature"] = aggregated_sign
			aggregated_result["request_id"] = request_id
			aggregated_result["sa_data"] = sa_data
			logging.info(f'Aggregated sign result: {aggregated_result["result"]}')
		else:
			aggregated_result["result"] = "FAILED"
			aggregated_result["signature_data"] = list(signatures.values())
		return aggregated_result
