"""Optional EVM testnet anchoring; invoked explicitly by the operator, never by scans."""
import hashlib
import json
import os
from urllib.parse import urlsplit


def anchor_cbom(cbom, expected_chain_id):
    from web3 import Web3
    rpc = os.environ.get('ECDAT_RPC_URL', '')
    if urlsplit(rpc).scheme != 'https':
        raise ValueError('Set ECDAT_RPC_URL to your HTTPS testnet RPC endpoint.')
    web3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={'timeout': 20}))
    if web3.eth.chain_id != expected_chain_id:
        raise ValueError('RPC chain ID does not match the explicitly selected chain.')
    if expected_chain_id not in {80002, 11155111}:
        raise ValueError('Only Polygon Amoy and Ethereum Sepolia testnets are enabled.')
    account = web3.eth.account.from_key(os.environ['ECDAT_ANCHOR_PRIVATE_KEY'])
    digest = hashlib.sha256(json.dumps(cbom, sort_keys=True).encode()).hexdigest()
    # A transaction to the signer records the digest in public transaction calldata.
    tx = {'chainId': expected_chain_id, 'nonce': web3.eth.get_transaction_count(account.address, 'pending'),
          'to': account.address, 'value': 0, 'data': Web3.to_bytes(hexstr=digest), 'gas': 24000,
          'gasPrice': web3.eth.gas_price}
    signed = account.sign_transaction(tx)
    transaction_hash = web3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = web3.eth.wait_for_transaction_receipt(transaction_hash, timeout=120)
    if receipt.status != 1:
        raise ValueError('Anchor transaction failed.')
    return {'chain_id': expected_chain_id, 'transaction_hash': transaction_hash.hex(), 'cbom_sha256': digest,
            'block_number': receipt.blockNumber, 'signer': account.address}


def verify_anchor(cbom, receipt):
    from web3 import Web3
    web3 = Web3(Web3.HTTPProvider(os.environ['ECDAT_RPC_URL'], request_kwargs={'timeout': 20}))
    if web3.eth.chain_id != receipt['chain_id']:
        return False
    tx = web3.eth.get_transaction(receipt['transaction_hash'])
    mined = web3.eth.get_transaction_receipt(receipt['transaction_hash'])
    digest = hashlib.sha256(json.dumps(cbom, sort_keys=True).encode()).digest()
    return mined.status == 1 and bytes(tx['input']) == digest and tx['from'].lower() == receipt['signer'].lower()
