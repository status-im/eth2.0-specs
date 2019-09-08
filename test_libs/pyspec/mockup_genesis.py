from eth2spec.phase0 import spec
from eth2spec.utils.bls import bls_sign
from eth2spec.utils.merkle_minimal import calc_merkle_tree_from_leaves, get_merkle_proof
from eth2spec.utils.hash_function import hash
from py_ecc.bls import privtopub
from typing import List, Tuple
from eth_utils import (
    encode_hex,
    int_to_big_endian,
)

from eth2spec.utils.ssz.ssz_typing import (
    enable_printing
)

CURVE_ORDER = 52435875175126190479447740508185965837690552500527637822603658699938581184513


def int_to_hex(n: int, byte_length: int = None) -> str:
    byte_value = int_to_big_endian(n)
    if byte_length:
        byte_value = byte_value.rjust(byte_length, b'\x00')
    return encode_hex(byte_value)


def generate_validator_keypairs(N: int) -> List[Tuple[int, bytes]]:
    keypairs = []
    for index in range(N):
        privkey = int.from_bytes(
            hash(index.to_bytes(length=32, byteorder='little')),
            byteorder='little',
        ) % CURVE_ORDER
        keypairs.append((privkey, privtopub(privkey)))
    return keypairs


eth1_root = b"\x42" * 32
timestamp = 1567816020
validator_count = 16

keys = generate_validator_keypairs(validator_count)
deposit_datas = [
    spec.DepositData(
        pubkey=pubkey,
        withdrawal_credentials=spec.BLS_WITHDRAWAL_PREFIX + spec.hash(pubkey)[1:],
        amount=spec.MAX_EFFECTIVE_BALANCE,
    )
    for (_, pubkey) in keys
]

for i in range(len(deposit_datas)):
    d = deposit_datas[i]
    (privkey, _) = keys[i]
    d.signature = bls_sign(message_hash=spec.signing_root(d),
                                privkey=privkey,
                                domain=spec.compute_domain(spec.DOMAIN_DEPOSIT))

    print("privkey " + int_to_hex(privkey))
    print("signing root " + spec.signing_root(d).hex())
    print("domain " + str(spec.compute_domain(spec.DOMAIN_DEPOSIT)))
    print("deposit signature " + d.signature.hex())

deposits = []
for i in range(len(deposit_datas)):
    tree = calc_merkle_tree_from_leaves(tuple([d.hash_tree_root() for d in deposit_datas[:i+1]]))
    proof = list(get_merkle_proof(tree, item_index=i)) + [(i + 1).to_bytes(32, 'little')]
    data = deposit_datas[i]
    deposits.append(spec.Deposit(
        proof=proof,
        data=data,
    ))

    root = spec.hash_tree_root(spec.List[spec.DepositData, 2**spec.DEPOSIT_CONTRACT_TREE_DEPTH](*deposit_datas[:i+1]))
    # check validity of merkle proof
    leaf = data.hash_tree_root()
    assert spec.is_valid_merkle_branch(leaf, proof, spec.DEPOSIT_CONTRACT_TREE_DEPTH + 1, i, root)

genesis_state = spec.initialize_beacon_state_from_eth1(eth1_block_hash=eth1_root, eth1_timestamp=timestamp, deposits=deposits)

