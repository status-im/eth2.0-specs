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

enable_printing(True)
b = spec.BeaconBlockBody()
print(b.hash_tree_root().hex())

