from hashlib import sha256
from .ssz.ssz_typing import pr

ZERO_BYTES32 = b'\x00' * 32


def _hash(x):
    return sha256(x).digest()


# Minimal collection of (key, value) pairs, for fast hash-retrieval, to save on repetitive computation cost.
# Key = the hash input
# Value = the hash output
hash_cache = []


def add_zero_hashes_to_cache():
    zerohashes = [(None, ZERO_BYTES32)]
    for layer in range(1, 32):
        k = zerohashes[layer - 1][1] + zerohashes[layer - 1][1]
        zerohashes.append((k, _hash(k)))
    hash_cache.extend(zerohashes[1:])


def hash(x):
    for (k, h) in hash_cache:
        if x == k:
            return h
    pr("HASHING ", list(x))
    res = _hash(x)
    pr("COMPUTED HASH ", res.hex())
    return res
