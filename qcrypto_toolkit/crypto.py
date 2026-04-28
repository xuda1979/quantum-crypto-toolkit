from __future__ import annotations

import hashlib
import hmac
import math
import secrets
from collections.abc import Iterable


def random_bytes(length: int) -> bytes:
    if length < 0:
        raise ValueError("length must be non-negative")
    return secrets.token_bytes(length)


def hkdf_extract(salt: bytes, ikm: bytes, hash_name: str = "sha256") -> bytes:
    return hmac.new(salt, ikm, hash_name).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int, hash_name: str = "sha256") -> bytes:
    if length < 0:
        raise ValueError("length must be non-negative")
    hash_len = hashlib.new(hash_name).digest_size
    if length > 255 * hash_len:
        raise ValueError("HKDF output length too large")
    blocks = bytearray()
    previous = b""
    for counter in range(1, math.ceil(length / hash_len) + 1):
        previous = hmac.new(prk, previous + info + bytes([counter]), hash_name).digest()
        blocks.extend(previous)
    return bytes(blocks[:length])


def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int, hash_name: str = "sha256") -> bytes:
    return hkdf_expand(hkdf_extract(salt, ikm, hash_name), info, length, hash_name)


def shake256(parts: Iterable[bytes], length: int) -> bytes:
    if length < 0:
        raise ValueError("length must be non-negative")
    xof = hashlib.shake_256()
    for part in parts:
        xof.update(part)
    return xof.digest(length)


def xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("inputs must have identical length")
    return bytes(a ^ b for a, b in zip(left, right))


def mac(key: bytes, *parts: bytes, length: int = 16) -> bytes:
    tag = hmac.new(key, digestmod=hashlib.sha256)
    for part in parts:
        tag.update(part)
    return tag.digest()[:length]


def constant_time_equal(left: bytes, right: bytes) -> bool:
    return hmac.compare_digest(left, right)
