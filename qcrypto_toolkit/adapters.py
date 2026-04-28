from __future__ import annotations

from dataclasses import dataclass

from .crypto import constant_time_equal, mac, random_bytes, shake256
from .models import AlgorithmDescriptor, EncapsulationResult, KeyPair, SignatureResult
from .registry import DEFAULT_REGISTRY


class DemoKEMAdapter:
    """KEM-shaped deterministic adapter for catalog algorithms.

    It preserves sizes and the keygen/encaps/decaps data flow. It is not an
    implementation of the named algorithm.
    """

    def keygen(self, algorithm_name: str) -> KeyPair:
        descriptor = DEFAULT_REGISTRY.get(algorithm_name)
        if descriptor.public_key_bytes is None or descriptor.secret_key_bytes is None:
            raise ValueError(f"{descriptor.name} does not define KEM key sizes")
        seed = random_bytes(32)
        public_key = shake256([b"DEMO-KEM-PK", descriptor.name.encode(), seed], descriptor.public_key_bytes)
        secret_key = seed + shake256([b"DEMO-KEM-SK", descriptor.name.encode(), seed], descriptor.secret_key_bytes - 32)
        return KeyPair(descriptor, public_key, secret_key, {"adapter": "demo"})

    def encaps(self, key_pair: KeyPair) -> EncapsulationResult:
        descriptor = key_pair.algorithm
        if descriptor.ciphertext_bytes is None:
            raise ValueError(f"{descriptor.name} does not define ciphertext size")
        nonce = random_bytes(32)
        ciphertext = shake256(
            [b"DEMO-KEM-CT", descriptor.name.encode(), key_pair.public_key, nonce],
            descriptor.ciphertext_bytes,
        )
        shared = self._shared(descriptor, key_pair.public_key, ciphertext)
        return EncapsulationResult(descriptor, ciphertext, shared, {"adapter": "demo"})

    def decaps(self, key_pair: KeyPair, ciphertext: bytes) -> bytes:
        return self._shared(key_pair.algorithm, key_pair.public_key, ciphertext)

    @staticmethod
    def _shared(descriptor: AlgorithmDescriptor, public_key: bytes, ciphertext: bytes) -> bytes:
        return shake256(
            [b"DEMO-KEM-SS", descriptor.name.encode(), public_key, ciphertext],
            descriptor.shared_secret_bytes,
        )


class DemoSignatureAdapter:
    """Signature-shaped adapter for algorithm catalog testing."""

    def keygen(self, algorithm_name: str) -> KeyPair:
        descriptor = DEFAULT_REGISTRY.get(algorithm_name)
        if descriptor.public_key_bytes is None or descriptor.secret_key_bytes is None:
            raise ValueError(f"{descriptor.name} does not define signature key sizes")
        seed = random_bytes(32)
        public_key = shake256([b"DEMO-SIG-PK", descriptor.name.encode(), seed], descriptor.public_key_bytes)
        secret_key = seed + shake256([b"DEMO-SIG-SK", descriptor.name.encode(), seed], descriptor.secret_key_bytes - 32)
        return KeyPair(descriptor, public_key, secret_key, {"adapter": "demo"})

    def sign(self, key_pair: KeyPair, message: bytes, context: bytes = b"") -> SignatureResult:
        descriptor = key_pair.algorithm
        if descriptor.signature_bytes is None:
            raise ValueError(f"{descriptor.name} does not define signature size")
        tag = mac(key_pair.public_key, b"DEMO-SIGN", descriptor.name.encode(), context, message, length=32)
        signature = tag + shake256(
            [b"DEMO-SIGN-PAD", descriptor.name.encode(), key_pair.public_key, context, message],
            descriptor.signature_bytes - len(tag),
        )
        return SignatureResult(descriptor, signature, {"adapter": "demo"})

    def verify(self, key_pair: KeyPair, message: bytes, signature: bytes, context: bytes = b"") -> bool:
        descriptor = key_pair.algorithm
        if descriptor.signature_bytes is None or len(signature) != descriptor.signature_bytes:
            return False
        expected = self.sign(key_pair, message, context).signature
        return constant_time_equal(signature, expected)


@dataclass(frozen=True)
class AdapterSuite:
    kem: DemoKEMAdapter
    signature: DemoSignatureAdapter


DEFAULT_ADAPTERS = AdapterSuite(kem=DemoKEMAdapter(), signature=DemoSignatureAdapter())
