"""
crypto_utils.py — Shared cryptographic primitives for the Secure File Transfer Protocol.

Provides:
  - RSA-2048 key generation / serialization (asymmetric identity keys)
  - ECDH-P256 ephemeral key exchange (forward-secret session keys)
  - AES-256-GCM AEAD for authenticated encryption of every chunk
  - HKDF-SHA256 for deterministic key derivation from shared secret
  - HMAC-SHA256 transcript binding helpers
  - Nonce / sequence-number helpers
"""

import os
import struct
import hashlib
import hmac as _hmac

from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ──────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────
PROTOCOL_VERSION   = b"\x01"          # 1-byte version tag
CHUNK_SIZE         = 64 * 1024         # 64 KiB plaintext chunk size
GCM_TAG_LEN        = 16               # AES-GCM authentication tag (bytes)
GCM_NONCE_LEN      = 12               # 96-bit nonce
SEQ_LEN            = 8                # 64-bit sequence number
HKDF_INFO_ENC      = b"sftp-v1-enc"   # HKDF context for encryption key
HKDF_INFO_MAC      = b"sftp-v1-mac"   # HKDF context for MAC key (transcript)
SIG_HASH           = hashes.SHA256()  # Hash used in RSA-PSS signatures


# ──────────────────────────────────────────────
# RSA Identity Keys  (long-lived, loaded from disk in real use)
# ──────────────────────────────────────────────

def generate_rsa_keypair():
    """Return (private_key, public_key) RSA-2048 objects."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private, private.public_key()


def serialize_public_key(pub) -> bytes:
    return pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_public_key(pem: bytes):
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    return load_pem_public_key(pem)


def rsa_sign(private_key, data: bytes) -> bytes:
    """RSA-PSS signature over *data*."""
    return private_key.sign(data, asym_padding.PSS(
        mgf=asym_padding.MGF1(hashes.SHA256()),
        salt_length=asym_padding.PSS.MAX_LENGTH,
    ), hashes.SHA256())


def rsa_verify(public_key, signature: bytes, data: bytes) -> bool:
    """Return True if signature is valid, False otherwise (never raises)."""
    try:
        public_key.verify(signature, data, asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ), hashes.SHA256())
        return True
    except Exception:
        return False


# ──────────────────────────────────────────────
# ECDH Ephemeral Key Exchange  (P-256)
# ──────────────────────────────────────────────

def generate_ecdh_keypair():
    """Return (private_key, public_key) ECDH P-256 objects."""
    private = ec.generate_private_key(ec.SECP256R1())
    return private, private.public_key()


def serialize_ecdh_public(pub) -> bytes:
    return pub.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )


def load_ecdh_public(raw: bytes):
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)


def ecdh_shared_secret(private_key, peer_public_key) -> bytes:
    """Return raw 32-byte shared secret (not yet a key — feed through HKDF)."""
    from cryptography.hazmat.primitives.asymmetric.ec import ECDH
    return private_key.exchange(ECDH(), peer_public_key)


# ──────────────────────────────────────────────
# HKDF Key Derivation
# ──────────────────────────────────────────────

def derive_session_keys(shared_secret: bytes, salt: bytes):
    """
    Derive two 32-byte keys from the ECDH shared secret + nonce salt.
      enc_key  — used for AES-256-GCM chunk encryption
      mac_key  — used for transcript HMAC binding
    """
    enc_key = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=salt, info=HKDF_INFO_ENC,
    ).derive(shared_secret)

    mac_key = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=salt, info=HKDF_INFO_MAC,
    ).derive(shared_secret)

    return enc_key, mac_key


# ──────────────────────────────────────────────
# AES-256-GCM  (AEAD — provides confidentiality + integrity in one pass)
# ──────────────────────────────────────────────

def aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Return ciphertext‖tag (GCM tag is appended by the library)."""
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext_with_tag: bytes, aad: bytes = b"") -> bytes:
    """Return plaintext, or raise InvalidTag on failure."""
    return AESGCM(key).decrypt(nonce, ciphertext_with_tag, aad)


# ──────────────────────────────────────────────
# Nonce / sequence helpers
# ──────────────────────────────────────────────

def random_nonce() -> bytes:
    """Return a cryptographically random 12-byte GCM nonce."""
    return os.urandom(GCM_NONCE_LEN)


def random_32() -> bytes:
    return os.urandom(32)


def seq_to_bytes(seq: int) -> bytes:
    """Pack a 64-bit unsigned sequence number big-endian."""
    return struct.pack(">Q", seq)


def bytes_to_seq(b: bytes) -> int:
    return struct.unpack(">Q", b)[0]


# ──────────────────────────────────────────────
# Transcript MAC  (prevents MITM on handshake messages)
# ──────────────────────────────────────────────

def compute_transcript_mac(mac_key: bytes, *messages: bytes) -> bytes:
    """
    HMAC-SHA256 over the concatenation of all handshake messages (in order).
    Both sides independently compute this; a mismatch means the transcript
    was tampered with.
    """
    h = _hmac.new(mac_key, digestmod=hashlib.sha256)
    for msg in messages:
        h.update(msg)
    return h.digest()


def verify_transcript_mac(mac_key: bytes, expected_mac: bytes, *messages: bytes) -> bool:
    got = compute_transcript_mac(mac_key, *messages)
    return _hmac.compare_digest(got, expected_mac)


# ──────────────────────────────────────────────
# File chunking utility
# ──────────────────────────────────────────────

def file_chunks(path: str, chunk_size: int = CHUNK_SIZE):
    """Yield (seq_num, chunk_bytes) for every chunk in the file."""
    with open(path, "rb") as f:
        seq = 0
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            yield seq, data
            seq += 1
