"""
protocol.py — Wire-format definitions and state-machine for the Secure File
Transfer Protocol (SFTP-v1).

Message layout (all integers big-endian):
───────────────────────────────────────────────────────────────────────────────
  [1] MSG_TYPE   [4] PAYLOAD_LEN   [PAYLOAD_LEN] PAYLOAD
───────────────────────────────────────────────────────────────────────────────

Handshake sequence (both sides run a strict state machine):
  CLIENT                                SERVER
    │── MSG_CLIENT_HELLO ─────────────────►│   (client nonce, client ECDH pub)
    │◄─────────────────── MSG_SERVER_HELLO ─│   (server nonce, server ECDH pub,
    │                                       │    server RSA cert, sig over HS)
    │── MSG_CLIENT_FINISH ────────────────►│   (client RSA cert, sig, transcript
    │                                       │    MAC to prove both saw same HS)
    ▼  ── session keys now established ── ▼

Data transfer:
  CLIENT                                SERVER
    │── MSG_FILE_META ──────────────────►│   (AES-GCM encrypted metadata)
    │── MSG_CHUNK (seq=0) ─────────────►│   (AES-GCM encrypted, AAD=seq)
    │── MSG_CHUNK (seq=1) ─────────────►│
    │   ...                              │
    │── MSG_TRANSFER_DONE ────────────►│   (final seq count, file HMAC)
    │◄─────────────────── MSG_ACK/NACK ──│

Error / abort:
    either side can send MSG_ERROR at any time → both abort
"""

import struct
from enum import IntEnum

# ──────────────────────────────────────────────
# Message type codes
# ──────────────────────────────────────────────
class MsgType(IntEnum):
    CLIENT_HELLO    = 0x01
    SERVER_HELLO    = 0x02
    CLIENT_FINISH   = 0x03
    FILE_META       = 0x10
    CHUNK           = 0x11
    TRANSFER_DONE   = 0x12
    ACK             = 0x20
    NACK            = 0x21
    ERROR           = 0xFF


# ──────────────────────────────────────────────
# State machine states
# ──────────────────────────────────────────────
class ClientState(IntEnum):
    INIT          = 0
    HELLO_SENT    = 1
    ESTABLISHED   = 2
    TRANSFERRING  = 3
    DONE          = 4
    ABORTED       = -1


class ServerState(IntEnum):
    INIT          = 0
    HELLO_SENT    = 1
    ESTABLISHED   = 2
    RECEIVING     = 3
    DONE          = 4
    ABORTED       = -1


# ──────────────────────────────────────────────
# Low-level framing
# ──────────────────────────────────────────────
HEADER_FMT   = ">BI"   # 1 byte type + 4 byte length
HEADER_SIZE  = struct.calcsize(HEADER_FMT)   # = 5


def pack_message(msg_type: MsgType, payload: bytes) -> bytes:
    """Prefix payload with a 5-byte header: [type:1][length:4]."""
    return struct.pack(HEADER_FMT, int(msg_type), len(payload)) + payload


def unpack_header(raw: bytes):
    """Return (msg_type, payload_length) from a 5-byte header."""
    if len(raw) < HEADER_SIZE:
        raise ValueError(f"Header too short: {len(raw)} < {HEADER_SIZE}")
    msg_type_int, payload_len = struct.unpack(HEADER_FMT, raw[:HEADER_SIZE])
    return MsgType(msg_type_int), payload_len


# ──────────────────────────────────────────────
# Socket I/O helpers  (length-prefixed framing)
# ──────────────────────────────────────────────

def send_message(sock, msg_type: MsgType, payload: bytes):
    """Send a framed message; raises on socket error."""
    data = pack_message(msg_type, payload)
    sock.sendall(data)


def recv_message(sock):
    """Block until a full framed message arrives; return (MsgType, payload)."""
    header = _recvn(sock, HEADER_SIZE)
    msg_type, payload_len = unpack_header(header)
    payload = _recvn(sock, payload_len) if payload_len else b""
    return msg_type, payload


def _recvn(sock, n: int) -> bytes:
    """Receive exactly n bytes from sock."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed prematurely")
        buf += chunk
    return buf


# ──────────────────────────────────────────────
# Payload builders / parsers
# ──────────────────────────────────────────────

# ── CLIENT_HELLO ────────────────────────────
# Layout: [nonce:32][ecdh_pub:65]
CH_NONCE_OFF  = 0
CH_NONCE_LEN  = 32
CH_ECDH_OFF   = CH_NONCE_OFF + CH_NONCE_LEN
CH_ECDH_LEN   = 65   # uncompressed P-256 point
CH_LEN        = CH_NONCE_LEN + CH_ECDH_LEN

def build_client_hello(nonce: bytes, ecdh_pub: bytes) -> bytes:
    assert len(nonce) == CH_NONCE_LEN and len(ecdh_pub) == CH_ECDH_LEN
    return nonce + ecdh_pub

def parse_client_hello(payload: bytes):
    assert len(payload) == CH_LEN
    return payload[:CH_NONCE_LEN], payload[CH_NONCE_LEN:]

# ── SERVER_HELLO ─────────────────────────────
# Layout: [nonce:32][ecdh_pub:65][cert_len:4][cert][sig_len:4][sig]
def build_server_hello(nonce: bytes, ecdh_pub: bytes, cert_pem: bytes, sig: bytes) -> bytes:
    assert len(nonce) == 32 and len(ecdh_pub) == 65
    return (nonce + ecdh_pub
            + struct.pack(">I", len(cert_pem)) + cert_pem
            + struct.pack(">I", len(sig)) + sig)

def parse_server_hello(payload: bytes):
    off = 0
    nonce    = payload[off:off+32];  off += 32
    ecdh_pub = payload[off:off+65];  off += 65
    clen,    = struct.unpack(">I", payload[off:off+4]); off += 4
    cert     = payload[off:off+clen]; off += clen
    slen,    = struct.unpack(">I", payload[off:off+4]); off += 4
    sig      = payload[off:off+slen]; off += slen
    return nonce, ecdh_pub, cert, sig

# ── CLIENT_FINISH ─────────────────────────────
# Layout: [cert_len:4][cert][sig_len:4][sig][transcript_mac:32]
def build_client_finish(cert_pem: bytes, sig: bytes, transcript_mac: bytes) -> bytes:
    assert len(transcript_mac) == 32
    return (struct.pack(">I", len(cert_pem)) + cert_pem
            + struct.pack(">I", len(sig)) + sig
            + transcript_mac)

def parse_client_finish(payload: bytes):
    off = 0
    clen, = struct.unpack(">I", payload[off:off+4]); off += 4
    cert  = payload[off:off+clen]; off += clen
    slen, = struct.unpack(">I", payload[off:off+4]); off += 4
    sig   = payload[off:off+slen]; off += slen
    tmac  = payload[off:off+32]
    return cert, sig, tmac

# ── FILE_META (encrypted payload structure) ──
# Plaintext layout before encryption:
#   [filename_len:2][filename][file_size:8][total_chunks:8][file_sha256:32]
def build_file_meta_plain(filename: str, file_size: int,
                           total_chunks: int, file_sha256: bytes) -> bytes:
    fn = filename.encode()
    return (struct.pack(">H", len(fn)) + fn
            + struct.pack(">QQ", file_size, total_chunks)
            + file_sha256)

def parse_file_meta_plain(data: bytes):
    off = 0
    fnlen, = struct.unpack(">H", data[off:off+2]); off += 2
    fn = data[off:off+fnlen].decode(); off += fnlen
    fsize, total = struct.unpack(">QQ", data[off:off+16]); off += 16
    sha256 = data[off:off+32]
    return fn, fsize, total, sha256

# ── CHUNK (encrypted) ──
# On the wire:  [seq:8][nonce:12][ciphertext+tag]
# The AAD for GCM is seq_bytes (protects sequence number from tampering)
CHUNK_SEQ_OFF   = 0
CHUNK_NONCE_OFF = 8
CHUNK_CT_OFF    = 8 + 12

def build_chunk_wire(seq: int, nonce: bytes, ciphertext: bytes) -> bytes:
    import struct as _s
    return _s.pack(">Q", seq) + nonce + ciphertext

def parse_chunk_wire(payload: bytes):
    import struct as _s
    seq,   = _s.unpack(">Q", payload[:8])
    nonce  = payload[8:20]
    ct     = payload[20:]
    return seq, nonce, ct

# ── TRANSFER_DONE ──
# Layout: [total_chunks:8][file_sha256:32]
def build_transfer_done(total_chunks: int, file_sha256: bytes) -> bytes:
    return struct.pack(">Q", total_chunks) + file_sha256

def parse_transfer_done(payload: bytes):
    total, = struct.unpack(">Q", payload[:8])
    sha256 = payload[8:40]
    return total, sha256

# ── ACK / NACK / ERROR ──
def build_ack(info: bytes = b"OK") -> bytes:
    return info

def build_nack(reason: bytes) -> bytes:
    return reason

def build_error(reason: bytes) -> bytes:
    return reason
