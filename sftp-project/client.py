"""
client.py — Secure File Transfer Client

State machine:
  INIT → (send CLIENT_HELLO) → HELLO_SENT → (recv SERVER_HELLO)
       → (send CLIENT_FINISH) → ESTABLISHED
       → (send FILE_META) → TRANSFERRING
       → (send all CHUNK) → (send TRANSFER_DONE) → DONE

Security actions:
  1. Verifies server's RSA-PSS signature on its ECDH key
  2. Signs own ECDH key with client RSA key
  3. Sends transcript MAC so server can detect any HS tampering
  4. Encrypts every chunk with AES-256-GCM, AAD = seq number
  5. Sends final SHA-256 commitment for file-level integrity check
"""

import socket
import os
import hashlib
import time

from crypto_utils import (
    generate_rsa_keypair, serialize_public_key, load_public_key,
    generate_ecdh_keypair, serialize_ecdh_public, load_ecdh_public,
    ecdh_shared_secret, derive_session_keys,
    rsa_sign, rsa_verify,
    aes_gcm_encrypt, random_nonce, random_32, seq_to_bytes,
    compute_transcript_mac,
    CHUNK_SIZE,
)
from protocol import (
    MsgType, ClientState,
    send_message, recv_message,
    build_client_hello, parse_server_hello,
    build_client_finish,
    build_file_meta_plain,
    build_chunk_wire,
    build_transfer_done,
    parse_transfer_done,
)
from transcript import Transcript


class SecureFileClient:
    def __init__(self, host="127.0.0.1", port=9876, log_dir="logs"):
        self.host    = host
        self.port    = port
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)

        # Long-lived RSA identity key
        self.rsa_priv, self.rsa_pub = generate_rsa_keypair()
        self.cert_pem               = serialize_public_key(self.rsa_pub)

    # ──────────────────────────────────────────
    def send_file(self, filepath: str, tamper_chunk: int = None,
                  drop_chunk: int = None, reorder_chunks=False):
        """
        Send *filepath* securely.

        tamper_chunk  — if set, flip a bit in that chunk's ciphertext (test)
        drop_chunk    — if set, skip sending that chunk (test)
        reorder_chunks — if True, send chunk 1 before chunk 0 (test)
        """
        t     = Transcript("CLIENT", self.log_dir)
        state = ClientState.INIT

        conn = socket.create_connection((self.host, self.port))
        t.log("TCP_CONNECTED", f"{self.host}:{self.port}")

        # Ephemeral ECDH + nonce for this session
        ecdh_priv, ecdh_pub = generate_ecdh_keypair()
        client_ecdh_bytes   = serialize_ecdh_public(ecdh_pub)
        client_nonce        = random_32()

        hs_msgs  = []   # accumulate raw payloads for transcript MAC
        enc_key  = None

        try:
            # ── STEP 1: Send CLIENT_HELLO ──────────────────────────────────
            ch_payload = build_client_hello(client_nonce, client_ecdh_bytes)
            hs_msgs.append(ch_payload)
            send_message(conn, MsgType.CLIENT_HELLO, ch_payload)
            t.log("SENT CLIENT_HELLO",
                  f"client_nonce={client_nonce[:8].hex()}… "
                  f"ecdh_pub={client_ecdh_bytes[:8].hex()}…")
            state = ClientState.HELLO_SENT

            # ── STEP 2: Receive SERVER_HELLO ───────────────────────────────
            msg_type, sh_payload = recv_message(conn)
            if msg_type != MsgType.SERVER_HELLO:
                raise ProtocolError(f"Expected SERVER_HELLO, got {msg_type}")
            hs_msgs.append(sh_payload)

            server_nonce, server_ecdh_bytes, server_cert_pem, server_sig = \
                parse_server_hello(sh_payload)

            # Verify server's RSA signature on its ECDH key
            server_pub  = load_public_key(server_cert_pem)
            to_verify   = server_nonce + server_ecdh_bytes + client_nonce
            if not rsa_verify(server_pub, server_sig, to_verify):
                raise AuthError("Server ECDH signature invalid — possible MITM")
            t.log("SERVER_SIGNATURE_OK",
                  f"server_nonce={server_nonce[:8].hex()}…")

            # ── Derive session keys ────────────────────────────────────────
            server_ecdh_pub = load_ecdh_public(server_ecdh_bytes)
            shared_secret   = ecdh_shared_secret(ecdh_priv, server_ecdh_pub)
            salt            = client_nonce + server_nonce
            enc_key, mac_key = derive_session_keys(shared_secret, salt)
            t.log("SESSION_KEYS_DERIVED",
                  f"enc_key={enc_key[:8].hex()}… mac_key={mac_key[:8].hex()}…")

            # ── STEP 3: Send CLIENT_FINISH ─────────────────────────────────
            to_sign = client_nonce + client_ecdh_bytes + server_nonce
            sig     = rsa_sign(self.rsa_priv, to_sign)

            tmac    = compute_transcript_mac(mac_key, *hs_msgs)
            cf_payload = build_client_finish(self.cert_pem, sig, tmac)
            send_message(conn, MsgType.CLIENT_FINISH, cf_payload)
            t.log("SENT CLIENT_FINISH",
                  f"sig_len={len(sig)} tmac={tmac.hex()[:16]}…")

            # Wait for handshake ACK
            msg_type, ack_data = recv_message(conn)
            if msg_type != MsgType.ACK:
                raise ProtocolError(f"Handshake not acknowledged: {msg_type}")
            t.log("RECV ACK", ack_data.decode(errors="replace"))
            state = ClientState.ESTABLISHED

            # ── STEP 4: Send FILE_META ─────────────────────────────────────
            file_size, file_sha256, total_chunks = _file_stats(filepath)
            meta_plain  = build_file_meta_plain(
                os.path.basename(filepath), file_size,
                total_chunks, file_sha256
            )
            meta_nonce  = random_nonce()
            meta_ct     = aes_gcm_encrypt(enc_key, meta_nonce, meta_plain)
            send_message(conn, MsgType.FILE_META, meta_nonce + meta_ct)
            t.log("SENT FILE_META",
                  f"file='{os.path.basename(filepath)}' size={file_size} "
                  f"chunks={total_chunks} sha256={file_sha256.hex()[:16]}…")

            # Wait for META ACK
            msg_type, ack_data = recv_message(conn)
            if msg_type != MsgType.ACK:
                raise ProtocolError("FILE_META not acknowledged")
            t.log("RECV ACK", ack_data.decode(errors="replace"))
            state = ClientState.TRANSFERRING

            # ── STEP 5: Send CHUNKs ────────────────────────────────────────
            t_start = time.perf_counter()
            chunks  = list(_read_chunks(filepath))

            if reorder_chunks and len(chunks) >= 2:
                # swap first two chunks to trigger reorder detection
                chunks[0], chunks[1] = chunks[1], chunks[0]
                t.log("TEST_REORDER", "Swapped chunk 0 and 1 (should be detected)")

            bytes_sent = 0
            for seq, plain in chunks:
                if drop_chunk is not None and seq == drop_chunk:
                    t.log("TEST_DROP", f"Intentionally dropping chunk seq={seq}")
                    continue  # simulate dropped chunk

                nonce    = random_nonce()
                aad      = seq_to_bytes(seq)
                ct       = aes_gcm_encrypt(enc_key, nonce, plain, aad=aad)

                if tamper_chunk is not None and seq == tamper_chunk:
                    # Flip a byte in the ciphertext (before the GCM tag)
                    ct_list    = bytearray(ct)
                    ct_list[0] ^= 0xFF
                    ct         = bytes(ct_list)
                    t.log("TEST_TAMPER",
                          f"Flipped byte 0 of ciphertext in chunk seq={seq}")

                wire = build_chunk_wire(seq, nonce, ct)
                send_message(conn, MsgType.CHUNK, wire)
                bytes_sent += len(plain)

                if seq % 16 == 0 or seq == total_chunks - 1:
                    t.log("SENT_CHUNK", f"seq={seq} plain={len(plain)} ct={len(ct)}")

            # ── STEP 6: Send TRANSFER_DONE ─────────────────────────────────
            done_payload = build_transfer_done(total_chunks, file_sha256)
            send_message(conn, MsgType.TRANSFER_DONE, done_payload)
            t.log("SENT TRANSFER_DONE",
                  f"total_chunks={total_chunks} sha256={file_sha256.hex()[:16]}…")

            # Wait for final ACK/NACK
            msg_type, final_data = recv_message(conn)
            elapsed    = time.perf_counter() - t_start
            throughput = (bytes_sent / elapsed / 1024 / 1024) if elapsed > 0 else 0

            if msg_type == MsgType.ACK:
                t.log("RECV FINAL_ACK",
                      f"{final_data.decode(errors='replace')} — "
                      f"{bytes_sent} bytes in {elapsed:.3f}s "
                      f"({throughput:.2f} MiB/s)")
                result = {
                    "status": "ok", "bytes": bytes_sent,
                    "elapsed_s": elapsed,
                    "throughput_mibps": throughput,
                }
            else:
                reason = final_data.decode(errors="replace")
                t.log("RECV NACK/ERROR", reason)
                result = {"status": "error", "reason": reason}

            state = ClientState.DONE

        except (ProtocolError, AuthError) as e:
            t.log("SECURITY_ERROR", str(e))
            result = {"status": "error", "reason": str(e)}

        except Exception as e:
            t.log("UNEXPECTED_ERROR", str(e))
            result = {"status": "error", "reason": str(e)}

        finally:
            conn.close()
            log_path = t.save()
            print(f"[CLIENT] Transcript saved → {log_path}")

        return result


# ──────────────────────────────────────────────
# File helpers
# ──────────────────────────────────────────────

def _file_stats(path: str):
    """Return (file_size, sha256_bytes, total_chunks)."""
    hasher = hashlib.sha256()
    size   = 0
    chunks = 0
    with open(path, "rb") as f:
        while True:
            data = f.read(CHUNK_SIZE)
            if not data:
                break
            hasher.update(data)
            size   += len(data)
            chunks += 1
    return size, hasher.digest(), chunks


def _read_chunks(path: str):
    """Yield (seq, chunk_bytes)."""
    with open(path, "rb") as f:
        seq = 0
        while True:
            data = f.read(CHUNK_SIZE)
            if not data:
                break
            yield seq, data
            seq += 1


# ──────────────────────────────────────────────
class ProtocolError(Exception): pass
class AuthError(Exception):     pass
