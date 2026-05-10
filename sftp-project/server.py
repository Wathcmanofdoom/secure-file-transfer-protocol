"""
server.py — Secure File Transfer Server

State machine:
  INIT → (recv CLIENT_HELLO) → HELLO_SENT → (recv CLIENT_FINISH)
       → ESTABLISHED → (recv FILE_META) → RECEIVING
       → (recv all CHUNK) → (recv TRANSFER_DONE) → DONE

Security checks performed:
  1. RSA-PSS signature on server's ephemeral ECDH key (sent in SERVER_HELLO)
  2. RSA-PSS signature on client's ephemeral ECDH key  (recv in CLIENT_FINISH)
  3. Transcript MAC — both sides hash all handshake messages with the derived
     mac_key; mismatch → abort (prevents MITM splice)
  4. AES-256-GCM on every chunk (AAD = sequence number bytes) — both
     confidentiality and integrity per chunk
  5. Sequence number checked monotonically — gap or reorder → NACK + abort
  6. SHA-256 of reassembled file checked against FILE_META commitment
"""

import socket
import os
import hashlib
import time
import struct

from crypto_utils import (
    generate_rsa_keypair, serialize_public_key, load_public_key,
    generate_ecdh_keypair, serialize_ecdh_public, load_ecdh_public,
    ecdh_shared_secret, derive_session_keys,
    rsa_sign, rsa_verify,
    aes_gcm_decrypt, random_nonce, random_32, seq_to_bytes,
    compute_transcript_mac, verify_transcript_mac,
)
from protocol import (
    MsgType, ServerState,
    send_message, recv_message,
    parse_client_hello, build_server_hello,
    parse_client_finish,
    parse_file_meta_plain,
    parse_chunk_wire, build_chunk_wire,
    parse_transfer_done,
    build_ack, build_nack, build_error,
)
from transcript import Transcript


class SecureFileServer:
    def __init__(self, host="127.0.0.1", port=9876, output_dir="received",
                 log_dir="logs"):
        self.host       = host
        self.port       = port
        self.output_dir = output_dir
        self.log_dir    = log_dir

        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(log_dir, exist_ok=True)

        # Long-lived RSA identity key (in practice loaded from disk / PKI)
        self.rsa_priv, self.rsa_pub = generate_rsa_keypair()
        self.cert_pem               = serialize_public_key(self.rsa_pub)

    # ──────────────────────────────────────────
    def serve_one(self):
        """Accept exactly one connection and handle it."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(1)
        print(f"[SERVER] Listening on {self.host}:{self.port} …")
        conn, addr = srv.accept()
        srv.close()
        print(f"[SERVER] Connection from {addr}")
        return self._handle(conn)

    # ──────────────────────────────────────────
    def _handle(self, conn):
        t = Transcript("SERVER", self.log_dir)
        state = ServerState.INIT

        # Ephemeral ECDH key for this session
        ecdh_priv, ecdh_pub = generate_ecdh_keypair()
        server_ecdh_bytes   = serialize_ecdh_public(ecdh_pub)
        server_nonce        = random_32()

        enc_key = mac_key = None
        # Collect raw handshake bytes for transcript MAC
        hs_msgs = []

        try:
            # ── STEP 1: Receive CLIENT_HELLO ──────────────────────────────
            msg_type, payload = recv_message(conn)
            if msg_type != MsgType.CLIENT_HELLO:
                raise ProtocolError(f"Expected CLIENT_HELLO, got {msg_type}")
            hs_msgs.append(payload)

            client_nonce, client_ecdh_bytes = parse_client_hello(payload)
            t.log("RECV CLIENT_HELLO",
                  f"client_nonce={client_nonce[:8].hex()}… "
                  f"ecdh_pub={client_ecdh_bytes[:8].hex()}…",
                  client_nonce)
            state = ServerState.HELLO_SENT

            # ── STEP 2: Build + Send SERVER_HELLO ─────────────────────────
            # Sign: server_nonce ‖ server_ecdh_pub ‖ client_nonce
            # (binding server's ephemeral key to this session's nonces)
            to_sign = server_nonce + server_ecdh_bytes + client_nonce
            sig     = rsa_sign(self.rsa_priv, to_sign)

            sh_payload = build_server_hello(server_nonce, server_ecdh_bytes,
                                            self.cert_pem, sig)
            hs_msgs.append(sh_payload)
            send_message(conn, MsgType.SERVER_HELLO, sh_payload)
            t.log("SENT SERVER_HELLO",
                  f"server_nonce={server_nonce[:8].hex()}… sig_len={len(sig)}",
                  server_nonce)

            # ── Derive session keys ────────────────────────────────────────
            client_ecdh_pub = load_ecdh_public(client_ecdh_bytes)
            shared_secret   = ecdh_shared_secret(ecdh_priv, client_ecdh_pub)
            # Salt = client_nonce ‖ server_nonce (both public, both authenticated)
            salt            = client_nonce + server_nonce
            enc_key, mac_key = derive_session_keys(shared_secret, salt)
            t.log("SESSION_KEYS_DERIVED",
                  f"enc_key={enc_key[:8].hex()}… mac_key={mac_key[:8].hex()}…")

            # ── STEP 3: Receive CLIENT_FINISH ─────────────────────────────
            msg_type, payload = recv_message(conn)
            if msg_type != MsgType.CLIENT_FINISH:
                raise ProtocolError(f"Expected CLIENT_FINISH, got {msg_type}")

            client_cert_pem, client_sig, recv_tmac = parse_client_finish(payload)
            hs_msgs_for_tmac = hs_msgs[:]   # CH + SH payloads so far

            # Verify client's RSA signature over its ECDH key
            client_pub   = load_public_key(client_cert_pem)
            to_verify    = client_nonce + client_ecdh_bytes + server_nonce
            if not rsa_verify(client_pub, client_sig, to_verify):
                raise AuthError("Client ECDH signature invalid")
            t.log("CLIENT_SIGNATURE_OK", "Client identity verified")

            # Verify transcript MAC
            expected_tmac = compute_transcript_mac(mac_key, *hs_msgs_for_tmac)
            if not verify_transcript_mac(mac_key, recv_tmac, *hs_msgs_for_tmac):
                raise AuthError(
                    f"Transcript MAC mismatch! "
                    f"Expected {expected_tmac.hex()}, got {recv_tmac.hex()}"
                )
            t.log("TRANSCRIPT_MAC_OK", "Handshake not tampered")
            state = ServerState.ESTABLISHED

            send_message(conn, MsgType.ACK, build_ack(b"HANDSHAKE_OK"))
            t.log("SENT ACK", "Handshake complete — session established")

            # ── STEP 4: Receive FILE_META ──────────────────────────────────
            msg_type, payload = recv_message(conn)
            if msg_type != MsgType.FILE_META:
                raise ProtocolError(f"Expected FILE_META, got {msg_type}")

            # Payload = nonce(12) ‖ ciphertext+tag
            meta_nonce = payload[:12]
            meta_ct    = payload[12:]
            meta_plain = aes_gcm_decrypt(enc_key, meta_nonce, meta_ct)
            filename, file_size, total_chunks, committed_sha256 = \
                parse_file_meta_plain(meta_plain)

            t.log("RECV FILE_META",
                  f"file='{filename}' size={file_size} chunks={total_chunks} "
                  f"sha256={committed_sha256.hex()[:16]}…")

            state         = ServerState.RECEIVING
            out_path      = os.path.join(self.output_dir, os.path.basename(filename))
            expected_seq  = 0
            file_hasher   = hashlib.sha256()
            bytes_recvd   = 0
            t_transfer_start = time.perf_counter()

            send_message(conn, MsgType.ACK, build_ack(b"META_OK"))

            # ── STEP 5: Receive CHUNK stream ───────────────────────────────
            with open(out_path, "wb") as out_f:
                while True:
                    msg_type, payload = recv_message(conn)

                    if msg_type == MsgType.TRANSFER_DONE:
                        recv_total, recv_sha256 = parse_transfer_done(payload)
                        t.log("RECV TRANSFER_DONE",
                              f"total={recv_total} sha256={recv_sha256.hex()[:16]}…")
                        break

                    if msg_type != MsgType.CHUNK:
                        raise ProtocolError(f"Expected CHUNK or DONE, got {msg_type}")

                    seq, nonce, ct = parse_chunk_wire(payload)

                    # ── Replay / reorder check ──
                    if seq != expected_seq:
                        raise ReplayError(
                            f"Sequence mismatch: expected {expected_seq}, got {seq}"
                        )

                    # ── AEAD decrypt — AAD binds sequence number ──
                    aad       = seq_to_bytes(seq)
                    plaintext = aes_gcm_decrypt(enc_key, nonce, ct, aad=aad)

                    out_f.write(plaintext)
                    file_hasher.update(plaintext)
                    bytes_recvd  += len(plaintext)
                    expected_seq += 1

                    if seq % 16 == 0 or seq == total_chunks - 1:
                        t.log("CHUNK_OK", f"seq={seq} plain_len={len(plaintext)}")

            # ── STEP 6: Final integrity check ──────────────────────────────
            t_transfer_end = time.perf_counter()
            actual_sha256  = file_hasher.digest()

            if actual_sha256 != recv_sha256:
                raise IntegrityError(
                    f"File SHA-256 mismatch!\n"
                    f"  committed : {committed_sha256.hex()}\n"
                    f"  received  : {actual_sha256.hex()}"
                )
            if actual_sha256 != committed_sha256:
                raise IntegrityError("SHA-256 differs from FILE_META commitment")

            elapsed = t_transfer_end - t_transfer_start
            throughput = (bytes_recvd / elapsed / 1024 / 1024) if elapsed > 0 else 0
            t.log("FILE_INTEGRITY_OK",
                  f"sha256={actual_sha256.hex()[:16]}… "
                  f"size={bytes_recvd} bytes "
                  f"throughput={throughput:.2f} MiB/s")

            send_message(conn, MsgType.ACK, build_ack(b"TRANSFER_OK"))
            t.log("SENT ACK", "Transfer verified and complete")
            state = ServerState.DONE

            result = {
                "status": "ok",
                "filename": filename,
                "bytes": bytes_recvd,
                "throughput_mibps": throughput,
                "elapsed_s": elapsed,
                "sha256": actual_sha256.hex(),
            }

        except (ProtocolError, AuthError, ReplayError, IntegrityError) as e:
            t.log("SECURITY_ERROR", str(e))
            try:
                send_message(conn, MsgType.ERROR, build_error(str(e).encode()))
            except Exception:
                pass
            result = {"status": "error", "reason": str(e)}

        except Exception as e:
            t.log("UNEXPECTED_ERROR", str(e))
            result = {"status": "error", "reason": str(e)}

        finally:
            conn.close()
            log_path = t.save()
            print(f"[SERVER] Transcript saved → {log_path}")

        return result


# ──────────────────────────────────────────────
# Custom exceptions
# ──────────────────────────────────────────────
class ProtocolError(Exception):  pass
class AuthError(Exception):      pass
class ReplayError(Exception):    pass
class IntegrityError(Exception): pass


if __name__ == "__main__":
    srv = SecureFileServer()
    srv.serve_one()
