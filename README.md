# Secure File Transfer Protocol

A cryptographically secure file transfer protocol built from scratch in Python for my Computer Networks / Security coursework.

## What it does
- Performs a secure handshake between client and server before any file is sent
- Encrypts every file chunk using AES-GCM (256-bit)
- Uses ECDH for session key exchange and RSA-2048 for identity verification
- Detects and blocks tampering, dropped packets, and chunk reordering attacks
- Logs a full cryptographic transcript of every session

## Performance
Tested at **120+ MiB/s** throughput on a local machine.

## How to run

Install the dependency:
pip install cryptography

Run the full test suite:
python run_tests.py

Send your own file interactively:
python send_my_file.py

## Project structure
- crypto_utils.py — RSA, ECDH, AES-GCM, HKDF key derivation
- protocol.py — message framing and serialisation
- server.py — server handshake and file receiver
- client.py — client handshake and file sender
- transcript.py — session logging
- run_tests.py — automated test suite (normal transfers + attack detection)
- send_my_file.py — interactive file sender

## Security features tested
- Tampered ciphertext → detected and connection dropped
- Dropped chunk → detected via sequence numbers
- Reordered chunks → detected via sequence numbers
