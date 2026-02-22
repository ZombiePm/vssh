#!/usr/bin/env python3
"""Add an SSH private key to Pageant via the SSH agent protocol.

Reads PEM-encoded private key from stdin, sends it to Pageant
using the SSH agent IPC — no temp files, no puttygen needed.
Supports RSA, Ed25519, and ECDSA keys.

Usage: vault kv get -field=private_key secret/ssh/key | python vssh-pageant.py
"""
import struct
import sys
from io import StringIO
from paramiko import RSAKey, Ed25519Key, ECDSAKey, Message
from paramiko.agent import Agent
from paramiko.win_pageant import can_talk_to_agent

SSH2_AGENTC_ADD_IDENTITY = 17
SSH_AGENT_SUCCESS = 6


def build_add_message(key, comment="vssh"):
    """Build SSH2_AGENTC_ADD_IDENTITY message for any supported key type."""
    msg = Message()
    msg.add_byte(struct.pack("B", SSH2_AGENTC_ADD_IDENTITY))

    key_type = key.get_name()
    msg.add_string(key_type)

    if key_type == "ssh-rsa":
        nums = key.key.private_numbers()
        pub = nums.public_numbers
        msg.add_mpint(pub.n)
        msg.add_mpint(pub.e)
        msg.add_mpint(nums.d)
        msg.add_mpint(nums.iqmp)
        msg.add_mpint(nums.p)
        msg.add_mpint(nums.q)

    elif key_type == "ssh-ed25519":
        sk = key._signing_key  # nacl.signing.SigningKey
        pub_bytes = sk.verify_key.encode()  # 32 bytes
        seed = sk.encode()  # 32 bytes
        msg.add_string(pub_bytes)
        msg.add_string(seed + pub_bytes)  # 64 bytes: seed || public

    elif key_type.startswith("ecdsa-sha2-"):
        curve = key_type.replace("ecdsa-sha2-", "")
        nums = key.signing_key.private_numbers()
        pub_point = key.verifying_key.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        msg.add_string(curve)
        msg.add_string(pub_point)
        msg.add_mpint(nums.private_value)

    else:
        return None

    msg.add_string(comment)
    return msg


def key_already_loaded(agent, key):
    """Check if this key's public part is already in Pageant."""
    pub_blob = key.asbytes()
    for existing in agent.get_keys():
        if existing.asbytes() == pub_blob:
            return True
    return False


def parse_key(key_pem):
    """Try to parse key as RSA, Ed25519, or ECDSA."""
    for cls in (Ed25519Key, RSAKey, ECDSAKey):
        try:
            return cls.from_private_key(StringIO(key_pem))
        except Exception:
            continue
    return None


def main():
    if not can_talk_to_agent():
        print("Pageant is not running", file=sys.stderr)
        return 1

    raw = sys.stdin.read()
    # Strip BOM and any encoding artifacts (PowerShell can prepend garbled BOM)
    idx = raw.find("-----BEGIN")
    key_pem = raw[idx:].strip() if idx >= 0 else raw.strip()
    if not key_pem:
        print("No key data on stdin", file=sys.stderr)
        return 1

    key = parse_key(key_pem)
    if key is None:
        print("Failed to parse key (unsupported type?)", file=sys.stderr)
        return 1

    agent = Agent()
    try:
        if key_already_loaded(agent, key):
            print("Key already in Pageant")
            return 0

        msg = build_add_message(key)
        if msg is None:
            print(f"Unsupported key type: {key.get_name()}", file=sys.stderr)
            return 1

        resp_type, _ = agent._send_message(msg)
        if resp_type == SSH_AGENT_SUCCESS:
            print("Key added to Pageant")
            return 0
        else:
            print("Pageant rejected the key", file=sys.stderr)
            return 1
    finally:
        agent.close()


if __name__ == "__main__":
    sys.exit(main())
