#!/usr/bin/env python3
"""Add an SSH private key to Pageant via the SSH agent protocol.

Reads PEM-encoded private key from stdin, sends it to Pageant
using the SSH agent IPC — no temp files, no puttygen needed.

Usage: vault kv get -field=private_key secret/ssh/key | python vssh-pageant.py
"""
import struct
import sys
from io import StringIO
from paramiko import RSAKey, Message
from paramiko.agent import Agent
from paramiko.win_pageant import can_talk_to_agent

SSH2_AGENTC_ADD_IDENTITY = 17
SSH_AGENT_SUCCESS = 6


def add_rsa_key(agent, key, comment="vssh"):
    nums = key.key.private_numbers()
    pub = nums.public_numbers

    msg = Message()
    msg.add_byte(struct.pack("B", SSH2_AGENTC_ADD_IDENTITY))
    msg.add_string("ssh-rsa")
    msg.add_mpint(pub.n)
    msg.add_mpint(pub.e)
    msg.add_mpint(nums.d)
    msg.add_mpint(nums.iqmp)
    msg.add_mpint(nums.p)
    msg.add_mpint(nums.q)
    msg.add_string(comment)

    resp_type, _ = agent._send_message(msg)
    return resp_type == SSH_AGENT_SUCCESS


def key_already_loaded(agent, key):
    """Check if this key's public part is already in Pageant."""
    pub_blob = key.asbytes()
    for existing in agent.get_keys():
        if existing.asbytes() == pub_blob:
            return True
    return False


def main():
    if not can_talk_to_agent():
        print("Pageant is not running", file=sys.stderr)
        return 1

    key_pem = sys.stdin.read().strip()
    if not key_pem:
        print("No key data on stdin", file=sys.stderr)
        return 1

    try:
        key = RSAKey.from_private_key(StringIO(key_pem))
    except Exception as e:
        print(f"Failed to parse key: {e}", file=sys.stderr)
        return 1

    agent = Agent()
    try:
        if key_already_loaded(agent, key):
            print("Key already in Pageant")
            return 0
        if add_rsa_key(agent, key):
            print("Key added to Pageant")
            return 0
        else:
            print("Pageant rejected the key", file=sys.stderr)
            return 1
    finally:
        agent.close()


if __name__ == "__main__":
    sys.exit(main())
