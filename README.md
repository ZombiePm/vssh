# vssh

SSH wrapper for secure, keyless connections using HashiCorp Vault. Private keys are fetched from Vault at connection time, loaded into memory, and never written to disk. On Windows, keys are automatically added to Pageant (PuTTY agent).

## Components

### vssh

Bash wrapper for standard SSH that fetches private keys from Vault and loads them into a temporary `ssh-agent`. The agent is destroyed on exit, keys exist only in RAM.

```
vssh <host> [ssh args...]
```

**How it works:**

1. Reads Vault address and key path from `~/.ssh/config`
2. Fetches the private key from Vault (`vault kv get`)
3. Loads it into a temporary `ssh-agent` via pipe (never touches disk)
4. On Windows: adds the key to Pageant via SSH agent protocol
5. Connects via standard `ssh`
6. On exit: kills the temporary agent, key is gone from memory

### vssh-pam

Python wrapper for SSH through a PAM-authenticated tunnel with automatic TOTP generation. Designed for enterprise environments where SSH access goes through a PAM proxy with multi-factor authentication.

```
vssh-pam <hostname>     # Connect (fuzzy match)
vssh-pam list           # List available servers
vssh-pam init           # Import .env + CSV into Vault
vssh-pam vault          # Show Vault contents (passwords masked)
```

**Features:**
- Automatic TOTP code generation (waits if code is about to expire)
- Fuzzy server name matching (case-insensitive, ignores `-` and `_`)
- Keyboard-interactive authentication (password + OTP)
- Cross-platform terminal handling (POSIX and Windows)
- All credentials stored in Vault, nothing on disk

### vssh-pageant.py

Helper that adds SSH keys directly to Pageant using the SSH agent protocol via shared memory IPC. No temp files, no `puttygen` conversion needed.

```
vault kv get -field=private_key secret/ssh/key | python vssh-pageant.py
```

## Configuration

All `vssh` settings live in `~/.ssh/config` as comment directives:

```ssh-config
# Global settings (top of file):
# vssh:vault_addr https://vault.example.com
# vssh:default_vault_key secret/ssh/default-key

# Per-host Vault key override (inside Host block):
Host production
    HostName 198.51.100.100
    User deploy
    # vssh:vault_path secret/ssh/prod-key
```

See `ssh_config.example` for a full example.

### vssh-pam configuration

Stored in Vault:

| Path | Fields |
|------|--------|
| `secret/pam/config` | `PAM_HOST`, `PAM_PORT`, `PAM_USER` |
| `secret/pam/credentials` | `PAM_PASS`, `TOTP_SECRET` |
| `secret/pam/servers` | `servers` (JSON array) |

Server entry format:
```json
{"hostname": "server-1", "ip": "10.0.1.1", "login": "admin", "password": "pass"}
```

## Requirements

- Bash (Git Bash / MSYS2 / Linux / macOS)
- [HashiCorp Vault](https://www.vaultproject.io/) CLI, authenticated (`vault login`)
- OpenSSH client (`ssh`, `ssh-agent`, `ssh-add`)

**vssh-pam additionally requires:**
- Python 3
- `paramiko` (`pip install paramiko`)
- `pyotp` (`pip install pyotp`)

**Pageant integration (Windows) additionally requires:**
- `paramiko` (`pip install paramiko`)
- Pageant running (from [PuTTY](https://www.chiark.greenend.org.uk/~sgtatham/putty/))

## Installation

```bash
# Clone
git clone https://github.com/aeve-co/vssh.git

# Add to PATH (e.g. copy to ~/bin or symlink)
cp vssh vssh-pam vssh-pam.py vssh-pageant.py ~/bin/

# Install Python dependencies (for vssh-pam and Pageant integration)
pip install paramiko pyotp
```

## Security

- Private keys never touch disk — fetched from Vault and piped directly into the agent
- Each `vssh` session uses an isolated, temporary `ssh-agent` that is killed on exit
- Pageant receives keys via IPC (shared memory), no intermediate files
- Vault token is the single point of authentication — revoke it to cut off access
- `.gitignore` excludes `*.pem`, `*.ppk`, `*.key`, `.env`, `.vault-token`

---

## Support

| Network  | Address |
|----------|---------|
| **SOL**  | `BMvNKNK7zTRc6jQsdyUKFE6wFL6TJMKL1ZSRhW6pCpNJ` |
| **ETH**  | `0x743d66E349270355200b958FC1caC8427a9efe04` |
| **BTC**  | `bc1qset463vqdydrgpxy4m5hvke0cqvtlqztqrqw2v` |
