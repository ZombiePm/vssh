# vssh — SSH with keys from HashiCorp Vault (zero keys on disk)

`vssh` is a bash wrapper around `ssh` that fetches private keys from [HashiCorp Vault](https://www.vaultproject.io/) and loads them directly into `ssh-agent` memory. **Private keys are never written to disk** — not even as temporary files.

## How it works

```
vault kv get ──► pipe ──► ssh-add - ──► ssh-agent (RAM only)
                                              │
                                         ssh connects
                                              │
                                        agent is killed
```

1. `vssh` reads the Vault path for the requested host from `~/.ssh/config`
2. Fetches the private key from Vault via `vault kv get`
3. Pipes it directly into `ssh-add -`, which loads the key into a temporary `ssh-agent`
4. Connects via `ssh` — the agent provides the key
5. On exit, the temporary agent (and the key in its memory) is destroyed

## Configuration

All configuration lives in a single file: `~/.ssh/config`. No separate config files needed.

### Global settings

Add these comments at the top of your `~/.ssh/config`:

```
# vssh:vault_addr https://vault.example.com
# vssh:default_vault_key secret/ssh/default-key
```

| Directive | Description |
|---|---|
| `vssh:vault_addr` | Vault server URL (can also be set via `VAULT_ADDR` env var) |
| `vssh:default_vault_key` | Vault path used when a host has no explicit `vssh:vault_path` |

### Per-host key mapping

To use a specific Vault key for a host, add a `vssh:vault_path` comment inside the `Host` block:

```
Host my-server
    HostName 203.0.113.10
    User deploy
    Port 2222
    # vssh:vault_path secret/ssh/my-server-key
```

Hosts without `vssh:vault_path` use the `default_vault_key`.

### Full example

See [ssh_config.example](ssh_config.example) for a complete example.

## Usage

```bash
# Connect to a host
vssh my-server

# Run a remote command
vssh my-server uptime

# Port forwarding
vssh my-server -L 8080:localhost:80

# List available hosts
vssh
```

## Setup

### Prerequisites

- **bash** (v4+)
- **ssh** with **ssh-agent** and **ssh-add**
- **[HashiCorp Vault CLI](https://developer.hashicorp.com/vault/install)**

### 1. Store SSH keys in Vault

```bash
# Enable KV v2 secrets engine (if not already enabled)
vault secrets enable -path=secret kv-v2

# Store a private key
vault kv put secret/ssh/my-key private_key=@~/.ssh/my_key.pem

# Verify
vault kv get -field=private_key secret/ssh/my-key
```

The key is stored under the `private_key` field. You can delete the local key file after uploading.

### 2. Install vssh

#### Linux

```bash
# Copy the script
sudo cp vssh /usr/local/bin/vssh
chmod +x /usr/local/bin/vssh

# Or install to ~/bin (make sure ~/bin is in PATH)
mkdir -p ~/bin
cp vssh ~/bin/vssh
chmod +x ~/bin/vssh
```

#### Windows (Git Bash)

Git for Windows includes bash, ssh-agent, and all required utilities.

```bash
# Create ~/bin if it doesn't exist
mkdir -p ~/bin

# Copy the script
cp vssh ~/bin/vssh
chmod +x ~/bin/vssh
```

Make sure `~/bin` is in your `PATH`. Add this to `~/.bashrc` or `~/.bash_profile` if needed:

```bash
export PATH="$HOME/bin:$PATH"
```

### 3. Configure ~/.ssh/config

Add the global vssh settings and host definitions:

```
# vssh:vault_addr https://vault.example.com
# vssh:default_vault_key secret/ssh/default-key

Host my-server
    HostName 203.0.113.10
    User deploy

Host special-server
    HostName 198.51.100.50
    User root
    # vssh:vault_path secret/ssh/special-key
```

### 4. Log in to Vault

```bash
# Token auth
vault login

# Or LDAP, OIDC, etc.
vault login -method=ldap username=you
vault login -method=oidc
```

### 5. Connect

```bash
vssh my-server
```

## How keys are stored in Vault

Each key is a KV v2 secret with a `private_key` field containing the PEM-encoded private key:

```
Path:   secret/ssh/my-key
Field:  private_key
Value:  -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA...
        -----END RSA PRIVATE KEY-----
```

### Bulk upload example

```bash
# Upload all .pem files from a directory
for f in /path/to/keys/*.pem; do
    name=$(basename "$f" .pem)
    vault kv put "secret/ssh/${name}" private_key=@"$f"
    echo "Uploaded: $name"
done
```

## Notes

- Each `vssh` invocation starts its own isolated `ssh-agent` — no interference with other sessions
- The agent is killed automatically on exit (including on errors or Ctrl+C)
- Works on both Linux and Windows (Git Bash / MSYS2) — CRLF line endings in `~/.ssh/config` are handled automatically
- Standard SSH config directives (`HostName`, `User`, `Port`, `ProxyJump`, etc.) work as usual — `vssh` only adds the key management layer
- `VAULT_ADDR` environment variable takes precedence over the config comment

## License

MIT
