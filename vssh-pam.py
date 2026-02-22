#!/usr/bin/env python3
"""vssh-pam — SSH через PAM-туннель с автоматической аутентификацией.

Секреты хранятся в HashiCorp Vault:
  secret/pam/config       → PAM_HOST, PAM_PORT, PAM_USER
  secret/pam/credentials  → PAM_PASS, TOTP_SECRET
  secret/pam/servers      → servers (JSON массив)

Usage:
  vssh-pam <name>         Подключиться к серверу (fuzzy match)
  vssh-pam list           Список серверов
  vssh-pam init           Импорт .env → Vault
  vssh-pam vault          Показать содержимое Vault (пароли замаскированы)
"""

import sys
import os
import json
import subprocess
import time
import threading
import socket

import paramiko
import pyotp

# --- Vault helpers ---

def vault_get(path):
    """Получить секрет из Vault (KV v1 или v2). Возвращает dict полей."""
    try:
        result = subprocess.run(
            ["vault", "kv", "get", "-format=json", path],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return None
        data = json.loads(result.stdout)
        inner = data.get("data", {})
        # KV v2 имеет вложенный data.data, KV v1 — данные сразу в data
        if "data" in inner and "metadata" in inner:
            return inner["data"]
        return inner
    except Exception:
        return None


def vault_put(path, fields):
    """Записать секрет в Vault (KV v2). fields — dict."""
    args = ["vault", "kv", "put", path]
    for k, v in fields.items():
        args.append(f"{k}={v}")
    result = subprocess.run(args, capture_output=True, text=True, timeout=10)
    return result.returncode == 0


# --- Config loading ---

def load_config():
    """Загрузить конфигурацию PAM из Vault."""
    config = vault_get("secret/pam/config")
    if not config:
        print("Ошибка: secret/pam/config не найден в Vault")
        print("Запустите: vssh-pam init")
        sys.exit(1)

    creds = vault_get("secret/pam/credentials")
    if not creds:
        print("Ошибка: secret/pam/credentials не найден в Vault")
        print("Запустите: vssh-pam init")
        sys.exit(1)

    return {
        "pam_host": config.get("PAM_HOST", ""),
        "pam_port": int(config.get("PAM_PORT", "2222")),
        "pam_user": config.get("PAM_USER", ""),
        "pam_pass": creds.get("PAM_PASS", ""),
        "totp_secret": creds.get("TOTP_SECRET", ""),
    }


def load_servers():
    """Загрузить список серверов из Vault."""
    data = vault_get("secret/pam/servers")
    if not data or "servers" not in data:
        return []
    try:
        return json.loads(data["servers"])
    except (json.JSONDecodeError, TypeError):
        return []


# --- TOTP ---

def generate_totp(secret):
    """Сгенерировать TOTP-код с ожиданием если < 3с до истечения."""
    totp = pyotp.TOTP(secret)
    code = totp.now()
    remaining = totp.interval - (int(time.time()) % totp.interval)
    if remaining < 3:
        print(f"  Жду новый TOTP-код ({remaining}с)...", flush=True)
        time.sleep(remaining + 1)
        code = totp.now()
    return code


# --- SSH auth ---

def make_handler(password, totp_code):
    """Keyboard-interactive handler для PAM (пароль + TOTP + выбор ресурса)."""
    sent = []

    def handler(title, instructions, prompt_list):
        if title and any(kw in title.lower() for kw in ("error", "locked", "unavailable", "limit")):
            raise paramiko.AuthenticationException(f"Сервер: {title.strip()}")
        answers = []
        for prompt, echo in prompt_list:
            pl = prompt.lower().strip()
            if "password" in pl or "пароль" in pl:
                if "password" in sent:
                    raise paramiko.AuthenticationException("Неверный пароль")
                answers.append(password)
                sent.append("password")
            elif any(kw in pl for kw in ("otp", "code", "token", "verification", "код")):
                if "totp" in sent:
                    raise paramiko.AuthenticationException("Неверный OTP")
                answers.append(totp_code)
                sent.append("totp")
            elif "resource" in pl:
                answers.append("1")
                sent.append("resource")
            elif not sent:
                answers.append(password)
                sent.append("password")
            else:
                answers.append(totp_code)
                sent.append("totp")
        return answers

    return handler


def ssh_connect(cfg, hostname, ip, login):
    """Подключение через PAM SSH-туннель."""
    pam_login = f"{cfg['pam_user']}#{ip}#{hostname}\\{login}##"

    transport = paramiko.Transport((cfg["pam_host"], cfg["pam_port"]))
    transport.connect()
    transport.set_keepalive(30)

    totp_code = generate_totp(cfg["totp_secret"])

    try:
        handler = make_handler(cfg["pam_pass"], totp_code)
        transport.auth_interactive(pam_login, handler)
    except paramiko.AuthenticationException:
        transport.auth_password(pam_login, cfg["pam_pass"])

    if not transport.is_authenticated():
        transport.close()
        raise Exception("Аутентификация не пройдена")

    return transport


# --- Interactive shell ---

def interactive_shell(channel):
    """Интерактивная сессия: stdin → channel, channel → stdout."""
    try:
        import termios
        import tty
        import select
        _posix_shell(channel)
    except ImportError:
        _windows_shell(channel)


def _posix_shell(channel):
    """Unix/Git Bash: raw terminal + select."""
    import termios
    import tty
    import select

    oldtty = termios.tcgetattr(sys.stdin)
    try:
        tty.setraw(sys.stdin.fileno())
        tty.setcbreak(sys.stdin.fileno())
        channel.settimeout(0.0)

        while True:
            r, _, _ = select.select([channel, sys.stdin], [], [])
            if channel in r:
                try:
                    data = channel.recv(1024)
                    if not data:
                        break
                    sys.stdout.write(data.decode("utf-8", errors="replace"))
                    sys.stdout.flush()
                except socket.timeout:
                    pass
            if sys.stdin in r:
                x = sys.stdin.read(1)
                if not x:
                    break
                channel.send(x)
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, oldtty)


def _windows_shell(channel):
    """Windows: msvcrt для посимвольного ввода."""
    import msvcrt

    def writer():
        while True:
            try:
                data = channel.recv(1024)
                if not data:
                    break
                sys.stdout.write(data.decode("utf-8", errors="replace"))
                sys.stdout.flush()
            except (socket.timeout, OSError):
                break

    t = threading.Thread(target=writer, daemon=True)
    t.start()

    try:
        while True:
            if channel.closed:
                break
            if msvcrt.kbhit():
                ch = msvcrt.getch()
                if ch == b"\xe0" or ch == b"\x00":
                    ch2 = msvcrt.getch()
                    key_map = {
                        b"H": b"\x1b[A", b"P": b"\x1b[B",
                        b"M": b"\x1b[C", b"K": b"\x1b[D",
                    }
                    channel.send(key_map.get(ch2, b""))
                elif ch == b"\r":
                    channel.send(b"\n")
                else:
                    channel.send(ch)
            else:
                time.sleep(0.01)
    except (EOFError, OSError):
        pass


# --- Fuzzy match ---

def find_server(servers, query):
    """Найти сервер по имени: сначала точное совпадение, потом подстрока."""
    ql = query.lower()

    # Точное совпадение (case-insensitive)
    for s in servers:
        if s["hostname"].lower() == ql:
            return s

    # Подстрока (без разделителей)
    q = ql.replace("-", "").replace("_", "")
    matches = []
    for s in servers:
        name = s["hostname"].lower().replace("-", "").replace("_", "")
        if q in name:
            matches.append(s)

    if len(matches) == 1:
        return matches[0]
    elif len(matches) > 1:
        print(f"Найдено {len(matches)} серверов:")
        for i, s in enumerate(matches, 1):
            print(f"  {i}. {s['hostname']:<35} {s['ip']:<18} {s['login']}")
        try:
            choice = input(f"\nВыберите [1-{len(matches)}]: ").strip()
            idx = int(choice) - 1
            if 0 <= idx < len(matches):
                return matches[idx]
        except (ValueError, EOFError):
            pass
        return None
    else:
        print(f"Сервер не найден: {query}")
        print("Используйте 'vssh-pam list' для списка серверов")
        return None


# --- Commands ---

def cmd_connect(args):
    """Подключиться к серверу."""
    if not args:
        print("Usage: vssh-pam <hostname>")
        sys.exit(1)

    query = args[0]
    cfg = load_config()
    servers = load_servers()

    if not servers:
        print("Список серверов пуст. Запустите: vssh-pam init")
        sys.exit(1)

    srv = find_server(servers, query)
    if not srv:
        sys.exit(1)

    hostname = srv["hostname"]
    ip = srv["ip"]
    login = srv["login"]

    print(f"Подключение к {hostname} ({ip}) как {login}...")

    try:
        transport = ssh_connect(cfg, hostname, ip, login)
        print(f"Аутентификация OK. Открытие сессии...\n")

        channel = transport.open_session()
        channel.get_pty(term=os.environ.get("TERM", "xterm"), width=120, height=40)
        channel.invoke_shell()

        interactive_shell(channel)

        channel.close()
        transport.close()
    except Exception as e:
        print(f"Ошибка: {e}")
        sys.exit(1)


def cmd_list(args):
    """Список доступных серверов."""
    servers = load_servers()
    if not servers:
        print("Список серверов пуст. Запустите: vssh-pam init")
        return

    print(f"{'#':>3}  {'Сервер':<35} {'IP':<18} {'Логин':<15}")
    print("-" * 75)
    for i, s in enumerate(servers, 1):
        print(f"{i:>3}  {s['hostname']:<35} {s['ip']:<18} {s['login']:<15}")
    print(f"\nВсего: {len(servers)}")


def cmd_vault(args):
    """Показать содержимое Vault (маскированное)."""
    print("=== secret/pam/config ===")
    config = vault_get("secret/pam/config")
    if config:
        for k, v in config.items():
            print(f"  {k} = {v}")
    else:
        print("  (не найден)")

    print("\n=== secret/pam/credentials ===")
    creds = vault_get("secret/pam/credentials")
    if creds:
        for k, v in creds.items():
            if k in ("PAM_PASS", "TOTP_SECRET") and len(v) > 2:
                masked = v[0] + "*" * (len(v) - 2) + v[-1]
                print(f"  {k} = {masked} [{len(v)} символов]")
            else:
                print(f"  {k} = {v}")
    else:
        print("  (не найден)")

    print("\n=== secret/pam/servers ===")
    servers = load_servers()
    if servers:
        print(f"  Серверов: {len(servers)}")
    else:
        print("  (не найден)")


def cmd_init(args):
    """Импортировать секреты из .env в Vault."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    import_dir = os.environ.get("VSSH_PAM_IMPORT_DIR", script_dir)

    # 1. Загрузить .env
    env_path = os.path.join(import_dir, ".env")
    env = {}
    if os.path.exists(env_path):
        print(f"Читаю {env_path}...")
        with open(env_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                v = v.strip()
                if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
                    v = v[1:-1]
                env[k.strip()] = v
    else:
        print(f"Файл {env_path} не найден")
        sys.exit(1)

    # 2. Записать config
    config_fields = {}
    for key in ("PAM_HOST", "PAM_PORT", "PAM_USER"):
        if key in env:
            config_fields[key] = env[key]

    if config_fields:
        print(f"Записываю secret/pam/config... ({', '.join(config_fields.keys())})")
        if not vault_put("secret/pam/config", config_fields):
            print("  ОШИБКА записи!")
        else:
            print("  OK")

    # 3. Записать credentials
    cred_fields = {}
    for key in ("PAM_PASS", "TOTP_SECRET"):
        if key in env:
            cred_fields[key] = env[key]

    if cred_fields:
        print(f"Записываю secret/pam/credentials... ({', '.join(cred_fields.keys())})")
        if not vault_put("secret/pam/credentials", cred_fields):
            print("  ОШИБКА записи!")
        else:
            print("  OK")

    print("\nГотово! Проверьте: vssh-pam vault")


def usage():
    print("vssh-pam — SSH через PAM-туннель")
    print()
    print("Команды:")
    print("  vssh-pam <name>     Подключиться к серверу (fuzzy match)")
    print("  vssh-pam list       Список серверов")
    print("  vssh-pam init       Импорт .env → Vault")
    print("  vssh-pam vault      Показать содержимое Vault")
    sys.exit(0)


def main():
    if len(sys.argv) < 2:
        usage()

    cmd = sys.argv[1].lower()
    rest = sys.argv[2:]

    if cmd in ("help", "--help", "-h"):
        usage()
    elif cmd == "list":
        cmd_list(rest)
    elif cmd == "init":
        cmd_init(rest)
    elif cmd == "vault":
        cmd_vault(rest)
    else:
        cmd_connect([sys.argv[1]] + rest)


if __name__ == "__main__":
    main()
