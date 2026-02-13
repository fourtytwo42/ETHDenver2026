#!/usr/bin/env python3
"""X-Claw agent runtime CLI scaffold.

This CLI provides the command surface required by the X-Claw skill wrapper.
Wallet core operations are implemented with encrypted-at-rest storage.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import pathlib
import re
import secrets
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
try:
    from argon2.low_level import Type, hash_secret_raw
except Exception:  # pragma: no cover - handled by runtime dependency check
    Type = None  # type: ignore[assignment]
    hash_secret_raw = None  # type: ignore[assignment]

try:
    from Crypto.Hash import keccak
except Exception:  # pragma: no cover - handled by runtime dependency check
    keccak = None  # type: ignore[assignment]

APP_DIR = pathlib.Path(os.environ.get("XCLAW_AGENT_HOME", str(pathlib.Path.home() / ".xclaw-agent")))
STATE_FILE = APP_DIR / "state.json"
WALLET_STORE_FILE = APP_DIR / "wallets.json"

WALLET_STORE_VERSION = 1
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 1
ARGON2_HASH_LEN = 32
CHALLENGE_TTL_SECONDS = 300
CHALLENGE_FORMAT_VERSION = "xclaw-auth-v1"
CHALLENGE_REQUIRED_KEYS = {"domain", "chain", "nonce", "timestamp", "action"}
CHALLENGE_ALLOWED_DOMAINS = {"xclaw.trade", "localhost", "127.0.0.1", "::1", "staging.xclaw.trade"}


class WalletStoreError(Exception):
    """Wallet store is unavailable or invalid."""


class WalletSecurityError(Exception):
    """Wallet security checks failed."""


class WalletPassphraseError(Exception):
    """Wallet passphrase input is unavailable or invalid."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def emit(payload: dict) -> int:
    print(json.dumps(payload, separators=(",", ":")))
    return 0


def ok(message: str, **extra: object) -> int:
    payload = {"ok": True, "code": "ok", "message": message}
    payload.update(extra)
    return emit(payload)


def fail(code: str, message: str, action_hint: str | None = None, details: dict | None = None, exit_code: int = 1) -> int:
    payload: dict[str, object] = {"ok": False, "code": code, "message": message}
    if action_hint:
        payload["actionHint"] = action_hint
    if details:
        payload["details"] = details
    emit(payload)
    return exit_code


def require_json_flag(args: argparse.Namespace) -> int | None:
    if getattr(args, "json", False):
        return None
    return fail("missing_flag", "This command requires --json output mode.", "Re-run with --json.", exit_code=2)


def ensure_app_dir() -> None:
    APP_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(APP_DIR, 0o700)


def _is_secure_permissions(path: pathlib.Path, expected_mode: int) -> bool:
    if os.name == "nt":
        return True
    mode = stat.S_IMODE(path.stat().st_mode)
    return mode == expected_mode


def _assert_secure_permissions(path: pathlib.Path, expected_mode: int, kind: str) -> None:
    if not path.exists():
        return
    if not _is_secure_permissions(path, expected_mode):
        raise WalletSecurityError(
            f"Unsafe {kind} permissions for '{path}'. Expected {oct(expected_mode)} owner-only permissions."
        )


def _read_json(path: pathlib.Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise WalletStoreError(f"Invalid JSON in '{path}': {exc}") from exc


def _write_json(path: pathlib.Path, payload: dict[str, Any]) -> None:
    ensure_app_dir()
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if os.name != "nt":
        os.chmod(path, 0o600)


def load_state() -> dict[str, Any]:
    if not STATE_FILE.exists():
        return {}
    return _read_json(STATE_FILE)


def save_state(state: dict[str, Any]) -> None:
    _write_json(STATE_FILE, state)


def _default_wallet_store() -> dict[str, Any]:
    return {
        "version": WALLET_STORE_VERSION,
        "defaultWalletId": None,
        "wallets": {},
        "chains": {},
    }


def load_wallet_store() -> dict[str, Any]:
    ensure_app_dir()
    _assert_secure_permissions(APP_DIR, 0o700, "directory")
    if not WALLET_STORE_FILE.exists():
        return _default_wallet_store()
    _assert_secure_permissions(WALLET_STORE_FILE, 0o600, "wallet store file")
    data = _read_json(WALLET_STORE_FILE)
    if not isinstance(data, dict):
        raise WalletStoreError("Wallet store must be a JSON object.")
    version = data.get("version")
    if version != WALLET_STORE_VERSION:
        raise WalletStoreError(f"Unsupported wallet store version: {version}")
    if not isinstance(data.get("wallets"), dict) or not isinstance(data.get("chains"), dict):
        raise WalletStoreError("Wallet store missing required maps: wallets/chains.")
    return data


def save_wallet_store(store: dict[str, Any]) -> None:
    _write_json(WALLET_STORE_FILE, store)


def ensure_wallet_entry(chain: str) -> tuple[dict[str, Any], dict[str, Any]]:
    state = load_state()
    wallets = state.setdefault("wallets", {})
    wallet = wallets.get(chain)
    return state, wallet or {}


def set_wallet_entry(chain: str, wallet: dict[str, Any]) -> None:
    state = load_state()
    wallets = state.setdefault("wallets", {})
    wallets[chain] = wallet
    save_state(state)


def remove_wallet_entry(chain: str) -> bool:
    existed = False

    state = load_state()
    wallets = state.setdefault("wallets", {})
    if chain in wallets:
        wallets.pop(chain, None)
        save_state(state)
        existed = True

    try:
        store = load_wallet_store()
    except (WalletStoreError, WalletSecurityError):
        return existed

    chains = store.setdefault("chains", {})
    wallet_id = chains.pop(chain, None)
    if wallet_id:
        existed = True
        in_use = wallet_id in chains.values()
        if not in_use:
            store.setdefault("wallets", {}).pop(wallet_id, None)
            if store.get("defaultWalletId") == wallet_id:
                store["defaultWalletId"] = None
        save_wallet_store(store)

    return existed


def is_hex_address(value: str) -> bool:
    return bool(re.fullmatch(r"0x[a-fA-F0-9]{40}", value))


def _normalize_private_key_hex(value: str) -> str | None:
    stripped = value.strip()
    if stripped.startswith("0x"):
        stripped = stripped[2:]
    if re.fullmatch(r"[a-fA-F0-9]{64}", stripped):
        return stripped.lower()
    return None


def cast_exists() -> bool:
    return shutil.which("cast") is not None


def _derive_address(private_key_hex: str) -> str:
    if keccak is None:
        raise WalletStoreError("Missing dependency: pycryptodome (Crypto.Hash.keccak).")
    private_key_bytes = bytes.fromhex(private_key_hex)
    private_value = int.from_bytes(private_key_bytes, byteorder="big")
    # cryptography validates private key range for secp256k1.
    private_key = ec.derive_private_key(private_value, ec.SECP256K1())
    public_key_bytes = private_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    digest = keccak.new(digest_bits=256)
    digest.update(public_key_bytes[1:])
    return "0x" + digest.digest()[-20:].hex()


def _derive_aes_key(passphrase: str, salt: bytes) -> bytes:
    if hash_secret_raw is None or Type is None:
        raise WalletStoreError("Missing dependency: argon2-cffi.")
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )


def _encrypt_private_key(private_key_hex: str, passphrase: str) -> dict[str, Any]:
    private_key_bytes = bytes.fromhex(private_key_hex)
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = _derive_aes_key(passphrase, salt)
    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(nonce, private_key_bytes, None)
    return {
        "version": 1,
        "enc": "aes-256-gcm",
        "kdf": "argon2id",
        "kdfParams": {
            "timeCost": ARGON2_TIME_COST,
            "memoryCost": ARGON2_MEMORY_COST,
            "parallelism": ARGON2_PARALLELISM,
            "hashLen": ARGON2_HASH_LEN,
        },
        "saltB64": base64.b64encode(salt).decode("ascii"),
        "nonceB64": base64.b64encode(nonce).decode("ascii"),
        "ciphertextB64": base64.b64encode(ciphertext).decode("ascii"),
    }


def _decrypt_private_key(entry: dict[str, Any], passphrase: str) -> bytes:
    crypto = entry.get("crypto")
    if not isinstance(crypto, dict):
        raise WalletStoreError("Wallet entry missing crypto object.")

    try:
        salt = base64.b64decode(crypto["saltB64"])
        nonce = base64.b64decode(crypto["nonceB64"])
        ciphertext = base64.b64decode(crypto["ciphertextB64"])
    except Exception as exc:
        raise WalletStoreError("Wallet crypto payload is not valid base64.") from exc

    if len(salt) != 16 or len(nonce) != 12 or len(ciphertext) < 16:
        raise WalletStoreError("Wallet crypto payload has invalid lengths.")

    key = _derive_aes_key(passphrase, salt)
    cipher = AESGCM(key)
    return cipher.decrypt(nonce, ciphertext, None)


def _validate_wallet_entry_shape(entry: dict[str, Any]) -> None:
    if not isinstance(entry, dict):
        raise WalletStoreError("Wallet entry is not an object.")
    address = entry.get("address")
    if not isinstance(address, str) or not is_hex_address(address):
        raise WalletStoreError("Wallet entry address is missing or invalid.")
    crypto = entry.get("crypto")
    if not isinstance(crypto, dict):
        raise WalletStoreError("Wallet entry crypto payload is missing.")

    required_crypto_fields = ["enc", "kdf", "kdfParams", "saltB64", "nonceB64", "ciphertextB64"]
    missing = [k for k in required_crypto_fields if k not in crypto]
    if missing:
        raise WalletStoreError(f"Wallet entry crypto payload missing fields: {', '.join(missing)}")

    if crypto.get("enc") != "aes-256-gcm" or crypto.get("kdf") != "argon2id":
        raise WalletStoreError("Wallet entry crypto algorithm metadata is invalid.")
    try:
        salt = base64.b64decode(str(crypto.get("saltB64", "")))
        nonce = base64.b64decode(str(crypto.get("nonceB64", "")))
        ciphertext = base64.b64decode(str(crypto.get("ciphertextB64", "")))
    except Exception as exc:
        raise WalletStoreError("Wallet crypto payload is not valid base64.") from exc
    if len(salt) != 16 or len(nonce) != 12 or len(ciphertext) < 16:
        raise WalletStoreError("Wallet crypto payload has invalid lengths.")


def _interactive_required() -> bool:
    return sys.stdin.isatty() and sys.stderr.isatty()


def _prompt_passphrase() -> str:
    first = getpass.getpass("Wallet passphrase: ").strip()
    second = getpass.getpass("Confirm wallet passphrase: ").strip()
    if not first:
        raise ValueError("Passphrase cannot be empty.")
    if first != second:
        raise ValueError("Passphrase confirmation mismatch.")
    return first


def _prompt_existing_passphrase() -> str:
    value = getpass.getpass("Wallet passphrase: ").strip()
    if not value:
        raise WalletPassphraseError("Passphrase cannot be empty.")
    return value


def _chain_wallet(store: dict[str, Any], chain: str) -> tuple[str | None, dict[str, Any] | None]:
    wallet_id = store.setdefault("chains", {}).get(chain)
    if not wallet_id:
        return None, None
    wallet = store.setdefault("wallets", {}).get(wallet_id)
    if not isinstance(wallet, dict):
        return wallet_id, None
    return wallet_id, wallet


def _bind_chain_to_wallet(store: dict[str, Any], chain: str, wallet_id: str) -> None:
    store.setdefault("chains", {})[chain] = wallet_id


def _new_wallet_id() -> str:
    return f"wlt_{secrets.token_hex(10)}"


def _require_wallet_passphrase_for_signing(chain: str) -> str:
    env_passphrase = os.environ.get("XCLAW_WALLET_PASSPHRASE")
    if isinstance(env_passphrase, str) and env_passphrase.strip():
        return env_passphrase
    if not _interactive_required():
        raise WalletPassphraseError(
            f"wallet.sign-challenge requires XCLAW_WALLET_PASSPHRASE in non-interactive mode for chain '{chain}'."
        )
    return _prompt_existing_passphrase()


def _parse_challenge_timestamp(value: str) -> datetime:
    parsed_raw = value.strip()
    if parsed_raw.endswith("Z"):
        parsed_raw = parsed_raw[:-1] + "+00:00"
    parsed = datetime.fromisoformat(parsed_raw)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone.")
    if parsed.utcoffset() != timedelta(0):
        raise ValueError("timestamp must be UTC (Z or +00:00).")
    parsed_utc = parsed.astimezone(timezone.utc)
    return parsed_utc


def _validate_challenge_timestamp(timestamp_value: str, now_utc: datetime | None = None) -> datetime:
    parsed = _parse_challenge_timestamp(timestamp_value)
    reference = now_utc or datetime.now(timezone.utc)
    delta_seconds = abs((reference - parsed).total_seconds())
    if delta_seconds > CHALLENGE_TTL_SECONDS:
        raise ValueError("timestamp is outside 5-minute nonce TTL window.")
    return parsed


def _parse_canonical_challenge(message: str, expected_chain: str) -> dict[str, str]:
    pairs: dict[str, str] = {}
    for idx, raw_line in enumerate(message.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        if "=" not in line:
            raise ValueError(f"line {idx} must use key=value format.")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key in pairs:
            raise ValueError(f"duplicate key '{key}'.")
        if key not in CHALLENGE_REQUIRED_KEYS:
            raise ValueError(f"unexpected key '{key}'.")
        pairs[key] = value

    missing = sorted(CHALLENGE_REQUIRED_KEYS - set(pairs.keys()))
    if missing:
        raise ValueError(f"missing required keys: {', '.join(missing)}")

    domain = pairs["domain"]
    if domain not in CHALLENGE_ALLOWED_DOMAINS:
        raise ValueError("domain is not in the allowlist.")

    if pairs["chain"] != expected_chain:
        raise ValueError("chain does not match command --chain.")

    nonce = pairs["nonce"]
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", nonce):
        raise ValueError("nonce must be 16..128 chars of [A-Za-z0-9_-].")

    if not pairs["action"].strip():
        raise ValueError("action cannot be empty.")

    _validate_challenge_timestamp(pairs["timestamp"])
    return pairs


def _cast_sign_message(private_key_hex: str, message: str) -> str:
    cast_bin = shutil.which("cast")
    if not cast_bin:
        raise WalletStoreError("Missing dependency: cast.")

    proc = subprocess.run(
        [cast_bin, "wallet", "sign", "--private-key", private_key_hex, message],
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        raise WalletStoreError(stderr or "cast wallet sign failed.")

    signature = (proc.stdout or "").strip()
    if not re.fullmatch(r"0x[a-fA-F0-9]{130}", signature):
        raise WalletStoreError("cast returned malformed signature output.")
    return signature


def cmd_status(args: argparse.Namespace) -> int:
    chk = require_json_flag(args)
    if chk is not None:
        return chk
    return ok("Agent runtime scaffold is healthy.", status="ready", timestamp=utc_now(), scaffold=True)


def cmd_not_implemented(args: argparse.Namespace, name: str) -> int:
    chk = require_json_flag(args)
    if chk is not None:
        return chk
    return fail(
        "not_implemented",
        f"{name} is scaffolded but not fully implemented yet.",
        "Implement runtime handler in apps/agent-runtime/xclaw_agent/cli.py and re-test.",
        {"command": name, "scaffold": True},
        exit_code=1,
    )


def cmd_wallet_health(args: argparse.Namespace) -> int:
    chk = require_json_flag(args)
    if chk is not None:
        return chk

    chain = args.chain
    has_wallet = False
    address: str | None = None
    metadata_valid = True
    permission_safe = True
    integrity_checked = False

    try:
        ensure_app_dir()
        _assert_secure_permissions(APP_DIR, 0o700, "directory")
        if STATE_FILE.exists():
            _assert_secure_permissions(STATE_FILE, 0o600, "state file")
        if WALLET_STORE_FILE.exists():
            _assert_secure_permissions(WALLET_STORE_FILE, 0o600, "wallet store file")

        store = load_wallet_store()
        wallet_id, wallet = _chain_wallet(store, chain)
        if wallet_id:
            if wallet is None:
                raise WalletStoreError(f"Chain '{chain}' points to missing wallet id '{wallet_id}'.")
            _validate_wallet_entry_shape(wallet)
            has_wallet = True
            address = wallet.get("address")

            probe_passphrase = os.environ.get("XCLAW_WALLET_PASSPHRASE")
            if probe_passphrase:
                plaintext = _decrypt_private_key(wallet, probe_passphrase)
                derived = _derive_address(plaintext.hex())
                if derived.lower() != str(address).lower():
                    raise WalletStoreError("Wallet encrypted payload does not match stored address.")
                integrity_checked = True
        else:
            # Legacy fallback for Slice 03 state shape.
            _, legacy_wallet = ensure_wallet_entry(chain)
            legacy_address = legacy_wallet.get("address")
            if isinstance(legacy_address, str) and is_hex_address(legacy_address):
                has_wallet = True
                address = legacy_address

    except WalletSecurityError as exc:
        permission_safe = False
        return fail("unsafe_permissions", str(exc), "Restrict permissions to owner-only (0700/0600) and retry.", {"chain": chain}, exit_code=1)
    except WalletStoreError as exc:
        metadata_valid = False
        return fail("wallet_store_invalid", str(exc), "Repair or remove invalid wallet metadata and retry.", {"chain": chain}, exit_code=1)
    except Exception as exc:
        metadata_valid = False
        return fail("wallet_health_failed", str(exc), "Inspect wallet files and retry wallet health.", {"chain": chain}, exit_code=1)

    return ok(
        "Wallet health checked.",
        chain=chain,
        hasCast=cast_exists(),
        hasWallet=has_wallet,
        address=address,
        metadataValid=metadata_valid,
        filePermissionsSafe=permission_safe,
        integrityChecked=integrity_checked,
        timestamp=utc_now(),
    )


def cmd_wallet_create(args: argparse.Namespace) -> int:
    chk = require_json_flag(args)
    if chk is not None:
        return chk

    if not _interactive_required():
        return fail(
            "non_interactive",
            "wallet.create requires an interactive TTY for secure passphrase input.",
            "Run the command in a terminal session with TTY attached.",
            {"chain": args.chain},
            exit_code=2,
        )

    try:
        passphrase = _prompt_passphrase()
        store = load_wallet_store()

        chain = args.chain
        wallet_id, wallet = _chain_wallet(store, chain)
        if wallet_id and wallet:
            return fail(
                "wallet_exists",
                f"Wallet already configured for chain '{chain}'.",
                "Use wallet address/health or wallet remove before creating again.",
                {"chain": chain, "address": wallet.get("address")},
                exit_code=1,
            )

        default_wallet_id = store.get("defaultWalletId")
        if isinstance(default_wallet_id, str) and default_wallet_id:
            default_wallet = store.setdefault("wallets", {}).get(default_wallet_id)
            if not isinstance(default_wallet, dict):
                raise WalletStoreError("defaultWalletId points to a missing wallet record.")
            _validate_wallet_entry_shape(default_wallet)
            _bind_chain_to_wallet(store, chain, default_wallet_id)
            save_wallet_store(store)
            set_wallet_entry(chain, {"address": default_wallet.get("address"), "walletId": default_wallet_id})
            return ok("Existing portable wallet bound to chain.", chain=chain, address=default_wallet.get("address"), created=False)

        private_key = ec.generate_private_key(ec.SECP256K1())
        private_value = private_key.private_numbers().private_value
        private_key_hex = private_value.to_bytes(32, "big").hex()
        address = _derive_address(private_key_hex)

        wallet_id = _new_wallet_id()
        encrypted = _encrypt_private_key(private_key_hex, passphrase)
        store.setdefault("wallets", {})[wallet_id] = {
            "walletId": wallet_id,
            "address": address,
            "createdAt": utc_now(),
            "crypto": encrypted,
        }
        store["defaultWalletId"] = wallet_id
        _bind_chain_to_wallet(store, chain, wallet_id)

        save_wallet_store(store)
        set_wallet_entry(chain, {"address": address, "walletId": wallet_id})
        return ok("Wallet created.", chain=chain, address=address, created=True)

    except ValueError as exc:
        return fail("invalid_input", str(exc), "Provide matching non-empty passphrase values.", {"chain": args.chain}, exit_code=2)
    except WalletSecurityError as exc:
        return fail("unsafe_permissions", str(exc), "Restrict permissions to owner-only (0700/0600) and retry.", {"chain": args.chain}, exit_code=1)
    except WalletStoreError as exc:
        return fail("wallet_store_invalid", str(exc), "Repair wallet store metadata and retry.", {"chain": args.chain}, exit_code=1)
    except Exception as exc:
        return fail("wallet_create_failed", str(exc), "Inspect runtime wallet dependencies/configuration and retry.", {"chain": args.chain}, exit_code=1)


def cmd_wallet_import(args: argparse.Namespace) -> int:
    chk = require_json_flag(args)
    if chk is not None:
        return chk

    if not _interactive_required():
        return fail(
            "non_interactive",
            "wallet.import requires an interactive TTY for secure secret input.",
            "Run the command in a terminal session with TTY attached.",
            {"chain": args.chain},
            exit_code=2,
        )

    try:
        private_key_input = getpass.getpass("Private key (hex, optional 0x): ")
        private_key_hex = _normalize_private_key_hex(private_key_input)
        if private_key_hex is None:
            return fail(
                "invalid_input",
                "Private key must be 32-byte hex (64 chars, optional 0x prefix).",
                "Provide a valid EVM private key hex string.",
                {"chain": args.chain},
                exit_code=2,
            )

        address = _derive_address(private_key_hex)
        passphrase = _prompt_passphrase()

        store = load_wallet_store()
        chain = args.chain
        existing_id, existing_wallet = _chain_wallet(store, chain)
        if existing_id and existing_wallet:
            return fail(
                "wallet_exists",
                f"Wallet already configured for chain '{chain}'.",
                "Use wallet remove first if you want to replace the chain binding.",
                {"chain": chain, "address": existing_wallet.get("address")},
                exit_code=1,
            )

        default_wallet_id = store.get("defaultWalletId")
        if isinstance(default_wallet_id, str) and default_wallet_id:
            default_wallet = store.setdefault("wallets", {}).get(default_wallet_id)
            if not isinstance(default_wallet, dict):
                raise WalletStoreError("defaultWalletId points to a missing wallet record.")
            _validate_wallet_entry_shape(default_wallet)
            default_address = str(default_wallet.get("address", "")).lower()
            if default_address != address.lower():
                return fail(
                    "portable_wallet_conflict",
                    "Imported private key does not match existing portable default wallet.",
                    "Import the same portable key or remove existing wallet bindings first.",
                    {"chain": chain, "existingAddress": default_wallet.get("address"), "importAddress": address},
                    exit_code=1,
                )
            _bind_chain_to_wallet(store, chain, default_wallet_id)
            save_wallet_store(store)
            set_wallet_entry(chain, {"address": default_wallet.get("address"), "walletId": default_wallet_id})
            return ok("Portable wallet bound to chain.", chain=chain, address=default_wallet.get("address"), imported=True)

        wallet_id = _new_wallet_id()
        encrypted = _encrypt_private_key(private_key_hex, passphrase)
        store.setdefault("wallets", {})[wallet_id] = {
            "walletId": wallet_id,
            "address": address,
            "createdAt": utc_now(),
            "crypto": encrypted,
        }
        store["defaultWalletId"] = wallet_id
        _bind_chain_to_wallet(store, chain, wallet_id)

        save_wallet_store(store)
        set_wallet_entry(chain, {"address": address, "walletId": wallet_id})
        return ok("Wallet imported.", chain=chain, address=address, imported=True)

    except ValueError as exc:
        return fail("invalid_input", str(exc), "Provide matching non-empty passphrase values.", {"chain": args.chain}, exit_code=2)
    except WalletSecurityError as exc:
        return fail("unsafe_permissions", str(exc), "Restrict permissions to owner-only (0700/0600) and retry.", {"chain": args.chain}, exit_code=1)
    except WalletStoreError as exc:
        return fail("wallet_store_invalid", str(exc), "Repair wallet store metadata and retry.", {"chain": args.chain}, exit_code=1)
    except Exception as exc:
        return fail("wallet_import_failed", str(exc), "Inspect runtime wallet dependencies/configuration and retry.", {"chain": args.chain}, exit_code=1)


def cmd_wallet_address(args: argparse.Namespace) -> int:
    chk = require_json_flag(args)
    if chk is not None:
        return chk

    chain = args.chain
    try:
        store = load_wallet_store()
        _, wallet = _chain_wallet(store, chain)
        if wallet:
            address = wallet.get("address")
            if isinstance(address, str) and is_hex_address(address):
                return ok("Wallet address fetched.", chain=chain, address=address)

    except (WalletStoreError, WalletSecurityError) as exc:
        return fail("wallet_store_invalid", str(exc), "Repair wallet store metadata and retry.", {"chain": chain}, exit_code=1)

    _, legacy_wallet = ensure_wallet_entry(chain)
    addr = legacy_wallet.get("address")
    if not isinstance(addr, str) or not is_hex_address(addr):
        return fail("wallet_missing", f"No wallet configured for chain '{chain}'.", "Run wallet create/import first.", {"chain": chain}, exit_code=1)
    return ok("Wallet address fetched.", chain=chain, address=addr)


def cmd_wallet_sign_challenge(args: argparse.Namespace) -> int:
    chk = require_json_flag(args)
    if chk is not None:
        return chk
    if not args.message.strip():
        return fail(
            "invalid_input",
            "Challenge message cannot be empty.",
            "Provide a non-empty message string.",
            {"message": args.message},
            exit_code=2,
        )
    chain = args.chain
    try:
        store = load_wallet_store()
        _, wallet = _chain_wallet(store, chain)
        if wallet:
            _validate_wallet_entry_shape(wallet)
        else:
            return fail("wallet_missing", f"No wallet configured for chain '{chain}'.", "Run wallet create/import first.", {"chain": chain}, exit_code=1)

        try:
            _parse_canonical_challenge(args.message, chain)
        except ValueError as exc:
            return fail(
                "invalid_challenge_format",
                str(exc),
                "Provide canonical challenge lines: domain, chain, nonce, timestamp, action.",
                {"format": CHALLENGE_FORMAT_VERSION, "chain": chain},
                exit_code=2,
            )

        passphrase = _require_wallet_passphrase_for_signing(chain)
        private_key_bytes = _decrypt_private_key(wallet, passphrase)
        signature = _cast_sign_message(private_key_bytes.hex(), args.message)
        return ok(
            "Challenge signed.",
            chain=chain,
            address=wallet.get("address"),
            signature=signature,
            scheme="eip191_personal_sign",
            challengeFormat=CHALLENGE_FORMAT_VERSION,
        )

    except WalletPassphraseError as exc:
        return fail("non_interactive", str(exc), "Set XCLAW_WALLET_PASSPHRASE or run with TTY attached.", {"chain": chain}, exit_code=2)
    except WalletSecurityError as exc:
        return fail("unsafe_permissions", str(exc), "Restrict permissions to owner-only (0700/0600) and retry.", {"chain": chain}, exit_code=1)
    except WalletStoreError as exc:
        msg = str(exc)
        if "Missing dependency: cast" in msg:
            return fail(
                "missing_dependency",
                msg,
                "Install Foundry and ensure `cast` is on PATH.",
                {"dependency": "cast"},
                exit_code=1,
            )
        return fail("sign_failed", msg, "Verify wallet passphrase and cast runtime, then retry.", {"chain": chain}, exit_code=1)
    except Exception as exc:
        return fail("sign_failed", str(exc), "Inspect runtime wallet/signing configuration and retry.", {"chain": chain}, exit_code=1)


def cmd_wallet_send(args: argparse.Namespace) -> int:
    chk = require_json_flag(args)
    if chk is not None:
        return chk
    if not is_hex_address(args.to):
        return fail("invalid_input", "Invalid recipient address format.", "Use 0x-prefixed 20-byte hex address.", {"to": args.to}, exit_code=2)
    if not re.fullmatch(r"[0-9]+", args.amount_wei):
        return fail("invalid_input", "Invalid amount-wei format.", "Use base-unit integer string.", {"amountWei": args.amount_wei}, exit_code=2)
    return cmd_not_implemented(args, "wallet.send")


def cmd_wallet_balance(args: argparse.Namespace) -> int:
    chk = require_json_flag(args)
    if chk is not None:
        return chk
    return cmd_not_implemented(args, "wallet.balance")


def cmd_wallet_token_balance(args: argparse.Namespace) -> int:
    chk = require_json_flag(args)
    if chk is not None:
        return chk
    if not is_hex_address(args.token):
        return fail("invalid_input", "Invalid token address format.", "Use 0x-prefixed 20-byte hex address.", {"token": args.token}, exit_code=2)
    return cmd_not_implemented(args, "wallet.token-balance")


def cmd_wallet_remove(args: argparse.Namespace) -> int:
    chk = require_json_flag(args)
    if chk is not None:
        return chk
    existed = remove_wallet_entry(args.chain)
    return ok("Wallet removed." if existed else "No wallet existed for chain.", chain=args.chain, removed=existed)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="xclaw-agent", add_help=True)
    sub = p.add_subparsers(dest="top")

    st = sub.add_parser("status")
    st.add_argument("--json", action="store_true")
    st.set_defaults(func=cmd_status)

    intents = sub.add_parser("intents")
    intents_sub = intents.add_subparsers(dest="intents_cmd")
    intents_poll = intents_sub.add_parser("poll")
    intents_poll.add_argument("--chain", required=True)
    intents_poll.add_argument("--json", action="store_true")
    intents_poll.set_defaults(func=lambda a: cmd_not_implemented(a, "intents.poll"))

    approvals = sub.add_parser("approvals")
    approvals_sub = approvals.add_subparsers(dest="approvals_cmd")
    approvals_check = approvals_sub.add_parser("check")
    approvals_check.add_argument("--intent", required=True)
    approvals_check.add_argument("--chain", required=True)
    approvals_check.add_argument("--json", action="store_true")
    approvals_check.set_defaults(func=lambda a: cmd_not_implemented(a, "approvals.check"))

    trade = sub.add_parser("trade")
    trade_sub = trade.add_subparsers(dest="trade_cmd")
    trade_exec = trade_sub.add_parser("execute")
    trade_exec.add_argument("--intent", required=True)
    trade_exec.add_argument("--chain", required=True)
    trade_exec.add_argument("--json", action="store_true")
    trade_exec.set_defaults(func=lambda a: cmd_not_implemented(a, "trade.execute"))

    report = sub.add_parser("report")
    report_sub = report.add_subparsers(dest="report_cmd")
    report_send = report_sub.add_parser("send")
    report_send.add_argument("--trade", required=True)
    report_send.add_argument("--json", action="store_true")
    report_send.set_defaults(func=lambda a: cmd_not_implemented(a, "report.send"))

    offdex = sub.add_parser("offdex")
    offdex_sub = offdex.add_subparsers(dest="offdex_cmd")

    offdex_intents = offdex_sub.add_parser("intents")
    offdex_intents_sub = offdex_intents.add_subparsers(dest="offdex_intents_cmd")
    offdex_intents_poll = offdex_intents_sub.add_parser("poll")
    offdex_intents_poll.add_argument("--chain", required=True)
    offdex_intents_poll.add_argument("--json", action="store_true")
    offdex_intents_poll.set_defaults(func=lambda a: cmd_not_implemented(a, "offdex.intents.poll"))

    offdex_accept = offdex_sub.add_parser("accept")
    offdex_accept.add_argument("--intent", required=True)
    offdex_accept.add_argument("--chain", required=True)
    offdex_accept.add_argument("--json", action="store_true")
    offdex_accept.set_defaults(func=lambda a: cmd_not_implemented(a, "offdex.accept"))

    offdex_settle = offdex_sub.add_parser("settle")
    offdex_settle.add_argument("--intent", required=True)
    offdex_settle.add_argument("--chain", required=True)
    offdex_settle.add_argument("--json", action="store_true")
    offdex_settle.set_defaults(func=lambda a: cmd_not_implemented(a, "offdex.settle"))

    wallet = sub.add_parser("wallet")
    wallet_sub = wallet.add_subparsers(dest="wallet_cmd")

    w_health = wallet_sub.add_parser("health")
    w_health.add_argument("--chain", required=True)
    w_health.add_argument("--json", action="store_true")
    w_health.set_defaults(func=cmd_wallet_health)

    w_create = wallet_sub.add_parser("create")
    w_create.add_argument("--chain", required=True)
    w_create.add_argument("--json", action="store_true")
    w_create.set_defaults(func=cmd_wallet_create)

    w_import = wallet_sub.add_parser("import")
    w_import.add_argument("--chain", required=True)
    w_import.add_argument("--json", action="store_true")
    w_import.set_defaults(func=cmd_wallet_import)

    w_addr = wallet_sub.add_parser("address")
    w_addr.add_argument("--chain", required=True)
    w_addr.add_argument("--json", action="store_true")
    w_addr.set_defaults(func=cmd_wallet_address)

    w_sign = wallet_sub.add_parser("sign-challenge")
    w_sign.add_argument("--message", required=True)
    w_sign.add_argument("--chain", required=True)
    w_sign.add_argument("--json", action="store_true")
    w_sign.set_defaults(func=cmd_wallet_sign_challenge)

    w_send = wallet_sub.add_parser("send")
    w_send.add_argument("--to", required=True)
    w_send.add_argument("--amount-wei", required=True)
    w_send.add_argument("--chain", required=True)
    w_send.add_argument("--json", action="store_true")
    w_send.set_defaults(func=cmd_wallet_send)

    w_bal = wallet_sub.add_parser("balance")
    w_bal.add_argument("--chain", required=True)
    w_bal.add_argument("--json", action="store_true")
    w_bal.set_defaults(func=cmd_wallet_balance)

    w_tbal = wallet_sub.add_parser("token-balance")
    w_tbal.add_argument("--token", required=True)
    w_tbal.add_argument("--chain", required=True)
    w_tbal.add_argument("--json", action="store_true")
    w_tbal.set_defaults(func=cmd_wallet_token_balance)

    w_remove = wallet_sub.add_parser("remove")
    w_remove.add_argument("--chain", required=True)
    w_remove.add_argument("--json", action="store_true")
    w_remove.set_defaults(func=cmd_wallet_remove)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 2
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
