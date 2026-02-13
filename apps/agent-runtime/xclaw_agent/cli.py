#!/usr/bin/env python3
"""X-Claw agent runtime CLI scaffold.

This CLI provides the command surface required by the X-Claw skill wrapper.
Wallet core operations are implemented with encrypted-at-rest storage.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import pathlib
import re
import secrets
import shutil
import stat
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
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
POLICY_FILE = APP_DIR / "policy.json"
REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
CHAIN_CONFIG_DIR = REPO_ROOT / "config" / "chains"

WALLET_STORE_VERSION = 1
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 1
ARGON2_HASH_LEN = 32
CHALLENGE_TTL_SECONDS = 300
CHALLENGE_FORMAT_VERSION = "xclaw-auth-v1"
CHALLENGE_REQUIRED_KEYS = {"domain", "chain", "nonce", "timestamp", "action"}
CHALLENGE_ALLOWED_DOMAINS = {"xclaw.trade", "localhost", "127.0.0.1", "::1", "staging.xclaw.trade"}
RETRY_WINDOW_SEC = 600
MAX_TRADE_RETRIES = 3


class WalletStoreError(Exception):
    """Wallet store is unavailable or invalid."""


class WalletSecurityError(Exception):
    """Wallet security checks failed."""


class WalletPassphraseError(Exception):
    """Wallet passphrase input is unavailable or invalid."""


class WalletPolicyError(Exception):
    """Wallet policy precondition checks failed."""

    def __init__(self, code: str, message: str, action_hint: str | None = None, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.action_hint = action_hint
        self.details = details or {}


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


def _require_cast_bin() -> str:
    cast_bin = shutil.which("cast")
    if not cast_bin:
        raise WalletStoreError("Missing dependency: cast.")
    return cast_bin


def _load_chain_config(chain: str) -> dict[str, Any]:
    path = CHAIN_CONFIG_DIR / f"{chain}.json"
    if not path.exists():
        raise WalletStoreError(f"Chain config not found for '{chain}' at '{path}'.")
    data = _read_json(path)
    if not isinstance(data, dict):
        raise WalletStoreError(f"Chain config '{path}' must be a JSON object.")
    return data


def _chain_rpc_url(chain: str) -> str:
    cfg = _load_chain_config(chain)
    rpc = cfg.get("rpc")
    if not isinstance(rpc, dict):
        raise WalletStoreError(f"Chain config for '{chain}' is missing rpc object.")
    primary = rpc.get("primary")
    fallback = rpc.get("fallback")
    for candidate in [primary, fallback]:
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    raise WalletStoreError(f"Chain config for '{chain}' has no usable rpc URL.")


def _utc_day_key(now_utc: datetime | None = None) -> str:
    reference = now_utc or datetime.now(timezone.utc)
    return reference.astimezone(timezone.utc).strftime("%Y-%m-%d")


def _parse_uint_text(value: str) -> int:
    raw = value.strip()
    if re.fullmatch(r"[0-9]+", raw):
        return int(raw)
    if re.fullmatch(r"0x[a-fA-F0-9]+", raw):
        return int(raw, 16)
    raise WalletStoreError(f"Unable to parse uint value: '{value}'.")


def _extract_tx_hash(output: str) -> str:
    trimmed = (output or "").strip()
    if not trimmed:
        raise WalletStoreError("cast send returned empty output.")
    try:
        parsed = json.loads(trimmed)
    except json.JSONDecodeError:
        parsed = None

    candidates: list[Any] = []
    if isinstance(parsed, dict):
        candidates.extend([parsed.get("transactionHash"), parsed.get("txHash"), parsed.get("hash")])
    elif isinstance(parsed, list):
        for item in parsed:
            if isinstance(item, dict):
                candidates.extend([item.get("transactionHash"), item.get("txHash"), item.get("hash")])

    for value in candidates:
        if isinstance(value, str) and re.fullmatch(r"0x[a-fA-F0-9]{64}", value):
            return value

    match = re.search(r"0x[a-fA-F0-9]{64}", trimmed)
    if match:
        return match.group(0)
    raise WalletStoreError("cast send output did not include a transaction hash.")


def _load_policy_for_chain(chain: str) -> dict[str, Any]:
    ensure_app_dir()
    _assert_secure_permissions(APP_DIR, 0o700, "directory")
    if not POLICY_FILE.exists():
        raise WalletPolicyError(
            "policy_blocked",
            f"Policy file is missing for chain '{chain}'.",
            "Create ~/.xclaw-agent/policy.json with chain and spend preconditions before sending funds.",
            {"chain": chain, "policyFile": str(POLICY_FILE)},
        )
    _assert_secure_permissions(POLICY_FILE, 0o600, "policy file")
    payload = _read_json(POLICY_FILE)
    if not isinstance(payload, dict):
        raise WalletPolicyError(
            "policy_blocked",
            "Policy file must be a JSON object.",
            "Repair ~/.xclaw-agent/policy.json and retry.",
            {"policyFile": str(POLICY_FILE)},
        )
    return payload


def _enforce_spend_preconditions(chain: str, amount_wei: int) -> tuple[dict[str, Any], str, int, int]:
    policy = _load_policy_for_chain(chain)

    paused = policy.get("paused")
    if not isinstance(paused, bool):
        raise WalletPolicyError(
            "policy_blocked",
            "Policy field 'paused' must be boolean.",
            "Set paused=true/false in ~/.xclaw-agent/policy.json.",
            {"field": "paused", "policyFile": str(POLICY_FILE)},
        )
    if paused:
        raise WalletPolicyError(
            "agent_paused",
            "Spend blocked because agent is paused.",
            "Resume the agent before sending funds.",
            {"chain": chain},
        )

    chains = policy.get("chains")
    if not isinstance(chains, dict):
        raise WalletPolicyError(
            "policy_blocked",
            "Policy field 'chains' must be an object.",
            "Configure chain-level policy under chains.<chain>.",
            {"field": "chains", "policyFile": str(POLICY_FILE)},
        )
    chain_policy = chains.get(chain)
    if not isinstance(chain_policy, dict):
        raise WalletPolicyError(
            "chain_disabled",
            f"Spend blocked because chain '{chain}' is not configured in policy.",
            "Add chains.<chain>.chain_enabled=true to policy.",
            {"chain": chain},
        )
    chain_enabled = chain_policy.get("chain_enabled")
    if not isinstance(chain_enabled, bool):
        raise WalletPolicyError(
            "policy_blocked",
            "Policy field chains.<chain>.chain_enabled must be boolean.",
            "Set chain_enabled=true/false for the active chain.",
            {"chain": chain, "field": "chain_enabled"},
        )
    if not chain_enabled:
        raise WalletPolicyError(
            "chain_disabled",
            f"Spend blocked because chain '{chain}' is disabled by policy.",
            "Enable the chain in policy before spending.",
            {"chain": chain},
        )

    spend = policy.get("spend")
    if not isinstance(spend, dict):
        raise WalletPolicyError(
            "policy_blocked",
            "Policy field 'spend' must be an object.",
            "Configure spend preconditions in policy.",
            {"field": "spend", "policyFile": str(POLICY_FILE)},
        )
    approval_required = spend.get("approval_required")
    approval_granted = spend.get("approval_granted")
    max_daily_native_wei = spend.get("max_daily_native_wei")

    if not isinstance(approval_required, bool) or not isinstance(approval_granted, bool):
        raise WalletPolicyError(
            "policy_blocked",
            "Policy fields spend.approval_required and spend.approval_granted must be boolean.",
            "Set approval_required and approval_granted in policy.",
            {"field": "spend"},
        )
    if approval_required and not approval_granted:
        raise WalletPolicyError(
            "approval_required",
            "Spend blocked because approval is required but not granted.",
            "Grant approval before sending funds.",
            {"chain": chain},
        )
    if not isinstance(max_daily_native_wei, str) or not re.fullmatch(r"[0-9]+", max_daily_native_wei):
        raise WalletPolicyError(
            "policy_blocked",
            "Policy field spend.max_daily_native_wei must be a uint string.",
            "Set max_daily_native_wei as a base-unit integer string.",
            {"field": "spend.max_daily_native_wei"},
        )

    max_daily_wei = int(max_daily_native_wei)
    day_key = _utc_day_key()
    state = load_state()
    ledger = state.setdefault("spendLedger", {})
    if not isinstance(ledger, dict):
        raise WalletStoreError("State field 'spendLedger' must be an object.")
    chain_ledger = ledger.setdefault(chain, {})
    if not isinstance(chain_ledger, dict):
        raise WalletStoreError(f"State spend ledger for chain '{chain}' must be an object.")
    current_raw = chain_ledger.get(day_key, "0")
    if not isinstance(current_raw, str) or not re.fullmatch(r"[0-9]+", current_raw):
        raise WalletStoreError(f"State spend ledger value for '{chain}' '{day_key}' must be uint string.")
    current_spend = int(current_raw)

    projected = current_spend + amount_wei
    if projected > max_daily_wei:
        raise WalletPolicyError(
            "daily_cap_exceeded",
            "Spend blocked because daily native cap would be exceeded.",
            "Reduce amount or increase max_daily_native_wei policy cap.",
            {
                "chain": chain,
                "day": day_key,
                "currentSpendWei": str(current_spend),
                "amountWei": str(amount_wei),
                "maxDailyNativeWei": str(max_daily_wei),
            },
        )
    return state, day_key, current_spend, max_daily_wei


def _record_spend(state: dict[str, Any], chain: str, day_key: str, new_spend_wei: int) -> None:
    ledger = state.setdefault("spendLedger", {})
    if not isinstance(ledger, dict):
        raise WalletStoreError("State field 'spendLedger' must be an object.")
    chain_ledger = ledger.setdefault(chain, {})
    if not isinstance(chain_ledger, dict):
        raise WalletStoreError(f"State spend ledger for chain '{chain}' must be an object.")
    chain_ledger[day_key] = str(new_spend_wei)
    save_state(state)


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


def _require_api_env() -> tuple[str, str]:
    base_url = (os.environ.get("XCLAW_API_BASE_URL") or "").strip()
    api_key = (os.environ.get("XCLAW_AGENT_API_KEY") or "").strip()
    if not base_url:
        raise WalletStoreError("Missing required env: XCLAW_API_BASE_URL.")
    if not api_key:
        raise WalletStoreError("Missing required env: XCLAW_AGENT_API_KEY.")
    return base_url.rstrip("/"), api_key


def _api_request(method: str, path: str, payload: dict[str, Any] | None = None, include_idempotency: bool = False) -> tuple[int, dict[str, Any]]:
    base_url, api_key = _require_api_env()
    if path.startswith("http://") or path.startswith("https://"):
        url = path
    else:
        normalized = path if path.startswith("/") else f"/{path}"
        url = f"{base_url}{normalized}"

    headers: dict[str, str] = {
        "Accept": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    raw_data: bytes | None = None
    if payload is not None:
        raw_data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if include_idempotency:
        headers["Idempotency-Key"] = f"rt-{secrets.token_hex(16)}"

    request = urllib.request.Request(url=url, data=raw_data, headers=headers, method=method.upper())
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            body = response.read().decode("utf-8")
            parsed = json.loads(body) if body else {}
            if not isinstance(parsed, dict):
                raise WalletStoreError("API returned non-object JSON payload.")
            return int(response.status), parsed
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8") if exc.fp else ""
        try:
            parsed = json.loads(body) if body else {}
            if not isinstance(parsed, dict):
                parsed = {"message": body}
        except Exception:
            parsed = {"message": body or str(exc)}
        return int(exc.code), parsed
    except urllib.error.URLError as exc:
        raise WalletStoreError(f"API request failed: {exc.reason}") from exc


def _canonical_event_for_trade_status(status: str) -> str:
    mapping = {
        "proposed": "trade_proposed",
        "approval_pending": "trade_approval_pending",
        "approved": "trade_approved",
        "rejected": "trade_rejected",
        "executing": "trade_executing",
        "verifying": "trade_verifying",
        "filled": "trade_filled",
        "failed": "trade_failed",
        "expired": "trade_expired",
        "verification_timeout": "trade_verification_timeout",
    }
    return mapping.get(status, "trade_failed")


def _post_trade_status(trade_id: str, from_status: str, to_status: str, extra: dict[str, Any] | None = None) -> None:
    payload: dict[str, Any] = {
        "tradeId": trade_id,
        "fromStatus": from_status,
        "toStatus": to_status,
        "at": datetime.now(timezone.utc).isoformat(),
    }
    if extra:
        payload.update(extra)
    status_code, body = _api_request("POST", f"/trades/{trade_id}/status", payload=payload, include_idempotency=True)
    if status_code < 200 or status_code >= 300:
        code = str(body.get("code", "api_error"))
        message = str(body.get("message", f"trade status update failed ({status_code})"))
        raise WalletStoreError(f"{code}: {message}")


def _require_chain_contract_address(chain: str, key: str) -> str:
    cfg = _load_chain_config(chain)
    contracts = cfg.get("coreContracts")
    if not isinstance(contracts, dict):
        raise WalletStoreError(f"Chain config for '{chain}' is missing coreContracts.")
    value = contracts.get(key)
    if not isinstance(value, str) or not is_hex_address(value):
        raise WalletStoreError(f"Chain config for '{chain}' has invalid coreContracts.{key}.")
    return value


def _chain_token_address(chain: str, token_symbol: str) -> str:
    cfg = _load_chain_config(chain)
    tokens = cfg.get("canonicalTokens")
    if not isinstance(tokens, dict):
        raise WalletStoreError(f"Chain config for '{chain}' is missing canonicalTokens.")
    value = tokens.get(token_symbol)
    if not isinstance(value, str) or not is_hex_address(value):
        raise WalletStoreError(f"Chain config for '{chain}' has invalid canonicalTokens.{token_symbol}.")
    return value


def _to_wei_uint(raw: str | None) -> str:
    if raw is None:
        return str(10**15)
    trimmed = str(raw).strip()
    if re.fullmatch(r"[0-9]+", trimmed):
        return trimmed
    try:
        decimal_value = Decimal(trimmed)
    except InvalidOperation as exc:
        raise WalletStoreError(f"Invalid amount format '{raw}' for trade execution.") from exc
    if decimal_value <= 0:
        raise WalletStoreError("Trade amount must be positive.")
    wei = int(decimal_value * Decimal(10**18))
    if wei <= 0:
        raise WalletStoreError("Trade amount is too small after wei conversion.")
    return str(wei)


def _read_trade_details(trade_id: str) -> dict[str, Any]:
    status_code, body = _api_request("GET", f"/trades/{trade_id}")
    if status_code < 200 or status_code >= 300:
        code = str(body.get("code", "api_error"))
        message = str(body.get("message", f"trade read failed ({status_code})"))
        raise WalletStoreError(f"{code}: {message}")
    trade = body.get("trade")
    if not isinstance(trade, dict):
        raise WalletStoreError("Trade details response missing trade object.")
    return trade


def _execution_wallet(store: dict[str, Any], chain: str) -> tuple[str, str]:
    _, wallet = _chain_wallet(store, chain)
    if wallet is None:
        raise WalletStoreError(f"No wallet configured for chain '{chain}'.")
    _validate_wallet_entry_shape(wallet)
    address = str(wallet.get("address"))
    passphrase = _require_wallet_passphrase_for_signing(chain)
    private_key_hex = _decrypt_private_key(wallet, passphrase).hex()
    return address, private_key_hex


def _cast_calldata(signature: str, args: list[str]) -> str:
    cast_bin = _require_cast_bin()
    proc = subprocess.run([cast_bin, "calldata", signature, *args], text=True, capture_output=True)
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        stdout = (proc.stdout or "").strip()
        raise WalletStoreError(stderr or stdout or f"cast calldata failed for {signature}.")
    data = (proc.stdout or "").strip()
    if not re.fullmatch(r"0x[a-fA-F0-9]+", data):
        raise WalletStoreError(f"cast calldata returned malformed output for {signature}.")
    return data


def _cast_rpc_send_transaction(rpc_url: str, tx_obj: dict[str, str]) -> str:
    cast_bin = _require_cast_bin()
    proc = subprocess.run(
        [cast_bin, "rpc", "--rpc-url", rpc_url, "eth_sendTransaction", json.dumps(tx_obj, separators=(",", ":"))],
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        stdout = (proc.stdout or "").strip()
        raise WalletStoreError(stderr or stdout or "cast rpc eth_sendTransaction failed.")
    return _extract_tx_hash(proc.stdout)


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


def cmd_intents_poll(args: argparse.Namespace) -> int:
    chk = require_json_flag(args)
    if chk is not None:
        return chk
    try:
        status_code, body = _api_request("GET", f"/trades/pending?chainKey={urllib.parse.quote(args.chain)}&limit=25")
        if status_code < 200 or status_code >= 300:
            return fail(
                str(body.get("code", "api_error")),
                str(body.get("message", f"intents poll failed ({status_code})")),
                str(body.get("actionHint", "Verify API auth and retry.")),
                {"status": status_code, "chain": args.chain},
                exit_code=1,
            )
        items = body.get("items", [])
        if not isinstance(items, list):
            raise WalletStoreError("Trade pending response 'items' is not a list.")
        return ok("Trade intents polled.", chain=args.chain, count=len(items), intents=items)
    except WalletStoreError as exc:
        return fail("intents_poll_failed", str(exc), "Verify API env, auth, and endpoint availability.", {"chain": args.chain}, exit_code=1)
    except Exception as exc:
        return fail("intents_poll_failed", str(exc), "Inspect runtime intents poll path and retry.", {"chain": args.chain}, exit_code=1)


def cmd_approvals_check(args: argparse.Namespace) -> int:
    chk = require_json_flag(args)
    if chk is not None:
        return chk
    try:
        trade = _read_trade_details(args.intent)
        if str(trade.get("chainKey")) != args.chain:
            return fail(
                "chain_mismatch",
                "Trade chain does not match command --chain.",
                "Use matching chain or refresh intent selection.",
                {"tradeId": args.intent, "tradeChain": trade.get("chainKey"), "requestedChain": args.chain},
                exit_code=1,
            )

        status = str(trade.get("status"))
        retry = trade.get("retry") if isinstance(trade.get("retry"), dict) else {}
        retry_eligible = bool(retry.get("eligible", False))
        if status == "approved" or (status == "failed" and retry_eligible):
            return ok("Approval check passed.", tradeId=args.intent, chain=args.chain, approved=True, status=status, retry=retry)
        if status == "approval_pending":
            return fail("approval_required", "Trade is waiting for management approval.", "Approve trade from authorized management view.", {"tradeId": args.intent}, exit_code=1)
        if status == "rejected":
            return fail("approval_rejected", "Trade approval was rejected.", "Review rejection reason and create a new trade if needed.", {"tradeId": args.intent, "reasonCode": trade.get("reasonCode")}, exit_code=1)
        if status == "expired":
            return fail("approval_expired", "Trade approval has expired.", "Re-propose trade and request approval again.", {"tradeId": args.intent}, exit_code=1)
        return fail(
            "policy_denied",
            f"Trade is not executable from status '{status}'.",
            "Poll intents and execute only actionable trades.",
            {"tradeId": args.intent, "status": status, "retry": retry},
            exit_code=1,
        )
    except WalletStoreError as exc:
        return fail("approval_check_failed", str(exc), "Verify API env, auth, and trade visibility.", {"tradeId": args.intent, "chain": args.chain}, exit_code=1)
    except Exception as exc:
        return fail("approval_check_failed", str(exc), "Inspect runtime approval-check path and retry.", {"tradeId": args.intent, "chain": args.chain}, exit_code=1)


def cmd_trade_execute(args: argparse.Namespace) -> int:
    chk = require_json_flag(args)
    if chk is not None:
        return chk

    transition_state = "init"
    previous_status = "approved"
    try:
        trade = _read_trade_details(args.intent)
        status = str(trade.get("status"))
        if str(trade.get("chainKey")) != args.chain:
            return fail(
                "chain_mismatch",
                "Trade chain does not match command --chain.",
                "Use matching chain or refresh intent selection.",
                {"tradeId": args.intent, "tradeChain": trade.get("chainKey"), "requestedChain": args.chain},
                exit_code=1,
            )

        previous_status = status
        retry = trade.get("retry") if isinstance(trade.get("retry"), dict) else {}
        retry_eligible = bool(retry.get("eligible", False))
        if status not in ("approved", "failed"):
            return fail(
                "approval_required",
                f"Trade is not executable from status '{status}'.",
                "Execute only approved trades or failed trades within retry policy.",
                {"tradeId": args.intent, "status": status},
                exit_code=1,
            )
        if status == "failed" and not retry_eligible:
            return fail(
                "policy_denied",
                "Retry policy does not allow this failed trade to execute.",
                "Re-propose trade or retry within policy window/limits.",
                {"tradeId": args.intent, "retry": retry, "maxRetries": MAX_TRADE_RETRIES, "retryWindowSec": RETRY_WINDOW_SEC},
                exit_code=1,
            )

        mode = str(trade.get("mode"))
        if mode == "mock":
            mock_receipt_id = f"mrc_{hashlib.sha256(f'{args.intent}:{utc_now()}'.encode('utf-8')).hexdigest()[:24]}"
            _post_trade_status(args.intent, previous_status, "executing", {"mockReceiptId": mock_receipt_id})
            transition_state = "executing"
            _post_trade_status(args.intent, "executing", "verifying", {"mockReceiptId": mock_receipt_id})
            transition_state = "verifying"
            _post_trade_status(args.intent, "verifying", "filled", {"mockReceiptId": mock_receipt_id})
            return ok("Trade executed in mock mode.", tradeId=args.intent, chain=args.chain, mode=mode, status="filled", mockReceiptId=mock_receipt_id)

        if mode != "real":
            raise WalletStoreError(f"Unsupported trade mode '{mode}'.")

        store = load_wallet_store()
        wallet_address, _private_key_hex = _execution_wallet(store, args.chain)
        cast_bin = _require_cast_bin()
        rpc_url = _chain_rpc_url(args.chain)
        router = _require_chain_contract_address(args.chain, "router")

        token_in = str(trade.get("tokenIn") or "")
        token_out = str(trade.get("tokenOut") or "")
        if not is_hex_address(token_in):
            token_in = _chain_token_address(args.chain, "WETH")
        if not is_hex_address(token_out):
            token_out = _chain_token_address(args.chain, "USDC")

        amount_wei_str = _to_wei_uint(trade.get("amountIn"))
        amount_wei = int(amount_wei_str)
        state, day_key, current_spend, max_daily_wei = _enforce_spend_preconditions(args.chain, amount_wei)
        deadline = str(int(datetime.now(timezone.utc).timestamp()) + 120)

        approve_data = _cast_calldata("approve(address,uint256)(bool)", [router, amount_wei_str])
        approve_tx_hash = _cast_rpc_send_transaction(
            rpc_url,
            {
                "from": wallet_address,
                "to": token_in,
                "data": approve_data,
            },
        )
        approve_receipt = subprocess.run(
            [cast_bin, "receipt", "--json", "--rpc-url", rpc_url, approve_tx_hash],
            text=True,
            capture_output=True,
        )
        if approve_receipt.returncode != 0:
            stderr = (approve_receipt.stderr or "").strip()
            stdout = (approve_receipt.stdout or "").strip()
            raise WalletStoreError(stderr or stdout or "cast receipt failed for approve tx.")
        approve_payload = json.loads((approve_receipt.stdout or "{}").strip() or "{}")
        approve_status = str(approve_payload.get("status", "0x0")).lower()
        if approve_status not in {"0x1", "1"}:
            raise WalletStoreError(f"Approve receipt indicates failure status '{approve_status}'.")

        swap_data = _cast_calldata(
            "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)(uint256[])",
            [amount_wei_str, "1", f"[{token_in},{token_out}]", wallet_address, deadline],
        )
        tx_hash = _cast_rpc_send_transaction(
            rpc_url,
            {
                "from": wallet_address,
                "to": router,
                "data": swap_data,
            },
        )
        _post_trade_status(args.intent, previous_status, "executing", {"txHash": tx_hash})
        transition_state = "executing"
        _post_trade_status(args.intent, "executing", "verifying", {"txHash": tx_hash})
        transition_state = "verifying"

        receipt_proc = subprocess.run(
            [cast_bin, "receipt", "--json", "--rpc-url", rpc_url, tx_hash],
            text=True,
            capture_output=True,
        )
        if receipt_proc.returncode != 0:
            stderr = (receipt_proc.stderr or "").strip()
            stdout = (receipt_proc.stdout or "").strip()
            raise WalletStoreError(stderr or stdout or "cast receipt failed.")
        receipt_payload = json.loads((receipt_proc.stdout or "{}").strip() or "{}")
        receipt_status = str(receipt_payload.get("status", "0x0")).lower()
        if receipt_status not in {"0x1", "1"}:
            raise WalletStoreError(f"On-chain receipt indicates failure status '{receipt_status}'.")

        _record_spend(state, args.chain, day_key, current_spend + amount_wei)
        _post_trade_status(args.intent, "verifying", "filled", {"txHash": tx_hash})
        return ok(
            "Trade executed in real mode.",
            tradeId=args.intent,
            chain=args.chain,
            mode=mode,
            status="filled",
            txHash=tx_hash,
            day=day_key,
            dailySpendWei=str(current_spend + amount_wei),
            maxDailyNativeWei=str(max_daily_wei),
        )
    except WalletPolicyError as exc:
        if transition_state == "executing":
            try:
                _post_trade_status(args.intent, "executing", "failed", {"reasonCode": "policy_denied", "reasonMessage": str(exc)})
            except Exception:
                pass
        return fail(exc.code, str(exc), exc.action_hint, exc.details, exit_code=1)
    except WalletStoreError as exc:
        if transition_state == "executing":
            try:
                _post_trade_status(args.intent, "executing", "failed", {"reasonCode": "rpc_unavailable", "reasonMessage": str(exc)})
            except Exception:
                pass
        elif transition_state == "init":
            try:
                _post_trade_status(args.intent, previous_status, "failed", {"reasonCode": "rpc_unavailable", "reasonMessage": str(exc)})
            except Exception:
                pass
        elif transition_state == "verifying":
            try:
                _post_trade_status(args.intent, "verifying", "failed", {"reasonCode": "verification_timeout", "reasonMessage": str(exc)})
            except Exception:
                pass
        return fail("trade_execute_failed", str(exc), "Verify approval state, wallet setup, and local chain connectivity.", {"tradeId": args.intent, "chain": args.chain}, exit_code=1)
    except Exception as exc:
        return fail("trade_execute_failed", str(exc), "Inspect runtime trade execute path and retry.", {"tradeId": args.intent, "chain": args.chain}, exit_code=1)


def cmd_report_send(args: argparse.Namespace) -> int:
    chk = require_json_flag(args)
    if chk is not None:
        return chk
    try:
        trade = _read_trade_details(args.trade)
        event_type = _canonical_event_for_trade_status(str(trade.get("status")))
        payload = {
            "schemaVersion": 1,
            "agentId": trade.get("agentId"),
            "tradeId": args.trade,
            "eventType": event_type,
            "payload": {
                "status": trade.get("status"),
                "mode": trade.get("mode"),
                "chainKey": trade.get("chainKey"),
                "reasonCode": trade.get("reasonCode"),
                "reportedBy": "xclaw-agent-runtime",
            },
            "createdAt": datetime.now(timezone.utc).isoformat(),
        }
        status_code, body = _api_request("POST", "/events", payload=payload, include_idempotency=True)
        if status_code < 200 or status_code >= 300:
            return fail(
                str(body.get("code", "api_error")),
                str(body.get("message", f"report send failed ({status_code})")),
                str(body.get("actionHint", "Verify API auth and retry.")),
                {"status": status_code, "tradeId": args.trade},
                exit_code=1,
            )
        return ok("Trade execution report sent.", tradeId=args.trade, eventType=event_type)
    except WalletStoreError as exc:
        return fail("report_send_failed", str(exc), "Verify API env/auth and trade visibility, then retry.", {"tradeId": args.trade}, exit_code=1)
    except Exception as exc:
        return fail("report_send_failed", str(exc), "Inspect runtime report-send path and retry.", {"tradeId": args.trade}, exit_code=1)


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

    chain = args.chain
    amount_wei = int(args.amount_wei)
    try:
        store = load_wallet_store()
        _, wallet = _chain_wallet(store, chain)
        if wallet is None:
            return fail("wallet_missing", f"No wallet configured for chain '{chain}'.", "Run wallet create/import first.", {"chain": chain}, exit_code=1)
        _validate_wallet_entry_shape(wallet)

        state, day_key, current_spend, max_daily_wei = _enforce_spend_preconditions(chain, amount_wei)
        passphrase = _require_wallet_passphrase_for_signing(chain)
        private_key_hex = _decrypt_private_key(wallet, passphrase).hex()
        cast_bin = _require_cast_bin()
        rpc_url = _chain_rpc_url(chain)

        proc = subprocess.run(
            [cast_bin, "send", "--json", "--rpc-url", rpc_url, "--private-key", private_key_hex, args.to, args.amount_wei],
            text=True,
            capture_output=True,
        )
        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip()
            stdout = (proc.stdout or "").strip()
            raise WalletStoreError(stderr or stdout or "cast send failed.")

        tx_hash = _extract_tx_hash(proc.stdout)
        _record_spend(state, chain, day_key, current_spend + amount_wei)

        return ok(
            "Wallet send executed.",
            chain=chain,
            to=args.to,
            amountWei=args.amount_wei,
            txHash=tx_hash,
            day=day_key,
            dailySpendWei=str(current_spend + amount_wei),
            maxDailyNativeWei=str(max_daily_wei),
        )
    except WalletPolicyError as exc:
        return fail(exc.code, str(exc), exc.action_hint, exc.details, exit_code=1)
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
        if "Chain config" in msg:
            return fail("chain_config_invalid", msg, "Repair config/chains/<chain>.json and retry.", {"chain": chain}, exit_code=1)
        return fail("send_failed", msg, "Verify wallet passphrase, policy, RPC connectivity, and retry.", {"chain": chain}, exit_code=1)
    except Exception as exc:
        return fail("send_failed", str(exc), "Inspect runtime send configuration and retry.", {"chain": chain}, exit_code=1)


def cmd_wallet_balance(args: argparse.Namespace) -> int:
    chk = require_json_flag(args)
    if chk is not None:
        return chk
    chain = args.chain
    try:
        store = load_wallet_store()
        _, wallet = _chain_wallet(store, chain)
        if wallet is None:
            return fail("wallet_missing", f"No wallet configured for chain '{chain}'.", "Run wallet create/import first.", {"chain": chain}, exit_code=1)
        _validate_wallet_entry_shape(wallet)
        address = str(wallet.get("address"))
        cast_bin = _require_cast_bin()
        rpc_url = _chain_rpc_url(chain)
        proc = subprocess.run(
            [cast_bin, "balance", address, "--rpc-url", rpc_url],
            text=True,
            capture_output=True,
        )
        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip()
            stdout = (proc.stdout or "").strip()
            raise WalletStoreError(stderr or stdout or "cast balance failed.")
        output = (proc.stdout or "").strip().splitlines()
        parsed = _parse_uint_text(output[-1] if output else "")
        return ok("Wallet balance fetched.", chain=chain, address=address, balanceWei=str(parsed))
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
        if "Chain config" in msg:
            return fail("chain_config_invalid", msg, "Repair config/chains/<chain>.json and retry.", {"chain": chain}, exit_code=1)
        return fail("balance_failed", msg, "Verify wallet and RPC connectivity, then retry.", {"chain": chain}, exit_code=1)
    except Exception as exc:
        return fail("balance_failed", str(exc), "Inspect runtime balance configuration and retry.", {"chain": chain}, exit_code=1)


def cmd_wallet_token_balance(args: argparse.Namespace) -> int:
    chk = require_json_flag(args)
    if chk is not None:
        return chk
    if not is_hex_address(args.token):
        return fail("invalid_input", "Invalid token address format.", "Use 0x-prefixed 20-byte hex address.", {"token": args.token}, exit_code=2)
    chain = args.chain
    try:
        store = load_wallet_store()
        _, wallet = _chain_wallet(store, chain)
        if wallet is None:
            return fail("wallet_missing", f"No wallet configured for chain '{chain}'.", "Run wallet create/import first.", {"chain": chain}, exit_code=1)
        _validate_wallet_entry_shape(wallet)
        address = str(wallet.get("address"))
        cast_bin = _require_cast_bin()
        rpc_url = _chain_rpc_url(chain)
        proc = subprocess.run(
            [cast_bin, "call", args.token, "balanceOf(address)(uint256)", address, "--rpc-url", rpc_url],
            text=True,
            capture_output=True,
        )
        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip()
            stdout = (proc.stdout or "").strip()
            raise WalletStoreError(stderr or stdout or "cast call balanceOf failed.")
        output = (proc.stdout or "").strip().splitlines()
        parsed = _parse_uint_text(output[-1] if output else "")
        return ok("Wallet token balance fetched.", chain=chain, address=address, token=args.token, balanceWei=str(parsed))
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
        if "Chain config" in msg:
            return fail("chain_config_invalid", msg, "Repair config/chains/<chain>.json and retry.", {"chain": chain}, exit_code=1)
        return fail("token_balance_failed", msg, "Verify wallet, token, and RPC connectivity, then retry.", {"chain": chain, "token": args.token}, exit_code=1)
    except Exception as exc:
        return fail("token_balance_failed", str(exc), "Inspect runtime token balance configuration and retry.", {"chain": chain, "token": args.token}, exit_code=1)


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
    intents_poll.set_defaults(func=cmd_intents_poll)

    approvals = sub.add_parser("approvals")
    approvals_sub = approvals.add_subparsers(dest="approvals_cmd")
    approvals_check = approvals_sub.add_parser("check")
    approvals_check.add_argument("--intent", required=True)
    approvals_check.add_argument("--chain", required=True)
    approvals_check.add_argument("--json", action="store_true")
    approvals_check.set_defaults(func=cmd_approvals_check)

    trade = sub.add_parser("trade")
    trade_sub = trade.add_subparsers(dest="trade_cmd")
    trade_exec = trade_sub.add_parser("execute")
    trade_exec.add_argument("--intent", required=True)
    trade_exec.add_argument("--chain", required=True)
    trade_exec.add_argument("--json", action="store_true")
    trade_exec.set_defaults(func=cmd_trade_execute)

    report = sub.add_parser("report")
    report_sub = report.add_subparsers(dest="report_cmd")
    report_send = report_sub.add_parser("send")
    report_send.add_argument("--trade", required=True)
    report_send.add_argument("--json", action="store_true")
    report_send.set_defaults(func=cmd_report_send)

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
