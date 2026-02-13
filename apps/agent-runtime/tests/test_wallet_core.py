import json
import os
import pathlib
import stat
import subprocess
import shutil
import sys
import tempfile
import unittest
import textwrap
from datetime import datetime, timedelta, timezone

RUNTIME_ROOT = pathlib.Path("apps/agent-runtime").resolve()
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))

from xclaw_agent import cli  # noqa: E402


class WalletCoreUnitTests(unittest.TestCase):
    def test_encrypt_decrypt_roundtrip(self) -> None:
        private_key_hex = "11" * 32
        encrypted = cli._encrypt_private_key(private_key_hex, "passphrase-123")
        entry = {"address": cli._derive_address(private_key_hex), "crypto": encrypted}
        decrypted = cli._decrypt_private_key(entry, "passphrase-123")
        self.assertEqual(decrypted.hex(), private_key_hex)

    def test_malformed_ciphertext_is_rejected(self) -> None:
        entry = {
            "address": "0x0000000000000000000000000000000000000001",
            "crypto": {
                "enc": "aes-256-gcm",
                "kdf": "argon2id",
                "kdfParams": {"timeCost": 3, "memoryCost": 65536, "parallelism": 1, "hashLen": 32},
                "saltB64": "AA==",
                "nonceB64": "AA==",
                "ciphertextB64": "AA==",
            },
        }
        with self.assertRaises(cli.WalletStoreError):
            cli._decrypt_private_key(entry, "pw")


class WalletCoreCliTests(unittest.TestCase):
    def _run(self, *args: str, home: str, extra_env: dict[str, str] | None = None) -> tuple[int, dict]:
        cmd = ["apps/agent-runtime/bin/xclaw-agent", *args]
        env = os.environ.copy()
        env["XCLAW_AGENT_HOME"] = str(pathlib.Path(home) / ".xclaw-agent")
        if extra_env:
            env.update(extra_env)
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
        payload = json.loads(proc.stdout.strip())
        return proc.returncode, payload

    def _seed_wallet(self, home: str, chain: str = "base_sepolia") -> tuple[str, str]:
        private_key_hex = "22" * 32
        address = cli._derive_address(private_key_hex)
        encrypted = cli._encrypt_private_key(private_key_hex, "passphrase-123")
        wallet_dir = pathlib.Path(home) / ".xclaw-agent"
        wallet_dir.mkdir(parents=True, exist_ok=True)
        store = {
            "version": 1,
            "defaultWalletId": "wlt_test",
            "wallets": {
                "wlt_test": {
                    "walletId": "wlt_test",
                    "address": address,
                    "createdAt": datetime.now(timezone.utc).isoformat(),
                    "crypto": encrypted,
                }
            },
            "chains": {chain: "wlt_test"},
        }
        wallet_path = wallet_dir / "wallets.json"
        wallet_path.write_text(json.dumps(store), encoding="utf-8")
        if os.name != "nt":
            os.chmod(wallet_dir, stat.S_IRWXU)
            os.chmod(wallet_path, stat.S_IRUSR | stat.S_IWUSR)
        return address, private_key_hex

    def _seed_multi_chain_wallet(self, home: str) -> str:
        private_key_hex = "33" * 32
        address = cli._derive_address(private_key_hex)
        encrypted = cli._encrypt_private_key(private_key_hex, "passphrase-123")
        wallet_dir = pathlib.Path(home) / ".xclaw-agent"
        wallet_dir.mkdir(parents=True, exist_ok=True)
        store = {
            "version": 1,
            "defaultWalletId": "wlt_test",
            "wallets": {
                "wlt_test": {
                    "walletId": "wlt_test",
                    "address": address,
                    "createdAt": datetime.now(timezone.utc).isoformat(),
                    "crypto": encrypted,
                }
            },
            "chains": {"base_sepolia": "wlt_test", "hardhat_local": "wlt_test"},
        }
        wallet_path = wallet_dir / "wallets.json"
        wallet_path.write_text(json.dumps(store), encoding="utf-8")
        if os.name != "nt":
            os.chmod(wallet_dir, stat.S_IRWXU)
            os.chmod(wallet_path, stat.S_IRUSR | stat.S_IWUSR)
        return address

    def _seed_policy(
        self,
        home: str,
        *,
        chain: str = "base_sepolia",
        chain_enabled: bool = True,
        paused: bool = False,
        approval_required: bool = True,
        approval_granted: bool = True,
        max_daily_native_wei: str = "1000000000000000000",
    ) -> None:
        wallet_dir = pathlib.Path(home) / ".xclaw-agent"
        wallet_dir.mkdir(parents=True, exist_ok=True)
        policy = {
            "version": 1,
            "paused": paused,
            "chains": {chain: {"chain_enabled": chain_enabled}},
            "spend": {
                "approval_required": approval_required,
                "approval_granted": approval_granted,
                "max_daily_native_wei": max_daily_native_wei,
            },
        }
        policy_path = wallet_dir / "policy.json"
        policy_path.write_text(json.dumps(policy), encoding="utf-8")
        if os.name != "nt":
            os.chmod(wallet_dir, stat.S_IRWXU)
            os.chmod(policy_path, stat.S_IRUSR | stat.S_IWUSR)

    def _seed_spend_state(self, home: str, *, chain: str, amount_wei: str) -> None:
        wallet_dir = pathlib.Path(home) / ".xclaw-agent"
        wallet_dir.mkdir(parents=True, exist_ok=True)
        day_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        state = {"spendLedger": {chain: {day_key: amount_wei}}}
        state_path = wallet_dir / "state.json"
        state_path.write_text(json.dumps(state), encoding="utf-8")
        if os.name != "nt":
            os.chmod(wallet_dir, stat.S_IRWXU)
            os.chmod(state_path, stat.S_IRUSR | stat.S_IWUSR)

    def _install_fake_cast(self, home: str) -> str:
        if os.name == "nt":
            self.skipTest("fake cast script helper is POSIX-only")
        bin_dir = pathlib.Path(home) / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        cast_path = bin_dir / "cast"
        cast_path.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env bash
                set -euo pipefail
                cmd="${1:-}"
                if [ "$cmd" = "send" ]; then
                  echo '{"transactionHash":"0xabababababababababababababababababababababababababababababababab"}'
                  exit 0
                fi
                if [ "$cmd" = "balance" ]; then
                  echo "123456789"
                  exit 0
                fi
                if [ "$cmd" = "call" ]; then
                  echo "0x2a"
                  exit 0
                fi
                echo "unsupported fake cast command" >&2
                exit 1
                """
            ),
            encoding="utf-8",
        )
        os.chmod(cast_path, stat.S_IRWXU)
        return str(bin_dir)

    def _canonical_message(self, chain: str = "base_sepolia", timestamp: datetime | None = None) -> str:
        ts = timestamp or datetime.now(timezone.utc)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        iso = ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        return "\n".join(
            [
                "domain=xclaw.trade",
                f"chain={chain}",
                "nonce=nonce_1234567890ABCDEF",
                f"timestamp={iso}",
                "action=agent_token_recovery",
            ]
        )

    def test_wallet_create_non_interactive_rejected_without_env(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_home:
            code, payload = self._run("wallet", "create", "--chain", "base_sepolia", "--json", home=tmp_home)
            self.assertEqual(code, 2)
            self.assertEqual(payload["code"], "non_interactive")

    def test_wallet_create_non_interactive_with_env_passphrase(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_home:
            code, payload = self._run(
                "wallet",
                "create",
                "--chain",
                "base_sepolia",
                "--json",
                home=tmp_home,
                extra_env={"XCLAW_WALLET_PASSPHRASE": "passphrase-123"},
            )
            self.assertEqual(code, 0)
            self.assertEqual(payload["code"], "ok")
            self.assertTrue(payload["created"])

    def test_wallet_import_non_interactive_rejected_without_env(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_home:
            code, payload = self._run("wallet", "import", "--chain", "base_sepolia", "--json", home=tmp_home)
            self.assertEqual(code, 2)
            self.assertEqual(payload["code"], "non_interactive")

    def test_wallet_import_non_interactive_with_env_private_key_and_passphrase(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_home:
            code, payload = self._run(
                "wallet",
                "import",
                "--chain",
                "base_sepolia",
                "--json",
                home=tmp_home,
                extra_env={
                    "XCLAW_WALLET_IMPORT_PRIVATE_KEY": "0x" + ("11" * 32),
                    "XCLAW_WALLET_PASSPHRASE": "passphrase-123",
                },
            )
            self.assertEqual(code, 0)
            self.assertEqual(payload["code"], "ok")
            self.assertTrue(payload["imported"])

    @unittest.skipIf(os.name == "nt", "Permission mode assertions are POSIX-specific")
    def test_wallet_health_rejects_unsafe_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_home:
            wallet_dir = pathlib.Path(tmp_home) / ".xclaw-agent"
            wallet_dir.mkdir(parents=True, exist_ok=True)
            store = wallet_dir / "wallets.json"
            store.write_text(json.dumps({"version": 1, "defaultWalletId": None, "wallets": {}, "chains": {}}), encoding="utf-8")
            os.chmod(wallet_dir, 0o700)
            os.chmod(store, 0o644)

            code, payload = self._run("wallet", "health", "--chain", "base_sepolia", "--json", home=tmp_home)
            self.assertEqual(code, 1)
            self.assertEqual(payload["code"], "unsafe_permissions")

    def test_wallet_address_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_home:
            code, payload = self._run("wallet", "address", "--chain", "base_sepolia", "--json", home=tmp_home)
            self.assertEqual(code, 1)
            self.assertEqual(payload["code"], "wallet_missing")

    def test_wallet_sign_challenge_empty_message_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_home:
            code, payload = self._run(
                "wallet",
                "sign-challenge",
                "--message",
                " ",
                "--chain",
                "base_sepolia",
                "--json",
                home=tmp_home,
            )
            self.assertEqual(code, 2)
            self.assertEqual(payload["code"], "invalid_input")

    def test_wallet_sign_challenge_missing_wallet(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_home:
            code, payload = self._run(
                "wallet",
                "sign-challenge",
                "--message",
                self._canonical_message(),
                "--chain",
                "base_sepolia",
                "--json",
                home=tmp_home,
                extra_env={"XCLAW_WALLET_PASSPHRASE": "passphrase-123"},
            )
            self.assertEqual(code, 1)
            self.assertEqual(payload["code"], "wallet_missing")

    def test_wallet_sign_challenge_malformed_challenge_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_home:
            self._seed_wallet(tmp_home)
            bad_message = "domain=xclaw.trade\nchain=base_sepolia\nnonce=abc"
            code, payload = self._run(
                "wallet",
                "sign-challenge",
                "--message",
                bad_message,
                "--chain",
                "base_sepolia",
                "--json",
                home=tmp_home,
                extra_env={"XCLAW_WALLET_PASSPHRASE": "passphrase-123"},
            )
            self.assertEqual(code, 2)
            self.assertEqual(payload["code"], "invalid_challenge_format")

    def test_wallet_sign_challenge_chain_mismatch_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_home:
            self._seed_wallet(tmp_home)
            code, payload = self._run(
                "wallet",
                "sign-challenge",
                "--message",
                self._canonical_message(chain="hardhat_local"),
                "--chain",
                "base_sepolia",
                "--json",
                home=tmp_home,
                extra_env={"XCLAW_WALLET_PASSPHRASE": "passphrase-123"},
            )
            self.assertEqual(code, 2)
            self.assertEqual(payload["code"], "invalid_challenge_format")

    def test_wallet_sign_challenge_stale_timestamp_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_home:
            self._seed_wallet(tmp_home)
            stale = datetime.now(timezone.utc) - timedelta(minutes=10)
            code, payload = self._run(
                "wallet",
                "sign-challenge",
                "--message",
                self._canonical_message(timestamp=stale),
                "--chain",
                "base_sepolia",
                "--json",
                home=tmp_home,
                extra_env={"XCLAW_WALLET_PASSPHRASE": "passphrase-123"},
            )
            self.assertEqual(code, 2)
            self.assertEqual(payload["code"], "invalid_challenge_format")

    def test_wallet_sign_challenge_non_interactive_without_env_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_home:
            self._seed_wallet(tmp_home)
            code, payload = self._run(
                "wallet",
                "sign-challenge",
                "--message",
                self._canonical_message(),
                "--chain",
                "base_sepolia",
                "--json",
                home=tmp_home,
            )
            self.assertEqual(code, 2)
            self.assertEqual(payload["code"], "non_interactive")

    def test_wallet_sign_challenge_cast_missing_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_home:
            self._seed_wallet(tmp_home)
            code, payload = self._run(
                "wallet",
                "sign-challenge",
                "--message",
                self._canonical_message(),
                "--chain",
                "base_sepolia",
                "--json",
                home=tmp_home,
                extra_env={"XCLAW_WALLET_PASSPHRASE": "passphrase-123", "PATH": "/usr/bin:/bin"},
            )
            self.assertEqual(code, 1)
            self.assertEqual(payload["code"], "missing_dependency")

    def test_wallet_send_missing_policy_file_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_home:
            self._seed_wallet(tmp_home)
            code, payload = self._run(
                "wallet",
                "send",
                "--to",
                "0x0000000000000000000000000000000000000001",
                "--amount-wei",
                "1",
                "--chain",
                "base_sepolia",
                "--json",
                home=tmp_home,
                extra_env={"XCLAW_WALLET_PASSPHRASE": "passphrase-123"},
            )
            self.assertEqual(code, 1)
            self.assertEqual(payload["code"], "policy_blocked")

    def test_wallet_send_chain_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_home:
            self._seed_wallet(tmp_home)
            self._seed_policy(tmp_home, chain_enabled=False)
            code, payload = self._run(
                "wallet",
                "send",
                "--to",
                "0x0000000000000000000000000000000000000001",
                "--amount-wei",
                "1",
                "--chain",
                "base_sepolia",
                "--json",
                home=tmp_home,
                extra_env={"XCLAW_WALLET_PASSPHRASE": "passphrase-123"},
            )
            self.assertEqual(code, 1)
            self.assertEqual(payload["code"], "chain_disabled")

    def test_wallet_send_paused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_home:
            self._seed_wallet(tmp_home)
            self._seed_policy(tmp_home, paused=True)
            code, payload = self._run(
                "wallet",
                "send",
                "--to",
                "0x0000000000000000000000000000000000000001",
                "--amount-wei",
                "1",
                "--chain",
                "base_sepolia",
                "--json",
                home=tmp_home,
                extra_env={"XCLAW_WALLET_PASSPHRASE": "passphrase-123"},
            )
            self.assertEqual(code, 1)
            self.assertEqual(payload["code"], "agent_paused")

    def test_wallet_send_approval_required(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_home:
            self._seed_wallet(tmp_home)
            self._seed_policy(tmp_home, approval_required=True, approval_granted=False)
            code, payload = self._run(
                "wallet",
                "send",
                "--to",
                "0x0000000000000000000000000000000000000001",
                "--amount-wei",
                "1",
                "--chain",
                "base_sepolia",
                "--json",
                home=tmp_home,
                extra_env={"XCLAW_WALLET_PASSPHRASE": "passphrase-123"},
            )
            self.assertEqual(code, 1)
            self.assertEqual(payload["code"], "approval_required")

    def test_wallet_send_daily_cap_exceeded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_home:
            self._seed_wallet(tmp_home)
            self._seed_policy(tmp_home, max_daily_native_wei="10")
            self._seed_spend_state(tmp_home, chain="base_sepolia", amount_wei="10")
            code, payload = self._run(
                "wallet",
                "send",
                "--to",
                "0x0000000000000000000000000000000000000001",
                "--amount-wei",
                "1",
                "--chain",
                "base_sepolia",
                "--json",
                home=tmp_home,
                extra_env={"XCLAW_WALLET_PASSPHRASE": "passphrase-123"},
            )
            self.assertEqual(code, 1)
            self.assertEqual(payload["code"], "daily_cap_exceeded")

    def test_wallet_send_success_updates_spend_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_home:
            self._seed_wallet(tmp_home)
            self._seed_policy(tmp_home, max_daily_native_wei="50")
            fake_bin = self._install_fake_cast(tmp_home)
            code, payload = self._run(
                "wallet",
                "send",
                "--to",
                "0x0000000000000000000000000000000000000001",
                "--amount-wei",
                "7",
                "--chain",
                "base_sepolia",
                "--json",
                home=tmp_home,
                extra_env={"XCLAW_WALLET_PASSPHRASE": "passphrase-123", "PATH": f"{fake_bin}:/usr/bin:/bin"},
            )
            self.assertEqual(code, 0)
            self.assertEqual(payload["code"], "ok")
            self.assertRegex(payload["txHash"], r"^0x[a-fA-F0-9]{64}$")
            self.assertEqual(payload["dailySpendWei"], "7")

            state_path = pathlib.Path(tmp_home) / ".xclaw-agent" / "state.json"
            state = json.loads(state_path.read_text(encoding="utf-8"))
            day_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            self.assertEqual(state["spendLedger"]["base_sepolia"][day_key], "7")

    def test_wallet_balance_success_with_fake_cast(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_home:
            address, _ = self._seed_wallet(tmp_home)
            fake_bin = self._install_fake_cast(tmp_home)
            code, payload = self._run(
                "wallet",
                "balance",
                "--chain",
                "base_sepolia",
                "--json",
                home=tmp_home,
                extra_env={"PATH": f"{fake_bin}:/usr/bin:/bin"},
            )
            self.assertEqual(code, 0)
            self.assertEqual(payload["code"], "ok")
            self.assertEqual(payload["address"], address)
            self.assertEqual(payload["balanceWei"], "123456789")

    def test_wallet_token_balance_success_with_fake_cast(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_home:
            self._seed_wallet(tmp_home)
            fake_bin = self._install_fake_cast(tmp_home)
            code, payload = self._run(
                "wallet",
                "token-balance",
                "--token",
                "0x0000000000000000000000000000000000000001",
                "--chain",
                "base_sepolia",
                "--json",
                home=tmp_home,
                extra_env={"PATH": f"{fake_bin}:/usr/bin:/bin"},
            )
            self.assertEqual(code, 0)
            self.assertEqual(payload["code"], "ok")
            self.assertEqual(payload["token"], "0x0000000000000000000000000000000000000001")
            self.assertEqual(payload["balanceWei"], "42")

    def test_wallet_token_balance_invalid_token_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_home:
            code, payload = self._run(
                "wallet",
                "token-balance",
                "--token",
                "bad",
                "--chain",
                "base_sepolia",
                "--json",
                home=tmp_home,
            )
            self.assertEqual(code, 2)
            self.assertEqual(payload["code"], "invalid_input")

    def test_wallet_remove_multichain_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_home:
            self._seed_multi_chain_wallet(tmp_home)
            code, payload = self._run("wallet", "remove", "--chain", "base_sepolia", "--json", home=tmp_home)
            self.assertEqual(code, 0)
            self.assertTrue(payload["removed"])

            store_path = pathlib.Path(tmp_home) / ".xclaw-agent" / "wallets.json"
            store = json.loads(store_path.read_text(encoding="utf-8"))
            self.assertIn("hardhat_local", store["chains"])
            self.assertIn("wlt_test", store["wallets"])
            self.assertEqual(store["defaultWalletId"], "wlt_test")

            code2, payload2 = self._run("wallet", "remove", "--chain", "hardhat_local", "--json", home=tmp_home)
            self.assertEqual(code2, 0)
            self.assertTrue(payload2["removed"])

            store2 = json.loads(store_path.read_text(encoding="utf-8"))
            self.assertEqual(store2["chains"], {})
            self.assertEqual(store2["wallets"], {})
            self.assertIsNone(store2["defaultWalletId"])

    @unittest.skipUnless(shutil.which("cast"), "cast is required for signing happy-path test")
    def test_wallet_sign_challenge_happy_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_home:
            address, _ = self._seed_wallet(tmp_home)
            code, payload = self._run(
                "wallet",
                "sign-challenge",
                "--message",
                self._canonical_message(),
                "--chain",
                "base_sepolia",
                "--json",
                home=tmp_home,
                extra_env={"XCLAW_WALLET_PASSPHRASE": "passphrase-123"},
            )
            self.assertEqual(code, 0)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["code"], "ok")
            self.assertEqual(payload["address"], address)
            self.assertEqual(payload["scheme"], "eip191_personal_sign")
            self.assertEqual(payload["challengeFormat"], "xclaw-auth-v1")
            self.assertRegex(payload["signature"], r"^0x[a-fA-F0-9]{130}$")


if __name__ == "__main__":
    unittest.main(verbosity=2)
