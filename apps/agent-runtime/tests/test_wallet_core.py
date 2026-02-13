import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest

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
    def _run(self, *args: str, home: str) -> tuple[int, dict]:
        cmd = ["apps/agent-runtime/bin/xclaw-agent", *args]
        env = os.environ.copy()
        env["XCLAW_AGENT_HOME"] = str(pathlib.Path(home) / ".xclaw-agent")
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
        payload = json.loads(proc.stdout.strip())
        return proc.returncode, payload

    def test_wallet_create_non_interactive_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_home:
            code, payload = self._run("wallet", "create", "--chain", "base_sepolia", "--json", home=tmp_home)
            self.assertEqual(code, 2)
            self.assertEqual(payload["code"], "non_interactive")

    def test_wallet_import_non_interactive_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_home:
            code, payload = self._run("wallet", "import", "--chain", "base_sepolia", "--json", home=tmp_home)
            self.assertEqual(code, 2)
            self.assertEqual(payload["code"], "non_interactive")

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
