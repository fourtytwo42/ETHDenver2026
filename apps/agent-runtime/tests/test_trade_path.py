import argparse
import json
import unittest
from unittest import mock

import pathlib
import sys

RUNTIME_ROOT = pathlib.Path("apps/agent-runtime").resolve()
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))

from xclaw_agent import cli  # noqa: E402


class TradePathRuntimeTests(unittest.TestCase):
    def test_intents_poll_success(self) -> None:
        args = argparse.Namespace(chain="hardhat_local", json=True)
        with mock.patch.object(
            cli,
            "_api_request",
            return_value=(200, {"items": [{"tradeId": "trd_1", "status": "approved"}]})
        ):
            code = cli.cmd_intents_poll(args)
        self.assertEqual(code, 0)

    def test_approvals_check_pending_rejected(self) -> None:
        args = argparse.Namespace(intent="trd_1", chain="hardhat_local", json=True)
        with mock.patch.object(
            cli,
            "_read_trade_details",
            return_value={"tradeId": "trd_1", "chainKey": "hardhat_local", "status": "approval_pending", "retry": {"eligible": False}},
        ):
            code = cli.cmd_approvals_check(args)
        self.assertEqual(code, 1)

    def test_trade_execute_mock_success(self) -> None:
        args = argparse.Namespace(intent="trd_1", chain="hardhat_local", json=True)
        trade_payload = {
            "tradeId": "trd_1",
            "chainKey": "hardhat_local",
            "status": "approved",
            "mode": "mock",
            "retry": {"eligible": False},
        }

        posted: list[tuple[str, str]] = []

        def fake_post(trade_id: str, from_status: str, to_status: str, extra: dict | None = None) -> None:
            posted.append((from_status, to_status))

        with mock.patch.object(cli, "_read_trade_details", return_value=trade_payload), mock.patch.object(
            cli,
            "_post_trade_status",
            side_effect=fake_post,
        ):
            code = cli.cmd_trade_execute(args)

        self.assertEqual(code, 0)
        self.assertEqual(posted[0], ("approved", "executing"))
        self.assertEqual(posted[1], ("executing", "verifying"))
        self.assertEqual(posted[2], ("verifying", "filled"))

    def test_trade_execute_retry_not_eligible_denied(self) -> None:
        args = argparse.Namespace(intent="trd_1", chain="hardhat_local", json=True)
        trade_payload = {
            "tradeId": "trd_1",
            "chainKey": "hardhat_local",
            "status": "failed",
            "mode": "mock",
            "retry": {"eligible": False, "failedAttempts": 3, "maxRetries": 3},
        }

        with mock.patch.object(cli, "_read_trade_details", return_value=trade_payload):
            code = cli.cmd_trade_execute(args)

        self.assertEqual(code, 1)

    def test_report_send_success(self) -> None:
        args = argparse.Namespace(trade="trd_1", json=True)
        with mock.patch.object(
            cli,
            "_read_trade_details",
            return_value={"tradeId": "trd_1", "agentId": "agt_1", "status": "filled", "mode": "mock", "chainKey": "hardhat_local", "reasonCode": None},
        ), mock.patch.object(cli, "_api_request", return_value=(200, {"ok": True})):
            code = cli.cmd_report_send(args)

        self.assertEqual(code, 0)

    def test_offdex_intents_poll_success(self) -> None:
        args = argparse.Namespace(chain="hardhat_local", json=True)
        with mock.patch.object(
            cli,
            "_offdex_intents_query",
            return_value=[{"settlementIntentId": "ofi_1", "status": "proposed"}],
        ):
            code = cli.cmd_offdex_intents_poll(args)
        self.assertEqual(code, 0)

    def test_offdex_accept_success(self) -> None:
        args = argparse.Namespace(intent="ofi_1", chain="hardhat_local", json=True)
        with mock.patch.object(
            cli,
            "_api_request",
            return_value=(200, {"settlementIntentId": "ofi_1", "status": "accepted"}),
        ):
            code = cli.cmd_offdex_accept(args)
        self.assertEqual(code, 0)

    def test_offdex_settle_requires_ready_to_settle(self) -> None:
        args = argparse.Namespace(intent="ofi_1", chain="hardhat_local", json=True)
        with mock.patch.object(
            cli,
            "_offdex_intents_query",
            return_value=[{"settlementIntentId": "ofi_1", "status": "accepted"}],
        ):
            code = cli.cmd_offdex_settle(args)
        self.assertEqual(code, 1)

    def test_offdex_settle_success(self) -> None:
        args = argparse.Namespace(intent="ofi_1", chain="hardhat_local", json=True)
        fake_wallet = {
            "address": "0x1111111111111111111111111111111111111111",
            "crypto": {
                "enc": "aes-256-gcm",
                "kdf": "argon2id",
                "kdfParams": {},
                "saltB64": "MDEyMzQ1Njc4OWFiY2RlZg==",
                "nonceB64": "MDEyMzQ1Njc4OWFi",
                "ciphertextB64": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
            }
        }
        with mock.patch.object(
            cli,
            "_offdex_intents_query",
            return_value=[{"settlementIntentId": "ofi_1", "status": "ready_to_settle", "escrowDealId": "0x" + "11" * 32}],
        ), mock.patch.object(
            cli,
            "_api_request",
            side_effect=[
                (200, {"settlementIntentId": "ofi_1", "status": "settling"}),
                (200, {"settlementIntentId": "ofi_1", "status": "settled"}),
            ],
        ), mock.patch.object(
            cli,
            "load_wallet_store",
            return_value={"version": 1, "defaultWalletId": "w1", "wallets": {"w1": fake_wallet}, "chains": {"hardhat_local": "w1"}},
        ), mock.patch.object(
            cli,
            "_validate_wallet_entry_shape",
            return_value=None,
        ), mock.patch.object(
            cli,
            "_require_wallet_passphrase_for_signing",
            return_value="pw",
        ), mock.patch.object(
            cli,
            "_decrypt_private_key",
            return_value=b"\x01" * 32,
        ), mock.patch.object(
            cli,
            "_require_cast_bin",
            return_value="cast",
        ), mock.patch.object(
            cli,
            "_chain_rpc_url",
            return_value="http://127.0.0.1:8545",
        ), mock.patch.object(
            cli,
            "_require_chain_contract_address",
            return_value="0x2222222222222222222222222222222222222222",
        ), mock.patch.object(
            cli,
            "_cast_calldata",
            return_value="0xdeadbeef",
        ), mock.patch.object(
            cli.subprocess,
            "run",
            return_value=mock.Mock(returncode=0, stdout='{"transactionHash":"0x' + "ab" * 32 + '"}', stderr=""),
        ):
            code = cli.cmd_offdex_settle(args)
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
