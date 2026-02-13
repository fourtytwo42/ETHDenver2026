import argparse
import json
import unittest
from unittest import mock
from decimal import Decimal

import pathlib
import sys

RUNTIME_ROOT = pathlib.Path("apps/agent-runtime").resolve()
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))

from xclaw_agent import cli  # noqa: E402


class TradePathRuntimeTests(unittest.TestCase):
    def test_cast_send_retries_underpriced_then_succeeds(self) -> None:
        tx_obj = {
            "from": "0x1111111111111111111111111111111111111111",
            "to": "0x2222222222222222222222222222222222222222",
            "data": "0xdeadbeef",
        }
        commands: list[list[str]] = []

        def fake_run(cmd: list[str], text: bool = True, capture_output: bool = True):  # type: ignore[override]
            commands.append(cmd)
            if cmd[1] == "nonce":
                return mock.Mock(returncode=0, stdout="0x1", stderr="")
            if cmd[1] == "send":
                send_index = len([entry for entry in commands if len(entry) > 1 and entry[1] == "send"])
                if send_index == 1:
                    return mock.Mock(returncode=1, stdout="", stderr="replacement transaction underpriced")
                return mock.Mock(returncode=0, stdout='{"transactionHash":"0x' + "ab" * 32 + '"}', stderr="")
            raise AssertionError(f"Unexpected command {cmd}")

        with mock.patch.object(cli, "_require_cast_bin", return_value="cast"), mock.patch.object(
            cli.subprocess, "run", side_effect=fake_run
        ):
            tx_hash = cli._cast_rpc_send_transaction("https://rpc.example", tx_obj, "0x" + "11" * 32)

        self.assertEqual(tx_hash, "0x" + "ab" * 32)
        send_cmds = [entry for entry in commands if len(entry) > 1 and entry[1] == "send"]
        self.assertEqual(len(send_cmds), 2)
        self.assertIn("5gwei", send_cmds[0])
        self.assertIn("7gwei", send_cmds[1])

    def test_cast_send_non_retryable_error_fails_immediately(self) -> None:
        tx_obj = {
            "from": "0x1111111111111111111111111111111111111111",
            "to": "0x2222222222222222222222222222222222222222",
            "data": "0xdeadbeef",
        }
        commands: list[list[str]] = []

        def fake_run(cmd: list[str], text: bool = True, capture_output: bool = True):  # type: ignore[override]
            commands.append(cmd)
            if cmd[1] == "nonce":
                return mock.Mock(returncode=0, stdout="0x2", stderr="")
            if cmd[1] == "send":
                return mock.Mock(returncode=1, stdout="", stderr="execution reverted")
            raise AssertionError(f"Unexpected command {cmd}")

        with mock.patch.object(cli, "_require_cast_bin", return_value="cast"), mock.patch.object(
            cli.subprocess, "run", side_effect=fake_run
        ):
            with self.assertRaises(cli.WalletStoreError):
                cli._cast_rpc_send_transaction("https://rpc.example", tx_obj, "0x" + "22" * 32)

        send_cmds = [entry for entry in commands if len(entry) > 1 and entry[1] == "send"]
        self.assertEqual(len(send_cmds), 1)

    def test_cast_send_retry_budget_exhausted(self) -> None:
        tx_obj = {
            "from": "0x1111111111111111111111111111111111111111",
            "to": "0x2222222222222222222222222222222222222222",
            "data": "0xdeadbeef",
        }

        def fake_run(cmd: list[str], text: bool = True, capture_output: bool = True):  # type: ignore[override]
            if cmd[1] == "nonce":
                return mock.Mock(returncode=0, stdout="0x3", stderr="")
            if cmd[1] == "send":
                return mock.Mock(returncode=1, stdout="", stderr="nonce too low")
            raise AssertionError(f"Unexpected command {cmd}")

        with mock.patch.dict(cli.os.environ, {"XCLAW_TX_SEND_MAX_ATTEMPTS": "2"}, clear=False), mock.patch.object(
            cli, "_require_cast_bin", return_value="cast"
        ), mock.patch.object(cli.subprocess, "run", side_effect=fake_run):
            with self.assertRaises(cli.WalletStoreError) as ctx:
                cli._cast_rpc_send_transaction("https://rpc.example", tx_obj, "0x" + "33" * 32)

        self.assertIn("after 2 attempts", str(ctx.exception))

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

    def test_limit_orders_sync_success(self) -> None:
        args = argparse.Namespace(chain="hardhat_local", json=True)
        with mock.patch.object(
            cli,
            "_api_request",
            return_value=(200, {"items": [{"orderId": "lmt_1", "chainKey": "hardhat_local", "status": "open"}]}),
        ), mock.patch.object(cli, "save_limit_order_store") as save_store:
            code = cli.cmd_limit_orders_sync(args)
        self.assertEqual(code, 0)
        save_store.assert_called_once()

    def test_limit_orders_run_once_mock_fill(self) -> None:
        args = argparse.Namespace(chain="hardhat_local", json=True, sync=False)
        store = {
            "version": 1,
            "orders": [
                {
                    "orderId": "lmt_1",
                    "chainKey": "hardhat_local",
                    "status": "open",
                    "side": "buy",
                    "mode": "mock",
                    "tokenIn": "0x1111111111111111111111111111111111111111",
                    "tokenOut": "0x2222222222222222222222222222222222222222",
                    "amountIn": "1",
                    "limitPrice": "20",
                }
            ],
        }
        statuses: list[dict[str, str]] = []
        with mock.patch.object(cli, "_replay_limit_order_outbox", return_value=(0, 0)), mock.patch.object(
            cli, "load_limit_order_store", return_value=store
        ), mock.patch.object(cli, "_quote_router_price", return_value=Decimal("10")), mock.patch.object(
            cli,
            "_post_limit_order_status",
            side_effect=lambda order_id, payload, queue_on_failure=True: statuses.append({"orderId": order_id, "status": str(payload.get("status"))}),
        ):
            code = cli.cmd_limit_orders_run_once(args)
        self.assertEqual(code, 0)
        self.assertEqual([entry["status"] for entry in statuses], ["triggered", "filled"])

    def test_limit_orders_run_once_real_failure_reports_failed(self) -> None:
        args = argparse.Namespace(chain="hardhat_local", json=True, sync=False)
        store = {
            "version": 1,
            "orders": [
                {
                    "orderId": "lmt_1",
                    "chainKey": "hardhat_local",
                    "status": "open",
                    "side": "sell",
                    "mode": "real",
                    "tokenIn": "0x1111111111111111111111111111111111111111",
                    "tokenOut": "0x2222222222222222222222222222222222222222",
                    "amountIn": "1",
                    "limitPrice": "1",
                }
            ],
        }
        statuses: list[str] = []
        with mock.patch.object(cli, "_replay_limit_order_outbox", return_value=(0, 0)), mock.patch.object(
            cli, "load_limit_order_store", return_value=store
        ), mock.patch.object(cli, "_quote_router_price", return_value=Decimal("2")), mock.patch.object(
            cli, "_execute_limit_order_real", side_effect=cli.WalletStoreError("rpc down")
        ), mock.patch.object(
            cli,
            "_post_limit_order_status",
            side_effect=lambda order_id, payload, queue_on_failure=True: statuses.append(str(payload.get("status"))),
        ):
            code = cli.cmd_limit_orders_run_once(args)
        self.assertEqual(code, 0)
        self.assertEqual(statuses, ["triggered", "failed"])


if __name__ == "__main__":
    unittest.main()
