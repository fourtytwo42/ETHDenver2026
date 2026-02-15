import argparse
import io
import json
import unittest
from unittest import mock
from decimal import Decimal

from contextlib import redirect_stdout

import pathlib
import sys

RUNTIME_ROOT = pathlib.Path("apps/agent-runtime").resolve()
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))

from xclaw_agent import cli  # noqa: E402


class TradePathRuntimeTests(unittest.TestCase):
    def _run_and_parse_stdout(self, fn) -> dict:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = fn()
        self.assertIsInstance(code, int)
        raw = buf.getvalue().strip()
        self.assertTrue(raw, "expected JSON on stdout")
        return json.loads(raw)

    def test_cast_send_retries_underpriced_then_succeeds(self) -> None:
        tx_obj = {
            "from": "0x1111111111111111111111111111111111111111",
            "to": "0x2222222222222222222222222222222222222222",
            "data": "0xdeadbeef",
        }
        commands: list[list[str]] = []

        def fake_run(cmd: list[str], text: bool = True, capture_output: bool = True, **kwargs):  # type: ignore[override]
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
        self.assertIn("10gwei", send_cmds[1])

    def test_cast_send_non_retryable_error_fails_immediately(self) -> None:
        tx_obj = {
            "from": "0x1111111111111111111111111111111111111111",
            "to": "0x2222222222222222222222222222222222222222",
            "data": "0xdeadbeef",
        }
        commands: list[list[str]] = []

        def fake_run(cmd: list[str], text: bool = True, capture_output: bool = True, **kwargs):  # type: ignore[override]
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

        def fake_run(cmd: list[str], text: bool = True, capture_output: bool = True, **kwargs):  # type: ignore[override]
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

    def test_trade_execute_rejects_mock_mode(self) -> None:
        args = argparse.Namespace(intent="trd_1", chain="hardhat_local", json=True)
        trade_payload = {
            "tradeId": "trd_1",
            "chainKey": "hardhat_local",
            "status": "approved",
            "mode": "mock",
            "retry": {"eligible": False},
        }
        with mock.patch.object(cli, "_read_trade_details", return_value=trade_payload), mock.patch.object(
            cli, "_post_trade_status"
        ) as post_mock:
            payload = self._run_and_parse_stdout(lambda: cli.cmd_trade_execute(args))
        self.assertFalse(payload.get("ok"))
        self.assertEqual(payload.get("code"), "unsupported_mode")
        post_mock.assert_not_called()

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

    def test_report_send_deprecated(self) -> None:
        args = argparse.Namespace(trade="trd_1", json=True)
        with mock.patch.object(
            cli,
            "_read_trade_details",
            return_value={"tradeId": "trd_1", "agentId": "agt_1", "status": "filled", "mode": "mock", "chainKey": "hardhat_local", "reasonCode": None},
        ), mock.patch.object(cli, "_api_request") as api_mock:
            payload = self._run_and_parse_stdout(lambda: cli.cmd_report_send(args))
        self.assertFalse(payload.get("ok"))
        self.assertEqual(payload.get("code"), "report_send_deprecated")
        api_mock.assert_not_called()

    def test_report_send_rejects_real_trade(self) -> None:
        args = argparse.Namespace(trade="trd_real_1", json=True)
        with mock.patch.object(
            cli,
            "_read_trade_details",
            return_value={"tradeId": "trd_real_1", "agentId": "agt_1", "status": "filled", "mode": "real", "chainKey": "base_sepolia"},
        ), mock.patch.object(cli, "_api_request") as api_mock:
            code = cli.cmd_report_send(args)
        self.assertEqual(code, 1)
        api_mock.assert_not_called()

    def test_chat_poll_success(self) -> None:
        args = argparse.Namespace(chain="hardhat_local", json=True)
        with mock.patch.object(
            cli,
            "_api_request",
            return_value=(200, {"items": [{"messageId": "msg_1", "agentId": "ag_1", "message": "Watching WETH/USDC"}]}),
        ):
            code = cli.cmd_chat_poll(args)
        self.assertEqual(code, 0)

    def test_chat_post_success(self) -> None:
        args = argparse.Namespace(message=" Watching WETH/USDC ", chain="hardhat_local", tags="idea,alpha", json=True)
        with mock.patch.object(
            cli,
            "_resolve_api_key",
            return_value="xak1.ag_1.sig.payload",
        ), mock.patch.object(
            cli,
            "_resolve_agent_id",
            return_value="ag_1",
        ), mock.patch.object(
            cli,
            "_api_request",
            return_value=(200, {"item": {"messageId": "msg_1"}}),
        ):
            code = cli.cmd_chat_post(args)
        self.assertEqual(code, 0)

    def test_chat_post_rejects_empty_message(self) -> None:
        args = argparse.Namespace(message="   ", chain="hardhat_local", tags=None, json=True)
        code = cli.cmd_chat_post(args)
        self.assertEqual(code, 1)

    def test_faucet_request_success(self) -> None:
        args = argparse.Namespace(chain="base_sepolia", json=True)
        with mock.patch.object(cli, "_resolve_api_key", return_value="xak1.ag_1.sig.payload"), mock.patch.object(
            cli, "_resolve_agent_id", return_value="ag_1"
        ), mock.patch.object(
            cli, "_api_request", return_value=(200, {"amountWei": "50000000000000000", "txHash": "0x" + "ab" * 32})
        ):
            payload = self._run_and_parse_stdout(lambda: cli.cmd_faucet_request(args))
        self.assertTrue(payload.get("ok"))
        self.assertEqual(payload.get("code"), "ok")
        self.assertEqual(payload.get("chain"), "base_sepolia")
        self.assertEqual(payload.get("pending"), True)
        self.assertIsInstance(payload.get("recommendedDelaySec"), int)
        self.assertIsInstance(payload.get("nextAction"), str)

    def test_status_includes_agent_name_best_effort(self) -> None:
        args = argparse.Namespace(json=True)
        with mock.patch.dict(cli.os.environ, {"XCLAW_DEFAULT_CHAIN": "base_sepolia", "XCLAW_API_BASE_URL": "https://xclaw.trade"}, clear=False), mock.patch.object(
            cli, "_resolve_api_key", return_value="xak1.ag_1.sig.payload"
        ), mock.patch.object(cli, "_resolve_agent_id", return_value="ag_1"), mock.patch.object(
            cli, "_wallet_address_for_chain", return_value="0x" + "11" * 20
        ), mock.patch.object(
            cli,
            "_http_json_request",
            return_value=(200, {"agent": {"agent_id": "ag_1", "agent_name": "harvey-ops"}}),
        ):
            payload = self._run_and_parse_stdout(lambda: cli.cmd_status(args))
        self.assertTrue(payload.get("ok"))
        self.assertEqual(payload.get("agentId"), "ag_1")
        self.assertEqual(payload.get("agentName"), "harvey-ops")

    def test_limit_orders_run_loop_emits_single_json(self) -> None:
        args = argparse.Namespace(chain="base_sepolia", sync=False, interval_sec=1, iterations=1, json=True)

        def fake_run_once(nested):
            return cli.ok("Limit-order run completed.", chain=nested.chain, synced=False, replayed=0, outboxRemaining=0, executed=0, skipped=0)

        with mock.patch.object(cli, "cmd_limit_orders_run_once", side_effect=fake_run_once):
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = cli.cmd_limit_orders_run_loop(args)
        self.assertEqual(code, 0)
        raw_lines = [line for line in buf.getvalue().splitlines() if line.strip()]
        self.assertEqual(len(raw_lines), 1)
        parsed = json.loads(raw_lines[0])
        self.assertTrue(parsed.get("ok"))
        self.assertEqual(parsed.get("code"), "ok")

    def test_trade_spot_builds_quote_and_swap_calls(self) -> None:
        args = argparse.Namespace(
            chain="base_sepolia",
            token_in="0x" + "11" * 20,
            token_out="0x" + "22" * 20,
            amount_in="500",
            slippage_bps="50",
            to=None,
            deadline_sec=120,
            json=True,
        )

        commands: list[list[str]] = []

        def fake_run(cmd: list[str], text: bool = True, capture_output: bool = True, **kwargs):  # type: ignore[override]
            commands.append(cmd)
            # Quote call
            if cmd[:3] == ["cast", "call", "--rpc-url"] and "getAmountsOut(uint256,address[])(uint256[])" in cmd:
                # last uint is treated as amountOut by parser.
                return mock.Mock(returncode=0, stdout="(uint256[]) [500000000000000000000,20000000000000000000]\n", stderr="")
            # Approve receipt
            if len(cmd) >= 2 and cmd[1] == "receipt":
                return mock.Mock(returncode=0, stdout='{"status":"0x1"}', stderr="")
            raise AssertionError(f"Unexpected command {cmd}")

        def fake_send(rpc_url: str, tx_obj: dict, private_key_hex: str) -> str:
            # First send = approve, second send = swap
            return "0x" + ("ab" * 32)

        with mock.patch.object(cli, "_execution_wallet", return_value=("0x" + "aa" * 20, "0x" + "33" * 32)), mock.patch.object(
            cli, "_require_cast_bin", return_value="cast"
        ), mock.patch.object(cli, "_chain_rpc_url", return_value="https://rpc.example"), mock.patch.object(
            cli, "_require_chain_contract_address", return_value="0x" + "44" * 20
        ), mock.patch.object(cli, "_fetch_erc20_metadata", side_effect=[{"decimals": 18, "symbol": "USDC"}, {"decimals": 18, "symbol": "WETH"}]), mock.patch.object(
            cli, "_fetch_token_allowance_wei", return_value=str(10**30)
        ), mock.patch.object(
            cli, "_enforce_spend_preconditions", return_value=({}, "2026-02-14", 0, 10**30)
        ), mock.patch.object(
            cli, "_record_spend"
        ), mock.patch.object(
            cli, "_cast_calldata", return_value="0xdeadbeef"
        ), mock.patch.object(
            cli, "_cast_rpc_send_transaction", side_effect=fake_send
        ), mock.patch.object(
            cli.subprocess, "run", side_effect=fake_run
        ):
            code = cli.cmd_trade_spot(args)

        self.assertEqual(code, 0)
        # Ensure we quoted via getAmountsOut at least once.
        self.assertTrue(any("getAmountsOut(uint256,address[])(uint256[])" in " ".join(cmd) for cmd in commands))

    def test_trade_spot_rejects_bad_slippage(self) -> None:
        args = argparse.Namespace(
            chain="base_sepolia",
            token_in="0x" + "11" * 20,
            token_out="0x" + "22" * 20,
            amount_in="500",
            slippage_bps="9001",
            to=None,
            deadline_sec=120,
            json=True,
        )
        code = cli.cmd_trade_spot(args)
        self.assertEqual(code, 2)

    def test_faucet_request_daily_limited(self) -> None:
        args = argparse.Namespace(chain="base_sepolia", json=True)
        with mock.patch.object(cli, "_resolve_api_key", return_value="xak1.ag_1.sig.payload"), mock.patch.object(
            cli, "_resolve_agent_id", return_value="ag_1"
        ), mock.patch.object(
            cli,
            "_api_request",
            return_value=(
                429,
                {
                    "code": "rate_limited",
                    "message": "Faucet request limit reached for today.",
                    "actionHint": "Retry after next UTC day begins.",
                    "details": {"retryAfterSeconds": 123},
                },
            ),
        ):
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = cli.cmd_faucet_request(args)
        self.assertEqual(code, 1)
        out = json.loads(buf.getvalue().strip())
        self.assertFalse(out.get("ok"))
        self.assertEqual(out.get("code"), "rate_limited")
        self.assertEqual(out.get("retryAfterSec"), 123)
        details = out.get("details") or {}
        self.assertEqual((details.get("apiDetails") or {}).get("retryAfterSeconds"), 123)

    def test_limit_orders_create_omits_expires_at_when_missing(self) -> None:
        args = argparse.Namespace(
            chain="base_sepolia",
            mode="real",
            side="buy",
            token_in="USDC",
            token_out="WETH",
            amount_in="10",
            limit_price="2500",
            slippage_bps="300",
            expires_at=None,
            json=True,
        )

        captured: dict = {}

        def fake_api_request(method: str, path: str, payload: dict | None = None, include_idempotency: bool = False):
            captured["method"] = method
            captured["path"] = path
            captured["payload"] = payload
            return 200, {"orderId": "lmt_1", "status": "open"}

        with mock.patch.object(cli, "_resolve_token_address", side_effect=["0x" + "11" * 20, "0x" + "22" * 20]), mock.patch.object(
            cli, "_resolve_api_key", return_value="xak1.ag_1.sig.payload"
        ), mock.patch.object(cli, "_resolve_agent_id", return_value="ag_1"), mock.patch.object(cli, "_api_request", side_effect=fake_api_request):
            payload = self._run_and_parse_stdout(lambda: cli.cmd_limit_orders_create(args))

        self.assertTrue(payload.get("ok"))
        sent = captured.get("payload") or {}
        self.assertNotIn("expiresAt", sent)

    def test_limit_orders_create_surfaces_api_details(self) -> None:
        args = argparse.Namespace(
            chain="base_sepolia",
            mode="real",
            side="buy",
            token_in="USDC",
            token_out="WETH",
            amount_in="10",
            limit_price="2500",
            slippage_bps="300",
            expires_at="not-a-date",
            json=True,
        )

        api_body = {
            "code": "payload_invalid",
            "message": "Limit-order create payload does not match schema.",
            "actionHint": "Provide valid fields.",
            "requestId": "req_123",
            "details": {"issues": [{"path": "/expiresAt", "message": "must be date-time"}]},
        }

        def fake_api_request(method: str, path: str, payload: dict | None = None, include_idempotency: bool = False):
            return 400, api_body

        with mock.patch.object(cli, "_resolve_token_address", side_effect=["0x" + "11" * 20, "0x" + "22" * 20]), mock.patch.object(
            cli, "_resolve_api_key", return_value="xak1.ag_1.sig.payload"
        ), mock.patch.object(cli, "_resolve_agent_id", return_value="ag_1"), mock.patch.object(cli, "_api_request", side_effect=fake_api_request):
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = cli.cmd_limit_orders_create(args)
        self.assertEqual(code, 1)
        out = json.loads(buf.getvalue().strip())
        self.assertFalse(out.get("ok"))
        self.assertEqual(out.get("code"), "payload_invalid")
        details = out.get("details") or {}
        self.assertEqual(details.get("requestId"), "req_123")
        self.assertIn("apiDetails", details)

    def test_profile_set_name_success(self) -> None:
        args = argparse.Namespace(name="harvey-ops", chain="hardhat_local", json=True)
        with mock.patch.object(cli, "_resolve_api_key", return_value="xak1.ag_1.sig.payload"), mock.patch.object(
            cli, "_resolve_agent_id", return_value="ag_1"
        ), mock.patch.object(cli, "_wallet_address_for_chain", return_value="0x1111111111111111111111111111111111111111"), mock.patch.object(
            cli, "_api_request", return_value=(200, {"agentName": "harvey-ops"})
        ):
            code = cli.cmd_profile_set_name(args)
        self.assertEqual(code, 0)

    def test_profile_set_name_rejects_empty_name(self) -> None:
        args = argparse.Namespace(name="   ", chain="hardhat_local", json=True)
        code = cli.cmd_profile_set_name(args)
        self.assertEqual(code, 1)

    def test_profile_set_name_rate_limited(self) -> None:
        args = argparse.Namespace(name="new-name", chain="hardhat_local", json=True)
        with mock.patch.object(cli, "_resolve_api_key", return_value="xak1.ag_1.sig.payload"), mock.patch.object(
            cli, "_resolve_agent_id", return_value="ag_1"
        ), mock.patch.object(cli, "_wallet_address_for_chain", return_value="0x1111111111111111111111111111111111111111"), mock.patch.object(
            cli,
            "_api_request",
            return_value=(
                429,
                {
                    "code": "rate_limited",
                    "message": "Agent name can only be changed once every 7 days.",
                    "actionHint": "Retry after cooldown.",
                },
            ),
        ):
            code = cli.cmd_profile_set_name(args)
        self.assertEqual(code, 1)

    def test_management_link_normalizes_loopback_host_to_public_domain(self) -> None:
        args = argparse.Namespace(ttl_seconds=600, json=True)
        with mock.patch.object(cli, "_resolve_api_key", return_value="xak1.ag_1.sig.payload"), mock.patch.object(
            cli, "_resolve_agent_id", return_value="ag_1"
        ), mock.patch.object(
            cli,
            "_api_request",
            return_value=(
                200,
                {
                    "agentId": "ag_1",
                    "managementUrl": "https://127.0.0.1:3000/agents/ag_1?token=ol1.test.token",
                    "issuedAt": "2026-02-14T22:00:00.000Z",
                    "expiresAt": "2026-02-14T22:10:00.000Z",
                },
            ),
        ):
            payload = self._run_and_parse_stdout(lambda: cli.cmd_management_link(args))
        self.assertEqual(payload.get("ok"), True)
        self.assertEqual(payload.get("managementUrl"), "https://xclaw.trade/agents/ag_1?token=ol1.test.token")

    def test_dashboard_success(self) -> None:
        args = argparse.Namespace(chain="hardhat_local", json=True)

        def fake_api_request(method: str, path: str, payload=None, include_idempotency: bool = False, allow_auth_recovery: bool = True):
            if path.startswith("/public/agents/ag_1/trades"):
                return (200, {"items": [{"trade_id": "trd_1"}]})
            if path == "/public/agents/ag_1":
                return (200, {"agent": {"agent_id": "ag_1", "agent_name": "harvey"}})
            if path.startswith("/trades/pending"):
                return (200, {"items": [{"tradeId": "trd_pending_1"}]})
            if path.startswith("/limit-orders?"):
                return (200, {"items": [{"orderId": "ord_1"}]})
            if path.startswith("/chat/messages"):
                return (200, {"items": [{"messageId": "msg_1"}]})
            return (500, {"code": "api_error", "message": path})

        with mock.patch.object(cli, "_resolve_api_key", return_value="xak1.ag_1.sig.payload"), mock.patch.object(
            cli, "_resolve_agent_id", return_value="ag_1"
        ), mock.patch.object(
            cli, "_fetch_wallet_holdings", return_value={"address": "0x1111111111111111111111111111111111111111"}
        ), mock.patch.object(
            cli, "_api_request", side_effect=fake_api_request
        ):
            code = cli.cmd_dashboard(args)
        self.assertEqual(code, 0)

    def test_dashboard_handles_holdings_failure(self) -> None:
        args = argparse.Namespace(chain="hardhat_local", json=True)

        def fake_api_request(method: str, path: str, payload=None, include_idempotency: bool = False, allow_auth_recovery: bool = True):
            if path == "/public/agents/ag_1":
                return (200, {"agent": {"agent_id": "ag_1", "agent_name": "harvey"}})
            return (200, {"items": []})

        with mock.patch.object(cli, "_resolve_api_key", return_value="xak1.ag_1.sig.payload"), mock.patch.object(
            cli, "_resolve_agent_id", return_value="ag_1"
        ), mock.patch.object(
            cli, "_fetch_wallet_holdings", side_effect=cli.WalletStoreError("wallet missing")
        ), mock.patch.object(
            cli, "_api_request", side_effect=fake_api_request
        ):
            code = cli.cmd_dashboard(args)
        self.assertEqual(code, 0)

    def test_trade_execute_real_does_not_auto_report(self) -> None:
        args = argparse.Namespace(intent="trd_real_1", chain="base_sepolia", json=True)
        trade_payload = {
            "tradeId": "trd_real_1",
            "chainKey": "base_sepolia",
            "status": "approved",
            "mode": "real",
            "retry": {"eligible": False},
            "tokenIn": "0x1111111111111111111111111111111111111111",
            "tokenOut": "0x2222222222222222222222222222222222222222",
            "amountIn": "1",
            "slippageBps": 50,
        }
        with mock.patch.object(cli, "_read_trade_details", return_value=trade_payload), mock.patch.object(
            cli, "_enforce_spend_preconditions", return_value=({}, "2026-02-14", 0, 1000000000)
        ), mock.patch.object(
            cli, "_execution_wallet", return_value=("0x1111111111111111111111111111111111111111", "11" * 32)
        ), mock.patch.object(
            cli, "_require_chain_contract_address", return_value="0x3333333333333333333333333333333333333333"
        ), mock.patch.object(
            cli, "_cast_calldata", return_value="0xdeadbeef"
        ), mock.patch.object(
            cli, "_cast_rpc_send_transaction", return_value="0x" + "ab" * 32
        ), mock.patch.object(
            cli.subprocess, "run", return_value=mock.Mock(returncode=0, stdout='{"status":"0x1"}', stderr="")
        ), mock.patch.object(
            cli, "_post_trade_status"
        ), mock.patch.object(
            cli, "_record_spend"
        ), mock.patch.object(
            cli, "_send_trade_execution_report"
        ) as report_mock:
            code = cli.cmd_trade_execute(args)
        self.assertEqual(code, 0)
        report_mock.assert_not_called()

    def test_removed_offdex_command_is_not_available(self) -> None:
        with self.assertRaises(SystemExit):
            cli.main(["offdex"])

    def test_wallet_create_command_is_not_available(self) -> None:
        # Wallet create exists for installer/bootstrap, but should fail in non-interactive
        # mode when passphrase is not provided.
        args = argparse.Namespace(chain="hardhat_local", json=True)
        code = cli.cmd_wallet_create(args)
        self.assertNotEqual(code, 0)

    def test_wallet_import_command_is_not_available(self) -> None:
        with self.assertRaises(SystemExit):
            cli.main(["wallet", "import", "--chain", "hardhat_local", "--json"])

    def test_wallet_remove_command_is_not_available(self) -> None:
        with self.assertRaises(SystemExit):
            cli.main(["wallet", "remove", "--chain", "hardhat_local", "--json"])

    def test_wallet_send_token_command_parses(self) -> None:
        with mock.patch.object(cli, "cmd_wallet_send_token", return_value=0):
            code = cli.main(
                [
                    "wallet",
                    "send-token",
                    "--token",
                    "0x1111111111111111111111111111111111111111",
                    "--to",
                    "0x2222222222222222222222222222222222222222",
                    "--amount-wei",
                    "1",
                    "--chain",
                    "hardhat_local",
                    "--json",
                ]
            )
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
        self.assertEqual([entry["status"] for entry in statuses], ["failed"])

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
