"""DeFi-specific smart contract analysis.

The generic Solidity audit finds the classic bugs. DeFi adds a second
layer of failures that are specific to how value moves through a
protocol, and they are worth a great deal of money:

- **Oracle manipulation** - a price feed that any single address can
  push is a price feed that will be pushed. The classic pattern is
  `latestRoundData` being read with no staleness check and no check on
  the round.
- **Unchecked token transfers** - most ERC-20 tokens can return `false`
  instead of reverting, and a protocol that ignores the return value
  believes it moved funds that never moved.
- **Front-running and sandwiching** - a constant-product AMM with a
  public price function and no slippage parameter is a sandwich waiting
  to happen. A `swap` with no `amountOutMin` has no slippage bound at
  all.
- **Reentrancy through token callbacks** - `transferFrom` and the ERC-777
  hooks call back into the recipient, so a reentrancy guard that only
  covers the obvious entry point is not enough.
- **Flash-loan economic attacks** - a pool with no borrow fee and a
  price derived from the same pool is manipulable within one block.
- **Missing event emission** - a state change with no event cannot be
  monitored, and a protocol that cannot be monitored cannot be secured.
- **Unchecked low-level `call` in a payment path** - a payment that
  silently fails is a protocol that accepts deliveries for free.
"""

from __future__ import annotations

import re
from pathlib import Path

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import ScanContext
from .solidity import SolidityAuditModule

#: A call to a token transfer that ignores the return value.
TOKEN_TRANSFER = re.compile(
    r"^\s*(?:\w+\s*=\s*)?\w+\.(transfer|transferFrom|safeTransfer|safeTransferFrom)\s*\("
)

#: A swap-like function that takes no slippage bound.
SLIPPAGE_FUNCTIONS = ("swap", "exchange", "trade", "convert")

#: A price read with no staleness or round check.
ORACLE_READS = re.compile(
    r"(latestRoundData|latestAnswer|getPrice|getRate|getLatestPrice|consult)\s*\("
)

#: Checks that make an oracle read safe.
ORACLE_GUARDS = (
    "updatedAt",
    "answeredInRound",
    "roundId",
    "timestamp",
    "stale",
    "heartbeat",
    "staleness",
)

#: A function that reads the pool's own reserves to price a trade.
AMM_PRICING = re.compile(
    r"(getReserves|reserve0|reserve1|getAmountOut|getAmountIn|slot0)\s*\("
)

#: A callback that a token hook can reach.
CALLBACK_HOOKS = ("tokensReceived", "onTokenTransfer", "onERC721Received", "onERC1155Received")

#: A state change with no event nearby.
EVENT_DECL = re.compile(r"\bevent\s+\w+")


class DefiSecurityModule(SolidityAuditModule):
    """Audits DeFi contracts for protocol-specific value failures."""

    group = "blockchain"
    id = "defi_security"
    name = "DeFi Security"
    description = (
        "Audits DeFi contracts for the failures that are specific to "
        "protocols that move value: manipulable oracles, unchecked token "
        "transfers, swaps with no slippage bound, and prices derived from "
        "the pool being traded."
    )
    severity = Severity.CRITICAL
    confidence = Confidence.MEDIUM
    category = Category.BUG
    capability = Capability.CODE
    cwe = "CWE-682"
    owasp = "A04"
    tags = ["defi", "solidity", "evm", "oracle", "amm", "flash-loan", "web3"]
    remediation = (
        "Read prices through an oracle that aggregates and checks "
        "staleness, and bound every swap with an amountOutMin derived from "
        "a trusted price. Check the return value of every token transfer, "
        "and use a reentrancy guard that covers every externally callable "
        "entry point, including the token callbacks."
    )
    references = [
        "https://scs.owasp.org/SCWE/SCWE-003/",
        "https://consensysdiligence.github.io/smart-contract-best-practices/",
        "https://samczsun.com/so-you-want-to-use-a-price-oracle/",
    ]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.code_path:
            return []
        root = Path(ctx.code_path)
        findings: list[Finding] = []
        for path in self._solidity_files(root)[: self.max_files]:
            findings.extend(self._defi_findings(path, root))
        return findings

    def _finding(
        self,
        relative: str,
        line_number: int,
        severity: Severity,
        title: str,
        description: str,
    ) -> Finding:
        """A DeFi finding.

        The base class orders the arguments differently, and the DeFi
        checks read better with the severity first - the severity is
        what the reader looks at.
        """
        return self.finding(
            title=title,
            target=relative,
            description=description,
            severity=severity,
            confidence=Confidence.MEDIUM,
            evidence_text=f"{relative}:{line_number}\n{title}",
            matched=title,
            file=relative,
            line=line_number,
        )

    def _defi_findings(self, path: Path, root: Path) -> list[Finding]:
        from ..code.common import read_lines

        lines = read_lines(path)
        if not lines:
            return []
        relative = str(path.relative_to(root)) if root in path.parents else str(path)
        text = "\n".join(lines)
        findings: list[Finding] = []

        functions = self._functions(lines)

        for name, start, _end, body in functions:
            body_text = "\n".join(body)
            lowered_name = name.lower()

            # 1. A token transfer whose return value is thrown away.
            for offset, line in enumerate(body):
                if not TOKEN_TRANSFER.match(line):
                    continue
                if "require(" in line or "if (" in line or "assert" in line:
                    continue
                if re.search(r"=\s*\w+\.(transfer|transferFrom)\s*\(", line):
                    continue
                if re.search(
                    r"(require|if)\s*\(?\s*\w+\.(transfer|transferFrom)", body_text
                ):
                    continue
                findings.append(
                    self._finding(
                        relative,
                        start + offset,
                        Severity.HIGH,
                        f"Unchecked token transfer in '{name}'",
                        f"'{name}' calls a token transfer and ignores the "
                        f"result. Most ERC-20 tokens return false rather "
                        f"than reverting, so this code path continues as if "
                        f"the funds moved when they did not. A protocol that "
                        f"credits an account without receiving the tokens is "
                        f"worth more on paper than in the bank.",
                    )
                )
                break

            # 2. A swap with no slippage bound.
            if any(lowered_name.startswith(verb) for verb in SLIPPAGE_FUNCTIONS) and not any(
                guard in body_text
                for guard in ("amountOutMin", "minAmountOut", "amountOutMinimum", "slippage", "minReturn")
            ):
                findings.append(
                        self._finding(
                            relative,
                            start,
                            Severity.HIGH,
                            f"Swap function '{name}' has no slippage bound",
                            f"'{name}' swaps without a minimum output. A "
                            f"transaction that can be included in a bundle "
                            f"can be sandwiched: the attacker buys before it "
                            f"and sells after it, and the protocol absorbs "
                            f"the difference. An explicit amountOutMin is "
                            f"the only thing that stops it.",
                        )
                    )

            # 3. A price read with no staleness check.
            if ORACLE_READS.search(body_text) and not any(
                guard in body_text for guard in ORACLE_GUARDS
            ):
                findings.append(
                    self._finding(
                        relative,
                        start,
                        Severity.CRITICAL,
                        f"Oracle price used without a staleness check in '{name}'",
                        f"'{name}' reads a price from an oracle and never "
                        f"asks how old the answer is. A price feed that a "
                        f"single transaction can move is a price feed that "
                        f"will be moved, and the protocol will act on the "
                        f"moved price.",
                    )
                )

            # 4. A price derived from the pool being traded.
            if AMM_PRICING.search(body_text) and any(
                verb in lowered_name for verb in SLIPPAGE_FUNCTIONS
            ):
                findings.append(
                    self._finding(
                        relative,
                        start,
                        Severity.HIGH,
                        f"'{name}' prices a trade from the pool's own reserves",
                        "The price is derived from the same reserves the "
                        "trade changes, so the attacker sets the price by "
                        "making the trade. Within a single block that is "
                        "worth an unbounded amount.",
                    )
                )

            # 5. A reentrancy-relevant token callback.
            for hook in CALLBACK_HOOKS:
                if hook in body_text:
                    findings.append(
                        self._finding(
                            relative,
                            start,
                            Severity.HIGH,
                            f"Token callback '{hook}' is reachable",
                            f"'{name}' implements {hook}, which the token "
                            f"calls back into during a transfer. A "
                            f"reentrancy guard that only covers the obvious "
                            f"entry point does not cover this one.",
                        )
                    )
                    break

        # 6. A state change with no event anywhere in the contract.
        if EVENT_DECL.search(text) is None and "function" in text:
            findings.append(
                self._finding(
                    relative,
                    1,
                    Severity.MEDIUM,
                    "Contract emits no events",
                    "A contract that changes state without emitting an "
                    "event cannot be monitored. Indexers, keepers and "
                    "incident responders all depend on the events, and a "
                    "protocol nobody can watch is a protocol nobody can "
                    "defend.",
                )
            )

        return findings
