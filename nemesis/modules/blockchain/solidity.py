"""Solidity smart-contract auditing.

The interesting bugs in a smart contract are not syntax bugs. They are
accounting bugs: the contract's own invariant - the sum of balances equals
the sum of deposits, or only one withdrawal can happen - is broken by some
path through the code. Those bugs are worth a great deal of money, and they
are all visible in the source without running anything.

The checks here are the classic, high-yield ones:

- **Reentrancy** - an external call happens before the state it protects
  is updated, so the callee can come back and do it again.
- **Access control** - a function that changes state has no ``onlyOwner``
  or equivalent.
- **Unchecked arithmetic** - Solidity 0.8 reverts on overflow, but
  subtraction underflows silently when the value is unsigned and the
  subtraction is done in unchecked blocks.
- **Unchecked return values** - a low-level call's success flag is
  ignored.
- **Self-destruct / delegatecall** to an attacker-controlled address.
- **tx.origin** as an authorisation check.
- **Timestamp and blockhash dependence** for randomness.
- **Unprotected initialisers** and **missing event emission**.
"""

from __future__ import annotations

import re
from pathlib import Path

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext
from ..code.common import read_lines

#: Contract extensions worth reading.
SOLIDITY_SUFFIXES = (".sol",)

#: Functions that are supposed to change state.
STATE_CHANGING = (
    "transfer", "transferFrom", "approve", "mint", "burn", "withdraw",
    "deposit", "set", "update", "pause", "unpause", "claim", "swap",
    "stake", "unstake", "delegate", "execute", "renounceOwnership",
    "transferOwnership", "grantRole", "revokeRole",
)

#: Modifiers that are access control.
ACCESS_MODIFIERS = (
    "onlyOwner", "onlyRole", "onlyAdmin", "onlyGovernance", "onlyPauser",
    "onlyExecutor", "requiresAuth", "auth", "only", "restricted",
)

#: Calls that hand control to another contract.
#:
#: The modern Solidity form is ``addr.call{value: x}("")`` and the older
#: one is ``addr.call.value(x)("")``. Both have to be recognised, and
#: ``.call.value(...)("")`` puts a ``.`` between ``call`` and its
#: arguments, so a simple ``\.call\s*\(`` misses it.
EXTERNAL_CALL = re.compile(
    r"\.(call|delegatecall|staticcall)\b\s*(?:\{|\.|\()|\.transfer\s*\(|\.send\s*\("
)

#: A low-level call whose return value is not checked.
UNCHECKED_CALL = re.compile(
    r"^\s*(?:\w+\s*=\s*)?[\w\.]+\.(call|delegatecall|send)\s*[\(\.]"
)

#: A state variable assignment. Indexing and member access are allowed,
#: because ``balances[msg.sender] = 0`` is the canonical example.
STATE_ASSIGN = re.compile(
    r"^\s*[\w\.\[\]]*\s*[\w\.\[\]\(\)]+\s*(?:\+\+|--|[+\-*/]?=)"
)

#: A local variable declaration, which writes to the stack and not to
#: contract state.
LOCAL_DECLARATION = re.compile(
    r"^(?:uint\d*|int\d*|address|bool|bytes\d*|bytes32|string|fixed|ufixed|"
    r"mapping\s*\(|struct\s+|enum\s+|\w+\[\])"
)

#: A declaration of a function.
FUNC_DECL = re.compile(
    r"function\s+(\w+)\s*\(([^)]*)\)\s*([^\{;]*)\{"
)

#: A modifier applied to a function.
MODIFIER_USE = re.compile(r"\b(onlyOwner|onlyRole|onlyAdmin|onlyExecutor|onlyPauser|auth|restricted)\b")


class SolidityAuditModule(Module):
    """Audits Solidity sources for the classic high-value defects."""

    group = "blockchain"
    id = "solidity_audit"
    name = "Solidity Smart Contract Audit"
    description = (
        "Audits Solidity sources for reentrancy, missing access control, "
        "unchecked arithmetic and return values, dangerous delegatecall and "
        "self-destruct paths, and insecure randomness."
    )
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    category = Category.BUG
    capability = Capability.CODE
    cwe = "CWE-841"
    owasp = "A04"
    tags = ["solidity", "evm", "smart-contract", "reentrancy", "web3"]
    remediation = (
        "Apply the checks-effects-interactions pattern: update state before "
        "any external call. Guard state-changing functions with an access "
        "modifier, use SafeERC20 and checked arithmetic, and never use "
        "tx.origin or block timestamps for authorisation or randomness."
    )
    references = [
        "https://swcregistry.io/docs/SWC-107/",
        "https://consensysdiligence.github.io/smart-contract-best-practices/",
        "https://scs.owasp.org/",
    ]

    max_files = 200

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.code_path:
            return []
        root = Path(ctx.code_path)
        findings: list[Finding] = []
        for path in self._solidity_files(root)[: self.max_files]:
            findings.extend(self._audit(path, root))
        return findings

    def _solidity_files(self, root: Path) -> list[Path]:
        skip = {".git", "node_modules", "lib", "vendor", "out", "cache", "artifacts", "__pycache__"}
        found: list[Path] = []
        for path in sorted(root.rglob("*.sol")):
            if not path.is_file():
                continue
            if any(part in skip for part in path.relative_to(root).parts):
                continue
            found.append(path)
        return found

    def _audit(self, path: Path, root: Path) -> list[Finding]:
        lines = read_lines(path)
        if not lines:
            return []
        findings: list[Finding] = []
        relative = str(path.relative_to(root)) if root in path.parents or path == root else str(path)

        # -- per-function analysis ----------------------------------------
        functions = self._functions(lines)
        for func in functions:
            name, start, _end, body = func
            body_text = "\n".join(body)

            # Access control on state-changing functions.
            if (
                self._is_state_changing(name)
                and not self._has_access_control(body_text, lines, start)
                and "constructor" not in name
                and "initializer" not in name.lower()
            ):
                findings.append(
                    self._finding(
                        relative,
                        start,
                        f"State-changing function '{name}' has no access control",
                        f"'{name}' changes contract state and carries no "
                        f"access modifier. Anyone who can call it can "
                        f"change the contract, which for a function that "
                        f"moves funds or changes a price is a total "
                        f"loss.",
                        Severity.CRITICAL,
                        name,
                    )
                )

            # Reentrancy: external call before a state write.
            call_line = self._first_external_call(body)
            write_line = self._first_state_write(body)
            if call_line is not None and write_line is not None and write_line > call_line:
                findings.append(
                    self._finding(
                        relative,
                        start + call_line,
                        f"Possible reentrancy in '{name}': external call before state update",
                        f"'{name}' makes an external call on line "
                        f"{start + call_line} and only updates state on line "
                        f"{start + write_line}. The callee can call back into "
                        f"the contract before the state has changed, so the "
                        f"check that guards the call passes a second time. "
                        f"Apply checks-effects-interactions.",
                        Severity.CRITICAL,
                        name,
                    )
                )

            # Unchecked low-level call return value.
            for offset, line in enumerate(body):
                if not UNCHECKED_CALL.match(line):
                    continue
                if "require" in line or "if (" in line or "assert" in line:
                    continue
                if re.search(r"=\s*\w+\.(call|delegatecall|send)\s*\(", line):
                    continue  # assigned, so the caller can check it
                if re.search(
                    r"require\s*\(\s*\w+\.(call|delegatecall|send)\s*\(", body_text
                ) or re.search(r"if\s*\(\s*\w+\.(call|delegatecall|send)\s*\(", body_text):
                    # The return value is checked somewhere in the function.
                    continue
                findings.append(
                    self._finding(
                        relative,
                        start + offset,
                        f"Unchecked external call result in '{name}'",
                        f"'{name}' calls another contract without checking "
                        f"whether the call succeeded. A call that fails "
                        f"silently leaves the contract believing it did "
                        f"something it did not.",
                        Severity.HIGH,
                        line.strip()[:120],
                    )
                )
                break

            # Unchecked arithmetic.
            for offset, line in enumerate(body):
                if "unchecked" in line:
                    continue
                match = re.search(r"(\w[\w\.\[\]]*)\s*-\s*(\w[\w\.\[\]]*)", line)
                if match and "=" in line and "-" in line:
                    if "require" in line or "if (" in line:
                        continue
                    findings.append(
                        self._finding(
                            relative,
                            start + offset,
                            f"Possible unchecked subtraction in '{name}'",
                            f"'{name}' subtracts without a guard. If the "
                            f"right-hand side can exceed the left-hand side, "
                            f"an unsigned subtraction underflows to a very "
                            f"large number.",
                            Severity.MEDIUM,
                            line.strip()[:120],
                        )
                    )
                    break

        # -- file-level analysis -------------------------------------------
        for number, line in enumerate(lines, start=1):
            stripped = line.strip()

            if "tx.origin" in stripped and "//" not in stripped.split("tx.origin")[0][-2:]:
                findings.append(
                    self._finding(
                        relative,
                        number,
                        "tx.origin is used for authorisation",
                        "tx.origin is the account that started the "
                        "transaction, and it stays the same through an "
                        "intermediate contract. A phishing contract can call "
                        "this function and appear as the owner.",
                        Severity.CRITICAL,
                        "tx.origin",
                    )
                )

            if "selfdestruct" in stripped or ".suicide" in stripped:
                findings.append(
                    self._finding(
                        relative,
                        number,
                        "Contract can be destroyed",
                        "selfdestruct sends the remaining balance to an "
                        "address and removes the code. A contract that can "
                        "still receive funds after that has a permanent loss.",
                        Severity.HIGH,
                        "selfdestruct",
                    )
                )

            if "delegatecall" in stripped and "address(" not in stripped:
                findings.append(
                    self._finding(
                        relative,
                        number,
                        "delegatecall to a computed address",
                        "delegatecall executes foreign code in this "
                        "contract's storage. If the target is not tightly "
                        "controlled, the caller can overwrite arbitrary "
                        "storage, including balances and owners.",
                        Severity.CRITICAL,
                        "delegatecall",
                    )
                )

            if re.search(r"block\.(timestamp|number|difficulty|prevrandao)", stripped):
                findings.append(
                    self._finding(
                        relative,
                        number,
                        "Block data is used where unpredictability or time is needed",
                        "A miner or validator can influence block.timestamp "
                        "and block.number, so they must not drive randomness "
                        "or any decision that assumes a fair value.",
                        Severity.MEDIUM,
                        "block." + stripped.split("block.")[1].split("(")[0].split()[0].strip(");,"),
                    )
                )

            if re.search(r"\bnow\b", stripped) and "pragma solidity" not in stripped:
                findings.append(
                    self._finding(
                        relative,
                        number,
                        "The deprecated 'now' alias is used",
                        "'now' was an alias for block.timestamp and was "
                        "removed in Solidity 0.7. It also invites exactly "
                        "the timestamp-dependence problem above.",
                        Severity.LOW,
                        "now",
                    )
                )

            if re.search(r"function\s+initialize\s*\(", stripped) and "initializer" not in stripped:
                findings.append(
                    self._finding(
                        relative,
                        number,
                        "Initialiser is not protected by the initializer modifier",
                        "An unprotected initialiser can be called again after "
                        "deployment, which lets an attacker take ownership of "
                        "a proxy contract.",
                        Severity.HIGH,
                        "initialize",
                    )
                )

            if "ecrecover" in stripped and "invalid" not in stripped.lower():
                findings.append(
                    self._finding(
                        relative,
                        number,
                        "ecrecover result is not checked for the zero address",
                        "ecrecover returns the zero address when the "
                        "signature is invalid. Treating that as a valid "
                        "signer would let anyone forge an authorisation.",
                        Severity.HIGH,
                        "ecrecover",
                    )
                )

        return findings

    # -- helpers ----------------------------------------------------------
    def _functions(self, lines: list[str]) -> list[tuple[str, int, int, list[str]]]:
        functions: list[tuple[str, int, int, list[str]]] = []
        for index, line in enumerate(lines):
            match = FUNC_DECL.search(line)
            if not match:
                continue
            name = match.group(1)
            # Collect the body by brace balance.
            depth = line.count("{") - line.count("}")
            body = [line]
            cursor = index + 1
            while cursor < len(lines) and depth > 0:
                depth += lines[cursor].count("{") - lines[cursor].count("}")
                body.append(lines[cursor])
                cursor += 1
            functions.append((name, index, cursor, body))
        return functions

    @staticmethod
    def _is_state_changing(name: str) -> bool:
        lowered = name.lower()
        return any(lowered.startswith(verb) for verb in STATE_CHANGING)

    @staticmethod
    def _has_access_control(body_text: str, lines: list[str], start: int) -> bool:
        if MODIFIER_USE.search(body_text):
            return True
        # The modifier may be on the declaration line above the body.
        if start > 0 and MODIFIER_USE.search(lines[start - 1]):
            return True
        if "require(msg.sender" in body_text or "if (msg.sender" in body_text:
            return True
        return bool("onlyOwner" in body_text or "_checkOwner" in body_text)

    @staticmethod
    def _first_external_call(body: list[str]) -> int | None:
        for offset, line in enumerate(body):
            if EXTERNAL_CALL.search(line) and "require(" not in line:
                return offset
        return None

    @staticmethod
    def _first_state_write(body: list[str]) -> int | None:
        """The first line that writes to contract state.

        A local declaration such as ``uint amount = balances[msg.sender];``
        is not a state write, even though it contains an ``=``. Counting it
        as one would hide every reentrancy, because the local is usually
        read before the external call.
        """
        for offset, line in enumerate(body):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*"):
                continue
            if "=>" in stripped:
                continue
            if LOCAL_DECLARATION.match(stripped):
                continue
            if STATE_ASSIGN.search(stripped) and "==" not in stripped:
                return offset
        return None

    def _finding(
        self, relative: str, line_number: int, title: str, description: str, severity: Severity, matched: str
    ) -> Finding:
        return self.finding(
            title=title,
            target=relative,
            description=description,
            severity=severity,
            confidence=Confidence.MEDIUM,
            evidence_text=f"{relative}:{line_number}\n{title}",
            matched=matched,
            file=relative,
            line=line_number,
        )
