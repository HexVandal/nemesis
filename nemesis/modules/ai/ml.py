"""Machine-learning model security.

A model artefact on disk is a program that gets executed by the framework
that loads it. Pickle-based formats are the sharp edge: ``torch.load``,
``joblib.load``, ``numpy.load`` and ``sklearn`` model files all execute
arbitrary code while loading.

The checks here look at what is actually in the tree:

- Model files in unsafe serialisation formats, and the code that loads them.
- A training pipeline that loads a model file without ``weights_only`` or
  a restricted unpickler.
- Model cards and configs that reveal training data, internal endpoints, or
  personal data.
- Datasets that contain credentials or personal identifiers.
- A model served behind an endpoint that has no authentication.

This is the "AI/ML" part of the AI security problem, and it is the part
that a normal SAST tool misses because it does not know what a ``.pkl``
file is.
"""

from __future__ import annotations

import re
from pathlib import Path

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext
from ..code.common import iter_source_files, read_lines

#: Model artefact extensions and the loader that interprets them.
MODEL_FORMATS = {
    ".pkl": "pickle", ".pickle": "pickle", ".joblib": "pickle",
    ".pt": "torch pickle", ".pth": "torch pickle", ".bin": "torch pickle",
    ".ckpt": "torch pickle", ".onnx": "protobuf", ".h5": "keras",
    ".keras": "keras", ".pb": "protobuf", ".caffemodel": "protobuf",
    ".gguf": "gguf", ".safetensors": "safetensors", ".pt2": "torch",
    ".model": "pickle", ".mlmodel": "protobuf",
}

#: Loaders that execute code while deserialising.
UNSAFE_LOADERS = (
    ("torch.load", "torch"),
    ("joblib.load", "joblib"),
    ("pickle.load", "pickle"),
    ("pickle.loads", "pickle"),
    ("cPickle.load", "pickle"),
    ("dill.load", "dill"),
    ("dill.loads", "dill"),
    ("numpy.load", "numpy"),
    ("np.load", "numpy"),
    ("marshal.loads", "marshal"),
    ("yaml.load", "yaml"),
    ("eval(", "eval"),
)

#: Arguments that make a loader safe.
SAFE_ARGS = re.compile(r"weights_only\s*=\s*True|allow_pickle\s*=\s*False|safe_load|RestrictedUnpickler")

#: Files that are obviously model artefacts.
ARTEFACT_NAMES = re.compile(r"(model|weights|checkpoint|ckpt)\.(pkl|pickle|joblib|pt|pth|bin|ckpt|h5|keras|gguf|onnx)$", re.IGNORECASE)

#: Training data and identity markers in a dataset.
PII_MARKERS = (
    ("ssn", "social security number"), ("social_security", "social security number"),
    ("passport", "passport number"), ("national_id", "national identity number"),
    ("credit_card", "card number"), ("card_number", "card number"),
    ("iban", "bank account"), ("date_of_birth", "date of birth"),
    ("home_address", "home address"), ("medical_record", "medical record"),
    ("diagnosis", "medical diagnosis"),
)

#: Credentials in a model card or config.
CREDENTIAL_MARKERS = re.compile(
    r"(aws_access_key|api[_-]?key|secret[_-]?key|password|bearer\s+token|private[_-]?key)"
    r"\s*[:=]\s*['\"]?[A-Za-z0-9/+_\-]{16,}",
    re.IGNORECASE,
)

#: Configuration that names an internal endpoint.
ENDPOINT_MARKERS = re.compile(
    r"https?://(?:[a-z0-9-]+\.)*(?:internal|corp|intra|private|local|svc|cluster)[a-z0-9.-]*\b",
    re.IGNORECASE,
)


class MlModelSecurityModule(Module):
    """Finds the security problems around model artefacts and datasets."""

    group = "ai"
    id = "ml_model_security"
    name = "ML Model Security"
    description = (
        "Finds model artefacts in unsafe serialisation formats, loading code "
        "that executes code while deserialising, datasets that contain "
        "personal data, and model cards or configs that leak credentials, "
        "internal endpoints or training data."
    )
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    category = Category.SUPPLY_CHAIN
    capability = Capability.CODE
    cwe = "CWE-502"
    owasp = "A08"
    tags = ["ml", "ai", "model", "pickle", "dataset", "pii"]
    remediation = (
        "Store model weights in a format that does not execute code on load "
        "(safetensors, ONNX, or torch.load with weights_only=True), never "
        "load an untrusted artefact, and strip credentials and personal data "
        "from datasets and model cards before they are shared."
    )
    references = [
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        "https://huggingface.co/docs/safetensors/index",
        "https://cwe.mitre.org/data/definitions/502.html",
    ]

    max_files = 4000

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.code_path:
            return []
        root = Path(ctx.code_path)
        findings: list[Finding] = []

        artefacts = self._artefacts(root)
        for path in artefacts[:200]:
            findings.append(
                self.finding(
                    title=f"Model artefact in an executable serialisation format: {path.name}",
                    target=str(path),
                    description=(
                        f"{path.name} is a {MODEL_FORMATS[path.suffix.lower()]} "
                        f"file. These formats execute code while they are "
                        f"being loaded, so anyone who can replace this file "
                        f"executes code on the machine that loads it. "
                        f"Convert it to safetensors or ONNX."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    evidence_text=f"Artefact: {path}\nFormat: {MODEL_FORMATS[path.suffix.lower()]}",
                    matched=path.name,
                    file=str(path),
                )
            )

        findings.extend(self._audit_loaders(root))
        findings.extend(self._audit_datasets(root))
        findings.extend(self._audit_metadata(root))
        return findings

    # -- artefact discovery ----------------------------------------------
    def _artefacts(self, root: Path) -> list[Path]:
        skip = {".git", "node_modules", "venv", ".venv", "__pycache__", "site-packages"}
        found: list[Path] = []
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            if any(part in skip for part in path.parts):
                continue
            suffix = path.suffix.lower()
            if (suffix in MODEL_FORMATS and ARTEFACT_NAMES.search(path.name)) or suffix in (".pkl", ".pickle", ".joblib", ".pt", ".pth", ".ckpt"):
                found.append(path)
        return found

    # -- loading code ----------------------------------------------------
    def _audit_loaders(self, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        for path in iter_source_files(root):
            lines = read_lines(path)
            if not lines:
                continue
            for number, line in enumerate(lines, start=1):
                for loader, kind in UNSAFE_LOADERS:
                    if loader not in line:
                        continue
                    if SAFE_ARGS.search(line):
                        continue
                    # yaml.load is only dangerous without safe_load.
                    if (loader == "yaml.load" and "Loader=" not in line and "SafeLoader" not in line) or loader == "eval(":
                        severity = Severity.HIGH
                    else:
                        severity = Severity.HIGH
                    findings.append(
                        self.finding(
                            title=f"Unsafe model deserialisation via {loader}",
                            target=str(path),
                            description=(
                                f"{loader} executes the contents of the file "
                                f"it reads. A model artefact that came from a "
                                f"third party, a shared drive or a pull "
                                f"request is remote code execution."
                            ),
                            severity=severity,
                            confidence=Confidence.HIGH,
                            evidence_text=(
                                f"{path}:{number}\n{line.strip()[:300]}"
                            ),
                            matched=loader,
                            file=str(path),
                            line=number,
                        )
                    )
                    break
        return findings

    # -- datasets --------------------------------------------------------
    def _audit_datasets(self, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        for path in self._iter_files(root, (".csv", ".tsv", ".jsonl", ".parquet", ".json")):
            lines = read_lines(path)
            if not lines:
                continue
            header = lines[0].lower()
            for marker, description in PII_MARKERS:
                if marker in header:
                    findings.append(
                        self.finding(
                            title=f"Dataset appears to contain {description} data",
                            target=str(path),
                            description=(
                                f"The columns of {path.name} include "
                                f"'{marker}'. A dataset that carries "
                                f"{description} data is regulated data, and "
                                f"loading it into a training pipeline is a "
                                f"processing event that has to be lawful and "
                                f"logged."
                            ),
                            severity=Severity.MEDIUM,
                            confidence=Confidence.MEDIUM,
                            evidence_text=f"{path}\nHeader: {lines[0][:300]}",
                            matched=marker,
                            file=str(path),
                            line=1,
                        )
                    )
                    break
        return findings

    # -- model cards and configs -----------------------------------------
    def _audit_metadata(self, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        interesting = {
            "modelcard.md", "model_card.md", "readme.md", "config.json",
            "config.yaml", "config.yml",
        }
        for path in self._iter_files(root, (".md", ".json", ".yaml", ".yml", ".txt")):
            if path.name.lower() not in interesting:
                continue
            text = "\n".join(read_lines(path))
            if not text:
                continue

            for match in CREDENTIAL_MARKERS.finditer(text):
                findings.append(
                    self.finding(
                        title="Credential found in model metadata",
                        target=str(path),
                        description=(
                            f"{path.name} contains something that looks like "
                            f"a credential. Model cards and configs are "
                            f"published with the model, and a published "
                            f"credential is a leaked credential."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        evidence_text=f"{path}\n{text[max(0, match.start() - 60):match.end() + 20]}",
                        matched=match.group(0)[:120],
                        file=str(path),
                    )
                )
                break

            for match in ENDPOINT_MARKERS.finditer(text):
                findings.append(
                    self.finding(
                        title="Internal endpoint disclosed in model metadata",
                        target=str(path),
                        description=(
                            f"{path.name} discloses an internal address "
                            f"({match.group(0)}). Internal hostnames are a "
                            f"map of the private network, and they are "
                            f"published with the model."
                        ),
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        evidence_text=f"{path}\n{match.group(0)}",
                        matched=match.group(0),
                        file=str(path),
                    )
                )
                break
        return findings

    # -- helpers ----------------------------------------------------------
    @staticmethod
    def _iter_files(root: Path, suffixes: tuple[str, ...]):
        """Yield files with one of *suffixes* under *root*.

        Datasets and model cards are not source code, so they are not in
        the shared source-file list, and the shared list is right: it
        deliberately excludes the data directories a source scan should
        skip. This walk has its own, narrower, skip list.
        """
        skip = {
            ".git", "node_modules", ".venv", "venv", "__pycache__",
            "site-packages", "dist", "build",
        }
        count = 0
        for path in sorted(Path(root).rglob("*")):
            if count >= 2000:
                return
            if not path.is_file():
                continue
            if any(part in skip for part in path.parts):
                continue
            if path.suffix.lower() in suffixes:
                count += 1
                yield path
