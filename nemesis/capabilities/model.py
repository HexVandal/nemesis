"""The capability model.

nemesis is a scanner, not a human. Some of the work it is asked to do can
be done by software; some of it needs a person, a lab bench, or a soldering
iron. Pretending otherwise is how a tool ends up with a feature list that
does not work.

So every capability carries an honest **maturity** label:

``native``
    nemesis does this itself, today, and you can point at the module.

``partial``
    nemesis covers a meaningful slice of it.

``integration``
    nemesis produces or consumes the artifacts the work needs - a
    detection rule, a triage report, a scope file - and an external tool
    or a human does the rest.

``research``
    Needs specialised hardware, a custom toolchain or a lab. nemesis
    carries the methodology and the scaffolding, not the capability.

``manual``
    A practice rather than a tool: reviewing, writing, disclosing.

The registry is the honest map. The modules are the proof.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Maturity levels, worst to best. Ordered so ``max()`` picks the strongest.
MATURITY_ORDER = ("manual", "research", "integration", "partial", "native")

MATURITY_LABELS = {
    "native": "Implemented natively",
    "partial": "Partially covered",
    "integration": "Integration / artifact producer",
    "research": "Research-grade, needs a lab",
    "manual": "Methodology, executed by a human",
}

#: The top-level domains a capability can belong to.
DOMAINS = {
    "exploitation": "Binary & memory exploitation",
    "internals": "Operating system & firmware internals",
    "web": "Web application security",
    "offensive": "Offensive methodology",
    "network": "Network, wireless & radio",
    "cloud": "Cloud, DevSecOps & supply chain",
    "detection": "Detection, response & forensics",
    "ai": "AI, ML & LLM security",
    "blockchain": "Blockchain & smart contracts",
    "sidechannel": "Side-channel & physical",
    "reporting": "Reporting, disclosure & research",
    "learning": "Learning & knowledge",
    "meta": "Practice & personal",
}


@dataclass(frozen=True)
class Capability:
    """One area of capability, and how far nemesis actually gets."""

    id: str
    name: str
    domain: str
    maturity: str
    summary: str
    #: Module ids inside nemesis that implement this capability.
    modules: tuple[str, ...] = ()
    #: Importable components inside nemesis that implement this capability,
    #: as ``package.module:Attribute``. Used for the parts of nemesis that
    #: are not scan modules - the CVSS calculator, the report generators -
    #: so the honesty check covers them too.
    components: tuple[str, ...] = ()
    #: External tools that do the heavy lifting for this capability.
    tools: tuple[str, ...] = ()
    #: Artifacts nemesis can emit for this capability.
    artifacts: tuple[str, ...] = ()
    #: What someone needs before this capability can be exercised.
    prerequisites: tuple[str, ...] = ()
    #: Keywords for `nemesis capabilities --search`.
    keywords: tuple[str, ...] = ()

    @property
    def domain_label(self) -> str:
        return DOMAINS.get(self.domain, self.domain)

    @property
    def maturity_label(self) -> str:
        return MATURITY_LABELS.get(self.maturity, self.maturity)

    @property
    def strength(self) -> int:
        return MATURITY_ORDER.index(self.maturity)

    @property
    def is_implemented(self) -> bool:
        """True when nemesis ships something that does the work."""
        return self.maturity in ("native", "partial")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "domain": self.domain,
            "domain_label": self.domain_label,
            "maturity": self.maturity,
            "maturity_label": self.maturity_label,
            "summary": self.summary,
            "modules": list(self.modules),
            "components": list(self.components),
            "tools": list(self.tools),
            "artifacts": list(self.artifacts),
            "prerequisites": list(self.prerequisites),
        }
