"""The research workspace.

Four of the capability areas are not things a scanner does - they are
things a person does, over months, and keeps:

- **Personal lab notes** - the record of what was tried, what worked and
  what did not. The most valuable artefact in security research, and the
  one nobody writes down.
- **Unsolved vulnerabilities** - the bugs you found and could not prove.
  A public, structured way to keep them is rarer than it should be.
- **Original research** - a question, a method, a dataset and a result.
- **Security portfolio** - the evidence that you did the work.

nemesis can create and maintain that workspace. It is a small thing, and
it is the thing that turns a scanner into a practice: the notes have a
consistent structure, the unsolved findings have a format that makes them
publishable later, and the portfolio is generated from real evidence
rather than from memory.

The workspace is a directory of Markdown and JSON. It is deliberately
plain - it should be readable in a text editor, greppable, and
version-controllable.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

#: The directories a workspace contains.
WORKSPACE_DIRS = (
    "notes",       # dated lab notes
    "findings",    # unsolved vulnerabilities
    "research",    # original research projects
    "portfolio",   # published work
    "scans",       # scan output
    "rules",       # generated detection content
)

#: The note template. The structure is what makes notes worth having six
#: months later: what was tried, what the result was, and what it means.
NOTE_TEMPLATE = """---
title: {title}
date: {date}
tags: []
target: ""
tools: []
---

# {title}

## What I was trying to find

_One paragraph. If you cannot write this, the goal is not clear enough
to work towards._

## What I did

```bash
# the commands, in the order they were run
```

## What happened

_What actually came back. Paste the output, do not describe it - a
description of the output is a memory of the output, and memories are
wrong._

## What it means

_The interpretation. This is the part that will still be useful in a
year, because the commands are not._

## Next

- [ ] _..._
"""

#: The unsolved-finding template. Structured so that a finding that was
#: never proved can still be written up later.
FINDING_TEMPLATE = """---
title: {title}
id: {finding_id}
date: {date}
status: open
severity: unknown
confidence: low
cwe: ""
target: ""
---

# {title}

## Summary

_What is wrong, in two sentences, without jargon._

## Evidence

```
_paste the request, the response, the diff - whatever you have_
```

## Why I could not prove it

_This is the interesting part. What was missing: a working exploit, a
crash, a second confirmation? Be specific, because "could not reproduce"
and "did not build the exploit" are very different notes._

## What would prove it

- [ ] _..._

## What I have tried

| Attempt | Result |
|---|---|
| | |

## References

- _..._
"""

#: The research project template.
RESEARCH_TEMPLATE = """---
title: {title}
date: {date}
status: active
question: ""
dataset: ""
method: ""
---

# {title}

## The question

_What do I want to know that nobody knows? If the answer is "is this
vulnerable", the answer is probably already on the internet._

## Why it matters

_Who would care about the answer, and what would they do with it?_

## Method

_How will I find out? A dataset, a measurement, a corpus, an argument._

## Status

- [ ] Define the scope
- [ ] Build the corpus
- [ ] Run the first pass
- [ ] Write it up

## Notes

"""

#: The portfolio entry template.
PORTFOLIO_TEMPLATE = """---
title: {title}
date: {date}
type: research
public: false
---

# {title}

## What I did

## What I found

## What changed because of it

_Links to the advisory, the patch, the talk, the disclosure._

## Evidence

"""


@dataclass
class Workspace:
    """A research workspace on disk."""

    root: Path
    created: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # -- creation --------------------------------------------------------
    def create(self) -> list[Path]:
        """Create the workspace directory structure."""
        created: list[Path] = []
        for name in WORKSPACE_DIRS:
            path = self.root / name
            path.mkdir(parents=True, exist_ok=True)
            created.append(path)
        readme = self.root / "README.md"
        if not readme.exists():
            readme.write_text(self._readme(), encoding="utf-8")
            created.append(readme)
        config = self.root / "workspace.json"
        if not config.exists():
            config.write_text(
                json.dumps(
                    {
                        "created": self.created,
                        "directories": list(WORKSPACE_DIRS),
                        "version": 1,
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            created.append(config)
        return created

    def _readme(self) -> str:
        return (
            "# Research workspace\n\n"
            "A working directory for the part of security research that is "
            "not a scanner.\n\n"
            "```\n"
            "notes/       dated lab notes - what was tried and what happened\n"
            "findings/    unsolved vulnerabilities, in a publishable shape\n"
            "research/    original research projects\n"
            "portfolio/   published work and evidence\n"
            "scans/       scan output\n"
            "rules/       generated detection content\n"
            "```\n\n"
            "Everything here is Markdown and JSON, so it diffs, it greps "
            "and it works in any editor.\n\n"
            "Create entries with:\n\n"
            "```bash\n"
            "nemesis lab note \"title\"\n"
            "nemesis lab finding \"title\"\n"
            "nemesis lab research \"title\"\n"
            "```\n"
        )

    # -- entries ---------------------------------------------------------
    def add_note(self, title: str, date: str | None = None) -> Path:
        return self._write(
            self.root / "notes" / f"{self._slug(title)}.md",
            NOTE_TEMPLATE.format(title=title, date=date or self._today()),
        )

    def add_finding(self, title: str, date: str | None = None) -> Path:
        return self._write(
            self.root / "findings" / f"{self._slug(title)}.md",
            FINDING_TEMPLATE.format(
                title=title,
                date=date or self._today(),
                finding_id=self._finding_id(title),
            ),
        )

    def add_research(self, title: str, date: str | None = None) -> Path:
        return self._write(
            self.root / "research" / f"{self._slug(title)}.md",
            RESEARCH_TEMPLATE.format(title=title, date=date or self._today()),
        )

    def add_portfolio_entry(self, title: str, date: str | None = None) -> Path:
        return self._write(
            self.root / "portfolio" / f"{self._slug(title)}.md",
            PORTFOLIO_TEMPLATE.format(title=title, date=date or self._today()),
        )

    def _write(self, path: Path, content: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            # Never silently overwrite a note somebody wrote.
            stem = path.stem
            index = 2
            while path.exists():
                path = path.with_name(f"{stem}-{index}.md")
                index += 1
        path.write_text(content, encoding="utf-8")
        return path

    # -- inventory -------------------------------------------------------
    def inventory(self) -> dict:
        """What is in the workspace."""
        counts: dict[str, int] = {}
        for name in WORKSPACE_DIRS:
            directory = self.root / name
            if not directory.is_dir():
                counts[name] = 0
                continue
            counts[name] = len([p for p in directory.iterdir() if p.is_file()])
        notes = self._read_front_matter(self.root / "notes")
        return {
            "root": str(self.root),
            "counts": counts,
            "total": sum(counts.values()),
            "tags": self._collect_tags(notes),
            "note_titles": [n.get("title", "") for n in notes][:20],
        }

    def _collect_tags(self, notes: list[dict]) -> list[str]:
        tags: list[str] = []
        for note in notes:
            for tag in note.get("tags", []) or []:
                if tag not in tags:
                    tags.append(tag)
        return tags

    def _read_front_matter(self, directory: Path) -> list[dict]:
        """Read the YAML-ish front matter from every file in a directory."""
        if not directory.is_dir():
            return []
        entries: list[dict] = []
        for path in sorted(directory.iterdir()):
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            entries.append(self._parse_front_matter(text))
        return entries

    @staticmethod
    def _parse_front_matter(text: str) -> dict:
        """Parse the small front-matter dialect the templates use."""
        if not text.startswith("---"):
            return {}
        end = text.find("\n---", 3)
        if end == -1:
            return {}
        block = text[3:end]
        data: dict = {}
        current_list: str | None = None
        for line in block.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("- ") and current_list:
                data.setdefault(current_list, [])
                if isinstance(data[current_list], list):
                    data[current_list].append(stripped[2:].strip().strip("\"'"))
                continue
            key, _, value = stripped.partition(":")
            key = key.strip()
            value = value.strip()
            if value == "[]":
                data[key] = []
                current_list = key
            elif value == "":
                data[key] = ""
                current_list = key
            else:
                data[key] = value.strip("\"'")
                current_list = None
        return data

    # -- helpers ---------------------------------------------------------
    @staticmethod
    def _today() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    @staticmethod
    def _slug(title: str) -> str:
        slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
        return slug[:60] or "entry"

    @staticmethod
    def _finding_id(title: str) -> str:
        digest = 0
        for char in title.lower():
            digest = (digest * 131 + ord(char)) & 0xFFFFFFFF
        return f"NF-{digest:08x}"
