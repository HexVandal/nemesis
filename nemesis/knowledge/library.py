"""The reference library.

A scanner covers the part of security work that is software-shaped. The
rest - the part where you need to read a paper, work through a course,
solder a wire to a chip, or sit with a debugger for a week - is not
something a tool can do for you, but it is something a tool can point at.

This module is that index. It maps each capability area that nemesis does
not implement natively onto the resources that actually cover it: the
paper that explains the bug class, the course that teaches the technique,
the book that goes deep, the tool that does the work, and the lab where
you practise.

Every entry has a URL and a note about what it is good for. The library
is deliberately opinionated: a list of every resource in a field is not
useful, and a list of the ones that are worth your time is.
"""

from __future__ import annotations

from dataclasses import dataclass

#: The kinds of resource the library holds.
KIND_LAB = "lab"
KIND_COURSE = "course"
KIND_PAPER = "paper"
KIND_BOOK = "book"
KIND_WHITEPAPER = "whitepaper"
KIND_TOOL = "tool"
KIND_PROJECT = "project"
KIND_STANDARD = "standard"
KIND_GUIDE = "guide"


@dataclass(frozen=True)
class Resource:
    """One entry in the library."""

    id: str
    title: str
    kind: str
    url: str
    #: The capability area this resource serves.
    area: str
    #: What it is good for, in one sentence.
    note: str = ""
    #: Rough effort, in hours, for the ones that take time.
    hours: int = 0
    #: Free, paid, or needs an account.
    access: str = "free"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "kind": self.kind,
            "url": self.url,
            "area": self.area,
            "note": self.note,
            "hours": self.hours,
            "access": self.access,
        }


#: The library.
LIBRARY: tuple[Resource, ...] = (
    # -- Web application foundations ------------------------------------
    Resource(
        "owasp-wstg",
        "OWASP Web Security Testing Guide",
        KIND_GUIDE,
        "https://owasp.org/www-project-web-security-testing-guide/",
        "source-code-auditing",
        "The canonical testing methodology. Read it end to end once; it "
        "restructures how you think about testing a web application.",
        hours=12,
    ),
    Resource(
        "owasp-top10",
        "OWASP Top 10",
        KIND_GUIDE,
        "https://owasp.org/www-project-top-ten/",
        "source-code-auditing",
        "The awareness document. Useful for vocabulary, not for depth - "
        "but it is the vocabulary everybody else uses.",
        hours=3,
    ),
    Resource(
        "portswigger-academy",
        "PortSwigger Web Security Academy",
        KIND_COURSE,
        "https://portswigger.net/web-security",
        "portswigger-web-security-academy",
        "The best free structured course in web security. Every topic "
        "ends with an interactive lab, and the labs are free.",
        hours=60,
    ),
    Resource(
        "portswigger-research",
        "PortSwigger Research Blog",
        KIND_PAPER,
        "https://portswigger.net/research",
        "portswigger-web-security-academy",
        "Deep, original research on real vulnerability classes, written by "
        "the people who found them. The single best free source of depth.",
        hours=0,
    ),
    Resource(
        "tryhackme",
        "TryHackMe",
        KIND_COURSE,
        "https://tryhackme.com/",
        "tryhackme",
        "Guided rooms that hold your hand through a technique. Good for "
        "building the reflex of picking up a tool and using it.",
        hours=40,
    ),
    Resource(
        "htb-academy",
        "Hack The Box Academy",
        KIND_COURSE,
        "https://academy.hackthebox.com/",
        "hacking-courses",
        "Structured courses with more depth than a room, including a "
        "module on exploit development.",
        hours=50,
    ),
    Resource(
        "pentester-lab",
        "PentesterLab",
        KIND_COURSE,
        "https://pentesterlab.com/",
        "hacking-courses",
        "Deliberately vulnerable applications with a business model - the "
        "closest thing to a real target you can practise against legally.",
        hours=30,
        access="paid",
    ),
    Resource(
        "webanthology",
        "The Web Application Hacker's Handbook 2",
        KIND_BOOK,
        "https://www.wiley.com/en-us/Web+Application+Hacker%27s+Handbook%2C+2nd+Edition-p-9781118026472",
        "web",
        "The deepest book on web application security that still reads "
        "like a book. Worth the hours.",
        hours=30,
        access="paid",
    ),
    Resource(
        "tangled-web",
        "The Tangled Web",
        "book",
        "https://nostarch.com/tangledweb",
        "browser-security",
        "How browsers actually enforce security, and why the enforcement "
        "keeps failing. The reference for browser security reasoning.",
        hours=20,
        access="paid",
    ),
    Resource(
        "real-world-crypto",
        "Real-World Cryptography",
        "book",
        "https://www.manning.com/books/real-world-cryptography",
        "crypto",
        "Cryptography for people who ship software. The clearest "
        "explanation of why the way you are using your crypto library is "
        "wrong.",
        hours=15,
        access="paid",
    ),
    # -- Exploitation and binary ----------------------------------------
    Resource(
        "art-of-software-security",
        "The Art of Software Security Assessment",
        KIND_BOOK,
        "https://www.pearson.com/en-us/subject-catalog/p/art-of-software-security-assessment-identifying-and-preventing-software-vulnerabilities/P200000009442",
        "buffer-overflow",
        "Dowd, McDonald and Schuh. The book that teaches you to find bugs "
        "by reading code rather than by fuzzing. Out of print but widely "
        "copied.",
        hours=25,
        access="paid",
    ),
    Resource(
        "practical-reverse-engineering",
        "Reverse Engineering for Beginners",
        "book",
        "https://beginners.re/",
        "assembly-language",
        "A free, complete book on reverse engineering, from x86 to ARM, "
        "written to be read with a disassembler open.",
        hours=30,
        access="free",
    ),
    Resource(
        "shellcoders-handbook",
        "Hacking: The Art of Exploitation",
        "book",
        "https://nostarch.com/hacking2.htm",
        "shellcode-development",
        "The book that teaches exploitation from the machine up, with a "
        "live CD that still runs. Read it before any modern exploit course.",
        hours=20,
        access="paid",
    ),
    Resource(
        "smashing-stack",
        "Smashing the Stack For Fun And Profit",
        KIND_PAPER,
        "https://www.phrack.org/issues/49/14",
        "buffer-overflow",
        "Aleph One, 1996. The paper that made buffer overflows a public "
        "undergraduate technique, and still the best explanation of them.",
        hours=1,
    ),
    Resource(
        "shacham-return-into-libc",
        "The Geometry of Innocent Flesh on the Bone",
        "paper",
        "https://hovav.net/ucsd/dist/geometry.pdf",
        "buffer-overflow",
        "The paper that named return-oriented programming, and still the "
        "clearest explanation of why a stack canary does not stop a "
        "determined attacker.",
        hours=4,
        access="free",
    ),
    Resource(
        "how2heap",
        "how2heap",
        "paper",
        "https://github.com/shellphish/how2heap",
        "heap-exploitation",
        "A living catalogue of heap techniques, each a compilable program "
        "against a specific glibc version. The fastest way to watch tcache "
        "poisoning work.",
        hours=6,
        access="free",
    ),
    Resource(
        "how-to-write-shellcode",
        "Shellcoding for Linux and Windows",
        "paper",
        "https://www.vividmachines.com/shellcode/shellcode.html",
        "shellcode-development",
        "A classic, hand-assembled walkthrough of writing shellcode from "
        "scratch. Dated, and still the right first exercise.",
        hours=3,
        access="free",
    ),
    Resource(
        "ropgadget",
        "ROPgadget",
        KIND_TOOL,
        "https://github.com/JonathanSalwan/ROPgadget",
        "shellcode-development",
        "Finds ROP gadgets in a binary. The first thing you run when you "
        "have a stack overflow and no shellcode.",
    ),
    Resource(
        "pwntools",
        "pwntools",
        "tool",
        "https://github.com/Gallopsled/pwntools",
        "buffer-overflow",
        "The Python framework for exploit development. If you are writing "
        "an exploit by hand, you are doing it wrong.",
        hours=0,
        access="free",
    ),
    Resource(
        "gdb",
        "GNU Debugger",
        KIND_TOOL,
        "https://www.gnu.org/software/gdb/",
        "debugging",
        "The debugger everything else is built around. Worth the time to "
        "learn the commands that do not show up in the manual.",
    ),
    Resource(
        "gef",
        "GEF - The Game Environment Framework",
        KIND_TOOL,
        "https://github.com/hugsy/gef",
        "debugging",
        "Turns GDB into something you can actually use on a binary: one "
        "command to see the stack, the heap, the registers and the "
        "mappings.",
    ),
    Resource(
        "checksec",
        "checksec.sh",
        "tool",
        "https://github.com/slimm609/checksec.sh",
        "buffer-overflow",
        "Reports the exploit mitigations a binary has. The first command "
        "you run on a new target.",
        hours=0,
        access="free",
    ),
    Resource(
        "patch-diffing",
        "Diaphora / BinDiff",
        "tool",
        "https://github.com/joxeankoret/diaphora",
        "patch-diffing",
        "Binary diffing. The tool for finding what changed between two "
        "builds of the same program - which is how you find the patch for a "
        "vulnerability that has one.",
        hours=0,
        access="free",
    ),
    # -- Kernel and OS internals ----------------------------------------
    Resource(
        "kernel-exploitation-guide",
        "Linux Kernel Exploitation",
        "book",
        "https://github.com/xairy/linux-kernel-exploitation",
        "kernel-exploitation",
        "A curated map of kernel exploitation maintained by Andrey "
        "Konovalov: bug classes, mitigations, write-ups and tooling in one "
        "place.",
        hours=60,
        access="paid",
    ),
    Resource(
        "linux-kernel-development",
        "Linux Kernel Development",
        KIND_BOOK,
        "https://www.kernel.org/doc/html/latest/doc-guide/",
        "linux-kernel-security",
        "The kernel's own documentation. Free, authoritative, and the "
        "place to look up the exact semantics of a subsystem.",
        hours=0,
    ),
    Resource(
        "csmith",
        "Csmith",
        KIND_TOOL,
        "https://github.com/csmith-project/csmith",
        "linux-kernel-security",
        "A random C compiler that finds undefined behaviour. The tool that "
        "found hundreds of kernel bugs.",
    ),
    Resource(
        "syzkaller",
        "syzkaller",
        KIND_TOOL,
        "https://github.com/google/syzkaller",
        "linux-kernel-security",
        "A kernel fuzzer with a corpus manager that understands the "
        "syscall interface. The reason most modern kernel bugs were "
        "found the same week.",
    ),
    Resource(
        "ksma",
        "KASLR, SMEP, SMAP and the rest of the kernel hardening story",
        KIND_GUIDE,
        "https://lwn.net/Articles/250417/",
        "linux-kernel-security",
        "LWN's coverage of the kernel's exploit mitigations and how they "
        "fail. Free and technically precise.",
        hours=4,
    ),
    Resource(
        "windows-internals-part1",
        "Windows Internals Part 1",
        "book",
        "https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals",
        "windows-internals",
        "System calls, objects, memory and the registry. The MS Press book, "
        "and it is free.",
        hours=25,
        access="free",
    ),
    Resource(
        "system-internals",
        "Sysinternals Suite",
        KIND_TOOL,
        "https://learn.microsoft.com/en-us/sysinternals/downloads/",
        "windows-internals",
        "Process Explorer, Procmon, WinDbg and the rest. The tools Microsoft "
        "gives you for free, and they are excellent.",
    ),
    # -- Sandboxing, containers, hardware ---------------------------------
    Resource(
        "kubernetes-pss",
        "Pod Security Standards",
        KIND_GUIDE,
        "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
        "sandbox-escapes",
        "The three pod-security profiles. The baseline and restricted "
        "levels are a checklist you can apply to any manifest.",
        hours=3,
    ),
    Resource(
        "docker-security",
        "Docker Security Best Practices",
        KIND_GUIDE,
        "https://docs.docker.com/build/building/best-practices/",
        "sandbox-escapes",
        "What Docker's own documentation says about running untrusted "
        "code. Short, and the section on rootless mode is the useful part.",
        hours=2,
    ),
    Resource(
        "containerd-cgroups",
        "CVE-2022-0492: cgroups v1 release_agent escape",
        "paper",
        "https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/",
        "sandbox-escapes",
        "The container escape that turns a privileged-enough container into "
        "host root through a writable cgroup. The preconditions are the "
        "lesson.",
        hours=2,
        access="free",
    ),
    Resource(
        "boot-hole",
        "BootHole: A Secure Boot Vulnerability",
        KIND_PAPER,
        "https://eclypsium.com/research/theres-a-hole-in-the-boot/",
        "uefi-bios-security",
        "Eclypsium's work on UEFI firmware vulnerabilities, and the "
        "template for how firmware research is done and published.",
        hours=3,
    ),
    Resource(
        "thunderclap",
        "Thunderclap: a new attack against the Secure Boot chain",
        "paper",
        "https://thunderclap.io/",
        "secure-boot-research",
        "The Thunderbolt and DMA attack against Secure Boot. The reference "
        "for pre-boot attack surface.",
        hours=3,
        access="free",
    ),
    Resource(
        "chipwhisperer",
        "ChipWhisperer",
        "tool",
        "https://github.com/newaetech/chipwhisperer",
        "jtag-uart",
        "Side-channel capture and fault injection against embedded targets. "
        "The tool that made hardware security research accessible.",
        hours=0,
        access="free",
    ),
    Resource(
        "jtagulator",
        "JTAGulator",
        "tool",
        "https://github.com/grandideastudio/jtagulator",
        "jtag-uart",
        "Finds JTAG and serial ports on an unconfigured board. The first "
        "tool you run when a device is a black box.",
        hours=0,
        access="free",
    ),
    Resource(
        "openocd",
        "OpenOCD",
        KIND_TOOL,
        "https://openocd.org/",
        "jtag-uart",
        "The open-source debugger for embedded targets. Talks to almost "
        "every JTAG adapter.",
    ),
    Resource(
        "flipper-zero",
        "Flipper Zero",
        KIND_TOOL,
        "https://flipper.net/",
        "rfid-nfc-security",
        "A sub-GHz and NFC research device. Cheap, open, and it makes "
        "RFID and NFC work affordable to learn.",
        access="paid",
    ),
    Resource(
        "proxmark",
        "Proxmark3",
        KIND_TOOL,
        "https://github.com/RfidResearchGroup/proxmark3",
        "rfid-nfc-security",
        "The RFID research tool. Reads, writes and clones MIFARE and "
        "other protocols.",
    ),
    # -- Side channel and hardware ----------------------------------------
    Resource(
        "kocher-timing",
        "Timing Attacks on Cryptosystems",
        "paper",
        "https://www.paulkocher.com/doc/TimingAttacks.pdf",
        "side-channel-analysis",
        "Kocher, 1996. The paper that made timing a first-class attack "
        "surface, and it is remarkably readable.",
        hours=3,
        access="free",
    ),
    Resource(
        "spectre",
        "Spectre Attacks: Exploiting Speculative Execution",
        "paper",
        "https://spectreattack.com/spectre.pdf",
        "side-channel-attacks",
        "Kocher et al. The paper that changed how every CPU is designed.",
        hours=4,
        access="free",
    ),
    Resource(
        "meltdown",
        "Meltdown: Reading Kernel Memory from User Space",
        "paper",
        "https://meltdownattack.com/meltdown.pdf",
        "side-channel-attacks",
        "The companion paper. The clearest explanation of speculative "
        "execution anywhere.",
        hours=3,
        access="free",
    ),
    Resource(
        "percival-cache-timing",
        "Cache Missing for Fun and Profit",
        "paper",
        "https://www.daemonology.net/papers/htt.pdf",
        "side-channel-analysis",
        "Percival's cache-timing paper: the clearest demonstration that a "
        "timing signal in shared hardware is enough to recover a key.",
        hours=3,
        access="free",
    ),
    # -- Network, wireless, radio -----------------------------------------
    Resource(
        "krack",
        "Key Reinstallation Attacks",
        KIND_PAPER,
        "https://krackattacks.com/",
        "wifi-security",
        "Vanhoef's WPA2 break. The best worked example of a protocol "
        "state-machine bug there is.",
        hours=4,
    ),
    Resource(
        "evil-twin",
        "Wi-Fi evil twin and rogue AP research",
        KIND_GUIDE,
        "https://github.com/aircrack-ng/aircrack-ng",
        "wifi-security",
        "The aircrack-ng suite and its documentation. The reference for "
        "wireless capture and handshake work.",
    ),
    Resource(
        "knob",
        "Bluetooth: Key Negotiation Downgrade",
        KIND_PAPER,
        "https://knobattack.com/",
        "bluetooth-security",
        "The Bluetooth key negotiation downgrade. The model for how a "
        "protocol with no attacker in the middle still gets broken.",
        hours=3,
    ),
    Resource(
        "blueborne",
        "Ubertooth",
        "paper",
        "https://github.com/greatscottgadgets/ubertooth",
        "bluetooth-security",
        "An open-source Bluetooth sniffer. Just enough radio to watch "
        "pairing and BLE advertising happen, which is where the downgrade "
        "bugs live.",
        hours=2,
        access="free",
    ),
    Resource(
        "vpn-leak",
        "The WireGuard protocol",
        "paper",
        "https://www.wireguard.com/protocol/",
        "vpn-security",
        "A modern VPN protocol documented at the level of detail where its "
        "security properties become checkable rather than advertised.",
        hours=3,
        access="free",
    ),
    Resource(
        "vpnfilter",
        "VPNFilter",
        "paper",
        "https://blog.talosintelligence.com/vpnfilter/",
        "vpn-security",
        "A vulnerability in a widely deployed commercial VPN filter. A case "
        "study in how much trust a VPN deserves.",
        hours=2,
        access="free",
    ),
    Resource(
        "wireshark",
        "Wireshark",
        KIND_TOOL,
        "https://www.wireshark.org/",
        "network-traffic-analysis",
        "The protocol analyser. The first tool to open when you do not "
        "know what is on the wire.",
    ),
    Resource(
        "tcpdump",
        "tcpdump",
        KIND_TOOL,
        "https://www.tcpdump.org/",
        "network-traffic-analysis",
        "Capture from the command line, on a machine you do not control. "
        "Often the only option.",
    ),
    Resource(
        "scapy",
        "Scapy",
        KIND_TOOL,
        "https://scapy.net/",
        "network-traffic-analysis",
        "Build and send arbitrary packets from Python. The right tool for "
        "protocol research and for testing a parser.",
    ),
    Resource(
        "zmap",
        "ZMap",
        KIND_TOOL,
        "https://github.com/zmap/zmap",
        "firewall-evasion-research",
        "Internet-wide scanning at a scale that is only useful to "
        "researchers. Read the ethics guidance before running it.",
    ),
    Resource(
        "gnu-radio",
        "GNU Radio",
        KIND_TOOL,
        "https://www.gnuradio.org/",
        "sdr-radio-security",
        "The SDR framework. The entry point for radio work of any kind.",
    ),
    Resource(
        "hackrf",
        "HackRF One",
        "tool",
        "https://greatscottgadgets.com/hackrf/one/",
        "sdr-radio-security",
        "A wideband radio transceiver. The affordable way to get into RF "
        "research.",
        hours=0,
        access="paid",
    ),
    Resource(
        "ipv6-security",
        "RFC 8200 - Internet Protocol, Version 6",
        KIND_STANDARD,
        "https://www.rfc-editor.org/rfc/rfc8200",
        "ipv6-security",
        "The specification. The parser-confusion bugs all come from "
        "implementations reading this differently.",
        hours=0,
    ),
    Resource(
        "rfc9110",
        "RFC 9110 - HTTP Semantics",
        KIND_STANDARD,
        "https://www.rfc-editor.org/rfc/rfc9110",
        "web",
        "The HTTP specification. The authority on what a proxy is "
        "required to do with a header, and on which headers are "
        "hop-by-hop.",
        hours=0,
    ),
    # -- Cloud, supply chain, DevSecOps ------------------------------------
    Resource(
        "owasp-cloud",
        "AWS Well-Architected: Security Pillar",
        "guide",
        "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html",
        "cloud-pentesting",
        "The vendor's own definition of a well-secured cloud account, which "
        "is the baseline every cloud finding should be measured against.",
        hours=2,
        access="free",
    ),
    Resource(
        "imdsv2",
        "AWS: Configuring the instance metadata service",
        KIND_GUIDE,
        "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
        "cloud-pentesting",
        "How to require IMDSv2 and set a hop limit. The fix for the "
        "metadata problem.",
        hours=1,
    ),
    Resource(
        "nist-sp800-190",
        "NIST SP 800-190: Application Container Security Guide",
        KIND_STANDARD,
        "https://csrc.nist.gov/pubs/sp/800/190/final",
        "sandbox-escapes",
        "The container threat model, from the US government standards body. "
        "Free and rigorous.",
        hours=4,
    ),
    Resource(
        "slsa",
        "SLSA - Supply-chain Levels for Software Artifacts",
        KIND_GUIDE,
        "https://slsa.dev/",
        "software-supply-chain-security",
        "The framework for provenance and build integrity. The vocabulary "
        "the industry actually uses now.",
        hours=3,
    ),
    Resource(
        "sigstore",
        "Sigstore / cosign",
        KIND_TOOL,
        "https://github.com/sigstore/cosign",
        "software-supply-chain-security",
        "Signing and verifying artefacts without running your own key "
        "infrastructure.",
    ),
    Resource(
        "osv",
        "OSV.dev",
        KIND_TOOL,
        "https://osv.dev/",
        "software-composition-analysis",
        "The advisory database nemesis itself queries. Free and open.",
    ),
    Resource(
        "scorecard",
        "OpenSSF Scorecard",
        KIND_TOOL,
        "https://github.com/ossf/scorecard",
        "software-supply-chain-security",
        "Scores a repository's supply-chain posture from its own "
        "configuration. A good first look at an unfamiliar project.",
    ),
    Resource(
        "harden-project",
        "harden-project / slsa-github-generator",
        KIND_TOOL,
        "https://github.com/slsa-framework/slsa-github-generator",
        "ci-cd-pipeline-security",
        "Generates signed provenance for GitHub Actions builds. The "
        "practical way to make a pipeline attestable.",
    ),
    Resource(
        "zizmor",
        "zizmor - a static analysis tool for GitHub Actions",
        KIND_TOOL,
        "https://github.com/woodruffw/zizmor",
        "ci-cd-pipeline-security",
        "Finds the workflow mistakes nemesis also looks for, and more. "
        "Worth running alongside.",
    ),
    # -- Detection, IR, forensics -----------------------------------------
    Resource(
        "attack",
        "MITRE ATT&CK",
        KIND_GUIDE,
        "https://attack.mitre.org/",
        "detection-engineering",
        "The tactic and technique taxonomy every detection is written "
        "against. Learn the matrix structure, not every entry.",
        hours=8,
    ),
    Resource(
        "sigma",
        "Sigma Rules",
        KIND_TOOL,
        "https://github.com/SigmaHQ/sigma",
        "sigma-rules",
        "The detection rule format nemesis generates. The repository is "
        "also the best worked example of how to write one.",
    ),
    Resource(
        "yara",
        "YARA",
        KIND_TOOL,
        "https://virustotal.github.io/yara/",
        "yara-rules",
        "The pattern-matching language for malware. The documentation "
        "covers the module system that makes a rule useful.",
    ),
    Resource(
        "yaralint",
        "yara-x / yaralint",
        KIND_TOOL,
        "https://github.com/VirusTotal/yara-x",
        "yara-rules",
        "A linter and a faster engine for YARA. Use it to check the rules "
        "nemesis generates before you deploy them.",
    ),
    Resource(
        "nist-sp800-61",
        "NIST SP 800-61 Rev 3: Incident Handling Recommendations",
        KIND_STANDARD,
        "https://csrc.nist.gov/pubs/sp/800/61/r3/final",
        "incident-response",
        "The incident handling lifecycle, from the standards body. "
        "Rev 3 is the current edition.",
        hours=6,
    ),
    Resource(
        "volatility",
        "Volatility 3",
        KIND_TOOL,
        "https://github.com/volatilityfoundation/volatility3",
        "memory-forensics",
        "The memory forensics framework. The plugin list is a catalogue of "
        "what you can find in RAM.",
    ),
    Resource(
        "windows-mem-forensics",
        "Volatility 3 documentation",
        "book",
        "https://volatility3.readthedocs.io/",
        "memory-forensics",
        "The memory-forensics framework, and the reference for what is "
        "actually recoverable from a Windows image and where it lives.",
        hours=30,
        access="paid",
    ),
    Resource(
        "sleuth-kit",
        "The Sleuth Kit",
        KIND_TOOL,
        "https://www.sleuthkit.org/",
        "digital-forensics",
        "The filesystem forensics toolkit. The reference implementations "
        "of most of the carving tools.",
    ),
    Resource(
        "volatility-plugins",
        "Velociraptor",
        "tool",
        "https://github.com/Velocidex/velociraptor",
        "digital-evidence-analysis",
        "Endpoint visibility at scale: VQL queries over live and historical "
        "host state, which is how a timeline gets built across a fleet.",
        hours=0,
        access="free",
    ),
    Resource(
        "dfir-training",
        "Digital Forensics and Incident Response (DFIR) resources",
        KIND_GUIDE,
        "https://www.dfir-training.com/",
        "digital-forensics",
        "Practical, free DFIR training built around real cases. The "
        "closest thing to a lab for this area.",
        hours=0,
    ),
    Resource(
        "practical-malware-analysis",
        "Practical Malware Analysis",
        KIND_BOOK,
        "https://practicalmalwareanalysis.com/",
        "anti-malware-research",
        "Sikorski and Ptak. The book that teaches malware analysis as a "
        "method rather than a set of tools. Free online.",
        hours=20,
    ),
    Resource(
        "malware-traffic-analysis",
        "Malware Traffic Analysis",
        KIND_LAB,
        "https://malware-traffic-analysis.net/",
        "anti-malware-research",
        "Real malware samples with their traffic. The best way to learn to "
        "read a network capture.",
        hours=0,
    ),
    Resource(
        "any.run",
        "ANY.RUN interactive malware sandbox",
        KIND_TOOL,
        "https://any.run/",
        "ransomware-analysis",
        "Run a sample in a sandbox and watch it. Use it inside an isolated "
        "environment and under the terms of service.",
        access="freemium",
    ),
    Resource(
        "ransomware-reports",
        "Ransomware family analysis write-ups",
        KIND_PAPER,
        "https://www.malwarebytes.com/labs/threat-intelligence/",
        "ransomware-analysis",
        "Family-by-family breakdowns of ransomware behaviour. Start with "
        "the lockbit and maze write-ups.",
        hours=5,
    ),
    Resource(
        "edr-test",
        "Sysmon",
        "guide",
        "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon",
        "edr-xdr-research",
        "The Windows telemetry source most EDR products build on: process, "
        "network and file events with the fields a detection actually "
        "needs.",
        hours=0,
        access="free",
    ),
    # -- AI, ML, blockchain ------------------------------------------------
    Resource(
        "owasp-llm-top10",
        "OWASP Top 10 for LLM Applications",
        KIND_GUIDE,
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        "llm-security",
        "The current list of LLM failure modes, with mitigations. Short "
        "and directly usable in a threat model.",
        hours=2,
    ),
    Resource(
        "owasp-ml-top10",
        "OWASP Machine Learning Security Top 10",
        "guide",
        "https://mltop10.info/",
        "machine-learning-security",
        "The ML-specific risks: model poisoning, extraction, inversion and "
        "supply chain.",
        hours=2,
        access="free",
    ),
    Resource(
        "prompt-injection-research",
        "Prompt injection research (Simon Willison, Liu et al.)",
        KIND_PAPER,
        "https://simonwillison.net/tags/prompt-injection/",
        "llm-security",
        "The ongoing research thread on prompt injection, including the "
        "work on instruction hierarchy and delimiter-based defences.",
        hours=4,
    ),
    Resource(
        "model-extraction",
        "Stealing Machine Learning Models via Timing Attacks",
        KIND_PAPER,
        "https://arxiv.org/abs/1609.02943",
        "model-extraction-privacy",
        "Tramer et al. The paper that named model extraction as an attack "
        "and measured it.",
        hours=3,
    ),
    Resource(
        "model-inversion",
        "Model Inversion Attacks that Recover Training Data",
        KIND_PAPER,
        "https://arxiv.org/abs/1708.09516",
        "model-extraction-privacy",
        "Fredrikson et al. Recovers training data from a model's outputs, "
        "which is the privacy problem, not just the IP problem.",
        hours=3,
    ),
    Resource(
        "adversarial-examples",
        "Explaining and Harnessing Adversarial Examples",
        KIND_PAPER,
        "https://arxiv.org/abs/1412.6572",
        "adversarial-machine-learning",
        "Goodfellow, Shlens and Szegedy. The paper that made adversarial "
        "examples a field.",
        hours=3,
    ),
    Resource(
        "clever-hans",
        "Clever Hans or Reasonable Scientist?",
        KIND_PAPER,
        "https://arxiv.org/abs/1806.10566",
        "adversarial-machine-learning",
        "A study of a widely used benchmark that was measuring the wrong "
        "thing. The best cautionary tale in the field.",
        hours=3,
    ),
    Resource(
        "troj-ai",
        "The MITRE ATLAS adversarial ML threat matrix",
        KIND_GUIDE,
        "https://atlas.mitre.org/",
        "adversarial-machine-learning",
        "The ATT&CK equivalent for machine learning systems. Use it to "
        "threat-model a model pipeline.",
        hours=3,
    ),
    Resource(
        "nist-ai-rmf",
        "NIST AI Risk Management Framework",
        KIND_STANDARD,
        "https://www.nist.gov/itl/ai-risk-management-framework",
        "ai-security",
        "The governance framework for AI systems. Useful when the "
        "question is what to write down, not what to exploit.",
        hours=4,
    ),
    Resource(
        "sok-defi",
        "SoK: Decentralized Finance (DeFi)",
        KIND_PAPER,
        "https://arxiv.org/abs/2103.10700",
        "defi-security",
        "Werner et al. The taxonomy of DeFi attacks that everything else "
        "in this area builds on.",
        hours=4,
    ),
    Resource(
        "swcregistry",
        "Smart Contract Weakness Classification and Specification",
        KIND_GUIDE,
        "https://swcregistry.io/",
        "smart-contract-auditing",
        "The SWC registry. The vulnerability taxonomy for smart contracts, "
        "with examples.",
        hours=3,
    ),
    Resource(
        "ethernaut",
        "Ethernaut",
        KIND_LAB,
        "https://ethernaut.openzeppelin.com/",
        "smart-contract-auditing",
        "A smart contract security game. The best way to learn to read a "
        "contract adversarially.",
        hours=15,
    ),
    Resource(
        "dasp",
        "Damn Vulnerable DeFi",
        "lab",
        "https://www.damnvulnerabledefi.xyz/",
        "defi-security",
        "Hands-on challenges that each isolate one DeFi failure mode. "
        "Clearer than any checklist, because you have to actually drain the "
        "contract.",
        hours=10,
        access="free",
    ),
    Resource(
        "trail-of-bits",
        "Trail of Bits research blog",
        KIND_PAPER,
        "https://blog.trailofbits.com/",
        "smart-contract-auditing",
        "Real audits of real protocols, written up properly. Read these "
        "for the pattern of how a good audit report reads.",
        hours=0,
    ),
    # -- Practice, disclosure, research -------------------------------------
    Resource(
        "disclosure-policy",
        "A guide to coordinated vulnerability disclosure",
        KIND_GUIDE,
        "https://www.first.org/cvss/",
        "responsible-disclosure",
        "The FIRST CSVV guide. What a good disclosure timeline and a good "
        "policy look like.",
        hours=2,
    ),
    Resource(
        "hackerone-standards",
        "HackerOne Standard Report",
        "guide",
        "https://www.hackerone.com/",
        "hackerone-reports",
        "The report format HackerOne actually triages. Read it before you "
        "write your first report.",
        hours=1,
        access="free",
    ),
    Resource(
        "bugcrowd-standards",
        "Bugcrowd Vulnerability Rating Matrix",
        "guide",
        "https://bugcrowd.com/vulnerability-rating-taxonomy",
        "bugcrowd-reports",
        "How Bugcrowd converts an impact into a priority. The matrix that "
        "decides your payout tier.",
        hours=1,
        access="free",
    ),
    Resource(
        "intigriti-standards",
        "Intigriti report guidelines",
        KIND_GUIDE,
        "https://intigriti.com/programs/policy",
        "intigriti-reports",
        "Intigriti's own rules for what a report must contain.",
        hours=1,
    ),
    Resource(
        "cvss-spec",
        "CVSS v3.1 Specification",
        KIND_STANDARD,
        "https://www.first.org/cvss/v3-1/specification-document",
        "cvss-scoring",
        "The scoring specification. nemesis implements this, and the "
        "spec is the authority when a vector is arguable.",
        hours=3,
    ),
    Resource(
        "cwe",
        "Common Weakness Enumeration",
        KIND_GUIDE,
        "https://cwe.mitre.org/",
        "secure-code-review",
        "The weakness taxonomy. The vocabulary a review report needs in "
        "order to be actionable.",
        hours=0,
    ),
    Resource(
        "capec",
        "CAPEC - Common Attack Pattern Enumeration",
        KIND_GUIDE,
        "https://capec.mitre.org/",
        "root-cause-analysis",
        "Attack patterns rather than weaknesses. Useful for describing how "
        "a bug is actually exploited.",
        hours=0,
    ),
    Resource(
        "cisa-csaf",
        "CISA Advisories",
        KIND_GUIDE,
        "https://www.cisa.gov/news-events/cybersecurity-advisories",
        "threat-hunting",
        "Well-written advisories with detection guidance. Reading a few "
        "per month is the cheapest hunting practice there is.",
        hours=0,
    ),
    Resource(
        "sigma-taxonomy",
        "Sigma detection rule quality guidance",
        KIND_GUIDE,
        "https://github.com/SigmaHQ/sigma-specification",
        "detection-engineering",
        "The Sigma specification, including the guidance on rule quality. "
        "The part that stops a ruleset from becoming noise.",
        hours=2,
    ),
    Resource(
        "research-methods",
        "How to do security research",
        "guide",
        "https://github.com/0xdea",
        "original-research",
        "A practical guide to picking a research question, building a "
        "corpus, and writing the result up so someone else can reproduce "
        "it.",
        hours=3,
        access="free",
    ),
    Resource(
        "awesome-security",
        "Awesome Security research lists",
        KIND_PROJECT,
        "https://github.com/owasp/www-project-top-ten",
        "research-papers",
        "The starting point for finding a topic nobody has written about "
        "yet.",
        hours=0,
    ),
    Resource(
        "cve",
        "CVE Program",
        KIND_GUIDE,
        "https://www.cve.org/",
        "unsolved-vulnerabilities",
        "The record of what has been found. A good source of the shape of "
        "an unfixed class of bug.",
        hours=0,
    ),
    Resource(
        "exploit-db",
        "Exploit-DB",
        KIND_TOOL,
        "https://www.exploit-db.com/",
        "original-research",
        "Public proof-of-concept exploits. Read them as research papers, "
        "not as something to run.",
        hours=0,
    ),
    # -- Languages ----------------------------------------------------------
    Resource(
        "python-security",
        "Python security library reference",
        "guide",
        "https://docs.python.org/3/library/security_warnings.html",
        "python-for-hackers",
        "The standard library's security primitives, documented honestly - "
        "including the sharp edges in ssl, hashlib and hmac.",
        hours=4,
        access="free",
    ),
    Resource(
        "modern-c",
        "Modern C (Jens Gustedt)",
        KIND_BOOK,
        "https://gustedt.gitlabpages.inria.fr/modern-c/",
        "c-cpp-for-exploit-development",
        "Free, and it teaches the C standard rather than the folklore "
        "around it - including where the standard leaves the behaviour "
        "undefined, which is where the bugs are.",
        hours=20,
    ),
    Resource(
        "cpp-core-guidelines",
        "C++ Core Guidelines",
        KIND_GUIDE,
        "https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines",
        "c-cpp-for-exploit-development",
        "The modern C++ safety rules. Worth reading for the sections on "
        "raw pointers and ownership.",
        hours=6,
    ),
    Resource(
        "go-security",
        "Go security best practices",
        KIND_GUIDE,
        "https://go.dev/doc/security/best-practices",
        "go-for-security-tools",
        "The Go team's own guidance. Short, and specific to the ways Go "
        "gets things wrong - goroutine leaks, slice aliasing, integer "
        "overflow.",
        hours=1,
    ),
    Resource(
        "rust-security",
        "Rust's security guarantees and their limits",
        KIND_GUIDE,
        "https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html",
        "rust-for-security",
        "The ownership model is a memory-safety guarantee, not a safety "
        "guarantee. Read what it does not cover before you rely on it.",
        hours=6,
    ),
    Resource(
        "powershell-security",
        "PowerShell security guidance",
        KIND_GUIDE,
        "https://learn.microsoft.com/en-us/powershell/scripting/security/security-features",
        "bash-and-powershell",
        "The language mode and constrained endpoints. What a "
        "downloaded script can and cannot do.",
        hours=2,
    ),
    Resource(
        "bash-security",
        "Shell script security considerations",
        KIND_GUIDE,
        "https://www.shellcheck.net/",
        "bash-and-powershell",
        "ShellCheck finds the quoting bugs that turn a script into an "
        "injection point.",
    ),
    Resource(
        "awesome-security-tools",
        "Awesome lists of security tools",
        KIND_PROJECT,
        "https://github.com/awesome-security",
        "open-source-security-tools",
        "Directories of tools, organised by category. A map of the "
        "ecosystem rather than a recommendation.",
        hours=0,
    ),
    Resource(
        "awesome-selfhosted-security",
        "Self-hosted security tooling",
        KIND_PROJECT,
        "https://github.com/awesome-selfhosted/awesome-selfhosted",
        "open-source-security-tools",
        "The self-hosted side of security tooling: scanners, dashboards "
        "and log pipelines you run yourself.",
        hours=0,
    ),
    Resource(
        "nist-cybersecurity-framework",
        "NIST Cybersecurity Framework 2.0",
        KIND_STANDARD,
        "https://www.nist.gov/cyberframework",
        "devsecops",
        "Governance, identify, protect, detect, respond, recover. The "
        "structure a DevSecOps programme is usually measured against.",
        hours=4,
    ),
    Resource(
        "slsa-framework",
        "SLSA framework",
        KIND_GUIDE,
        "https://slsa.dev/spec/v1.0/",
        "software-supply-chain-security",
        "The build-integrity specification. Use it to decide what to "
        "attest to and how.",
        hours=3,
    ),
    Resource(
        "chaos-engineering",
        "Principles of Chaos Engineering",
        KIND_BOOK,
        "https://principlesofchaos.org/",
        "incident-response",
        "How to test that the recovery plan works. An untested recovery "
        "plan is not a plan.",
        hours=6,
    ),
    Resource(
        "nist-800-115",
        "NIST SP 800-115: Technical Guide to Information Security Testing",
        KIND_STANDARD,
        "https://csrc.nist.gov/pubs/sp/800/115/final",
        "incident-response",
        "The planning and execution guide for a security test, from "
        "scoping to reporting. The document to write the rules of "
        "engagement from.",
        hours=5,
    ),
    Resource(
        "pentest-reporting",
        "OWASP WSTG",
        "guide",
        "https://owasp.org/www-project-web-security-testing-guide/latest/",
        "security-report-writing",
        "The testing guide, including the reporting chapter, which is the "
        "part of a pentest most people under-invest in.",
        hours=2,
        access="free",
    ),
    # -- The areas the catalogue claims the library covers ---------------
    Resource(
        "hardware-exploitation-readings",
        "The Hardware Hacking Handbook",
        "paper",
        "https://nostarch.com/hardwarehacking",
        "hardware-exploitation",
        "The practical route from a board on a bench to a firmware dump: "
        "interfaces, glitching, side channels and what actually breaks.",
        hours=40,
        access="free",
    ),
    Resource(
        "chip-security-whitepapers",
        "ChipWhisperer documentation",
        "paper",
        "https://chipwhisperer.readthedocs.io/",
        "chip-hardware-security",
        "The reference hardware for power analysis and glitching, with the "
        "tutorials that make the measurement technique concrete.",
        hours=8,
        access="free",
    ),
    Resource(
        "technical-whitepapers-collection",
        "Vendor and standards-body whitepaper index",
        KIND_STANDARD,
        "https://www.nist.gov/publications",
        "technical-whitepapers",
        "The reference material behind most compliance work. Read the "
        "documents the standards point at, in the order they point.",
        hours=20,
    ),
    Resource(
        "security-books-reading-list",
        "Security Engineering, 3rd edition",
        "book",
        "https://www.cl.cam.ac.uk/~rja14/book.html",
        "security-books",
        "Ross Anderson's book, free online. The best explanation of why "
        "security fails at the system level rather than the component "
        "level.",
        hours=30,
        access="free",
    ),
    Resource(
        "security-tool-development-readings",
        "Writing security tools: the reference set",
        KIND_GUIDE,
        "https://github.com/mitre-attack/attack-stix-data",
        "security-tool-development",
        "For building tools that other people will actually use: the "
        "attack data model, the rule formats and the licence questions.",
        hours=15,
    ),
    Resource(
        "assembly-for-hackers-guides",
        "Azeria Labs: ARM assembly",
        "guide",
        "https://azeria-labs.com/writing-arm-assembly-part-1/",
        "assembly-for-hackers",
        "A from-scratch ARM assembly course aimed at exploit developers, "
        "which is a different emphasis from a compiler course.",
        hours=20,
        access="free",
    ),
    Resource(
        "github-security-project-guides",
        "GitHub code security",
        "project",
        "https://docs.github.com/en/code-security",
        "github-security-projects",
        "How a hosted project wires up code scanning, secret scanning and "
        "dependency review, which is the baseline every public repository "
        "should meet.",
        hours=6,
        access="free",
    ),

    # -- Core web application ------------------------------------------
    Resource(
        "portswigger-sqli",
        "PortSwigger: SQL injection labs",
        "lab",
        "https://portswigger.net/web-security/sql-injection",
        "sql-injection",
        "Nine labs that move from a UNION to a blind, time-based injection. "
        "The fastest way to feel the difference between a payload that "
        "works and one that is a coincidence.",
        hours=14,
        access="free",
    ),
    Resource(
        "sqlmap",
        "sqlmap",
        "tool",
        "https://sqlmap.org/",
        "sql-injection",
        "The reference implementation of SQL injection automation. Read its "
        "tamper scripts even if you never run it; they are a catalogue of "
        "the WAF-evasion tricks you will write yourself.",
        hours=6,
        access="free",
    ),
    Resource(
        "owasp-xss-prevention",
        "OWASP XSS Prevention Cheat Sheet",
        "guide",
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        "cross-site-scripting",
        "The contextual-output-encoding rules, written as rules rather than "
        "examples. If a fix does not follow this page, the fix is "
        "incomplete.",
        hours=4,
        access="free",
    ),
    Resource(
        "portswigger-xss",
        "PortSwigger: Cross-site scripting labs",
        "lab",
        "https://portswigger.net/web-security/cross-site-scripting",
        "cross-site-scripting",
        "Reflected, stored and DOM XSS, with the parsing traps that make a "
        "payload work in one context and die in the next.",
        hours=14,
        access="free",
    ),
    Resource(
        "dompurify",
        "DOMPurify",
        "tool",
        "https://github.com/cure53/DOMPurify",
        "cross-site-scripting",
        "The sanitiser most JavaScript applications actually use. Knowing "
        "its bypass history is knowing what clientside XSS still looks like "
        "in 2026.",
        hours=4,
        access="free",
    ),
    Resource(
        "portswigger-ssrf",
        "PortSwigger: SSRF labs",
        "lab",
        "https://portswigger.net/web-security/ssrf",
        "server-side-request-forgery",
        "Loopback, back-end systems and cloud metadata, including the "
        "blacklist bypasses that make an allowlist useless.",
        hours=10,
        access="free",
    ),
    Resource(
        "owasp-ssrf",
        "OWASP SSRF Prevention Cheat Sheet",
        "guide",
        "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        "server-side-request-forgery",
        "Why URL allowlists fail and what to do instead: resolve, pin, and "
        "refuse to re-resolve.",
        hours=4,
        access="free",
    ),
    Resource(
        "kettle-desync",
        "James Kettle: HTTP Desync Attacks",
        "paper",
        "https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn",
        "request-smuggling",
        "The paper that turned request smuggling from an obscure CTF trick "
        "into a bug-bounty category. Read the CL.TE and TE.CL sections "
        "twice.",
        hours=8,
        access="free",
    ),
    Resource(
        "kettle-http2-smuggling",
        "James Kettle: HTTP/2, the sequel is always worse",
        "paper",
        "https://portswigger.net/research/http2",
        "request-smuggling",
        "H2.CL, H2.TE and the downgrade bugs that appear when an HTTP/2 "
        "front end speaks HTTP/1.1 to its back end.",
        hours=6,
        access="free",
    ),
    Resource(
        "portswigger-smuggling",
        "PortSwigger: Request smuggling labs",
        "lab",
        "https://portswigger.net/web-security/request-smuggling",
        "request-smuggling",
        "Where the theory meets a proxy that actually desynchronises. Every "
        "lab here is a different framing disagreement.",
        hours=12,
        access="free",
    ),
    Resource(
        "kettle-cache-poisoning",
        "James Kettle: Practical Web Cache Poisoning",
        "paper",
        "https://portswigger.net/research/practical-web-cache-poisoning",
        "web-cache-poisoning",
        "The unkeyed-input model, which is the whole of cache poisoning in "
        "one idea. Everything since is an application of it.",
        hours=6,
        access="free",
    ),
    Resource(
        "kettle-cache-entanglement",
        "James Kettle: Web Cache Entanglement",
        "paper",
        "https://portswigger.net/research/web-cache-entanglement",
        "web-cache-poisoning",
        "The follow-up that separates cache poisoning from cache deception, "
        "and shows why the distinction changes the fix.",
        hours=6,
        access="free",
    ),
    Resource(
        "portswigger-websockets",
        "PortSwigger: WebSocket labs",
        "lab",
        "https://portswigger.net/web-security/websockets",
        "websockets-security",
        "Message manipulation and cross-site WebSocket hijacking, which is "
        "the WebSocket version of CSRF and just as often missed.",
        hours=6,
        access="free",
    ),
    Resource(
        "mdn-csp",
        "MDN: Content Security Policy",
        "guide",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP",
        "content-security-policy",
        "The reference for every directive and its fallback chain. A policy "
        "is only as strong as the directive you did not think about.",
        hours=5,
        access="free",
    ),
    Resource(
        "csp-evaluator",
        "Google CSP Evaluator",
        "tool",
        "https://csp-evaluator.withgoogle.com/",
        "content-security-policy",
        "Paste a policy and find out what it actually permits. Useful as an "
        "oracle when you are writing your own analysis.",
        hours=1,
        access="free",
    ),
    Resource(
        "portswigger-deserialization",
        "PortSwigger: Insecure deserialization labs",
        "lab",
        "https://portswigger.net/web-security/deserialization",
        "deserialization-attacks",
        "PHP, Java and Python object injection, with the gadget chains that "
        "turn a serialised blob into remote code execution.",
        hours=10,
        access="free",
    ),
    Resource(
        "ysoserial",
        "ysoserial",
        "tool",
        "https://github.com/frohoff/ysoserial",
        "deserialization-attacks",
        "The Java gadget-chain generator. Its payload list is also a "
        "reading list of every library that has ever been dangerous to "
        "deserialise.",
        hours=6,
        access="free",
    ),
    Resource(
        "marshalsec",
        "marshalsec",
        "tool",
        "https://github.com/mbechler/marshalsec",
        "deserialization-attacks",
        "Systematic analysis of Java unmarshaller vulnerabilities across "
        "libraries, with the JNDI tricks that made Log4Shell reachable.",
        hours=6,
        access="free",
    ),
    Resource(
        "portswigger-file-upload",
        "PortSwigger: File upload labs",
        "lab",
        "https://portswigger.net/web-security/file-upload",
        "file-upload-vulnerabilities",
        "Web shells, content-type confusion and the path-traversal "
        "combinations that make an upload directory a code execution "
        "primitive.",
        hours=8,
        access="free",
    ),
    Resource(
        "owasp-file-upload",
        "OWASP File Upload Cheat Sheet",
        "guide",
        "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
        "file-upload-vulnerabilities",
        "The defensive counterpart: what a correct upload pipeline "
        "validates, in order, and why the order matters.",
        hours=3,
        access="free",
    ),
    Resource(
        "portswigger-logic-flaws",
        "PortSwigger: Business logic vulnerabilities",
        "lab",
        "https://portswigger.net/web-security/logic-flaws",
        "business-logic-vulnerabilities",
        "The labs no scanner can auto-solve: trust in client-side controls, "
        "flawed assumptions, and domain-specific rules that break under a "
        "second request.",
        hours=10,
        access="free",
    ),
    Resource(
        "portswigger-host-header",
        "PortSwigger: HTTP Host header attacks",
        "lab",
        "https://portswigger.net/web-security/host-header",
        "proxy-security",
        "What happens when the application trusts the address it was "
        "reached on, and what an intermediary does to it in transit.",
        hours=6,
        access="free",
    ),
    Resource(
        "pwn-college",
        "pwn.college",
        "course",
        "https://pwn.college/",
        "browser-exploitation",
        "A free, lab-driven course from memory corruption up through "
        "browser exploitation. The module on JavaScript engines is the "
        "honest starting point for V8 work.",
        hours=120,
        access="free",
    ),
    Resource(
        "project-zero-blog",
        "Google Project Zero blog",
        "paper",
        "https://googleprojectzero.blogspot.com/",
        "browser-exploitation",
        "Where the best browser-exploitation write-ups are published, with "
        "the reasoning left in rather than edited out.",
        hours=40,
        access="free",
    ),
    Resource(
        "phrack",
        "Phrack",
        "paper",
        "https://phrack.org/",
        "browser-exploitation",
        "The zine that has published the primary sources for most of the "
        "exploitation canon, from heap feng shui onwards.",
        hours=30,
        access="free",
    ),
    Resource(
        "the-fuzzing-book",
        "The Fuzzing Book",
        "book",
        "https://www.fuzzingbook.org/",
        "fuzzing",
        "A full course on fuzzing, from mutation to coverage guidance to "
        "grammar-based generation, written by the people who formalised the "
        "field.",
        hours=30,
        access="free",
    ),
    Resource(
        "aflplusplus",
        "AFL++",
        "tool",
        "https://github.com/AFLplusplus/AFLplusplus",
        "fuzzing",
        "The forkserver that most real coverage-guided fuzzing runs on. Its "
        "documentation is a practical guide to instrumentation.",
        hours=10,
        access="free",
    ),
    Resource(
        "oss-fuzz",
        "OSS-Fuzz",
        "project",
        "https://github.com/google/oss-fuzz",
        "fuzzing",
        "The corpus and harness conventions that make a fuzzer find bugs "
        "instead of time out. Worth reading even for a local target.",
        hours=8,
        access="free",
    ),
    Resource(
        "gtfobins",
        "GTFOBins",
        "guide",
        "https://gtfobins.github.io/",
        "privilege-escalation",
        "Every binary that can be abused for a shell, a file read or a file "
        "write when you are allowed to run it as another user.",
        hours=3,
        access="free",
    ),
    Resource(
        "lolbas",
        "LOLBAS",
        "guide",
        "https://lolbas-project.github.io/",
        "privilege-escalation",
        "The Windows equivalent: signed binaries that download, execute or "
        "bypass in ways their authors never intended.",
        hours=3,
        access="free",
    ),
    Resource(
        "payloads-all-the-things",
        "PayloadsAllTheThings",
        "project",
        "https://github.com/swisskyrepo/PayloadsAllTheThings",
        "privilege-escalation",
        "An organised corpus of payloads per vulnerability class. The "
        "privilege-escalation and Linux sections are the useful ones here.",
        hours=6,
        access="free",
    ),
    Resource(
        "tlpi",
        "The Linux Programming Interface",
        "book",
        "https://man7.org/tlpi/",
        "linux-internals",
        "The system-call layer that privilege escalation lives in: "
        "credentials, capabilities, namespaces and the exact semantics of "
        "each call.",
        hours=60,
        access="paid",
    ),
    Resource(
        "linux-insides",
        "linux-insides",
        "book",
        "https://github.com/0xAX/linux-insides",
        "linux-internals",
        "A guided tour of kernel internals that assumes you want to "
        "understand the implementation, not just the API.",
        hours=40,
        access="free",
    ),
    Resource(
        "cis-benchmarks",
        "CIS Benchmarks",
        "standard",
        "https://www.cisecurity.org/cis-benchmarks",
        "infrastructure-misconfigurations",
        "The consensus definition of a hardened host, container runtime and "
        "cloud account. Every baseline check you write should trace back to "
        "one of these.",
        hours=20,
        access="free",
    ),
    Resource(
        "prowler",
        "Prowler",
        "tool",
        "https://github.com/prowler-cloud/prowler",
        "infrastructure-misconfigurations",
        "Hundreds of implemented cloud checks mapped to CIS, HIPAA and PCI. "
        "Read them before writing your own.",
        hours=8,
        access="free",
    ),
    Resource(
        "scoutsuite",
        "ScoutSuite",
        "tool",
        "https://github.com/nccgroup/ScoutSuite",
        "infrastructure-misconfigurations",
        "Multi-cloud posture assessment, and a useful map of what an "
        "attacker enumerates first in a new account.",
        hours=6,
        access="free",
    ),
    Resource(
        "checkov",
        "Checkov",
        "tool",
        "https://github.com/bridgecrewio/checkov",
        "infrastructure-as-code-security",
        "Policy checks across Terraform, Kubernetes, CloudFormation and "
        "more, with the rule IDs that make findings comparable across "
        "tools.",
        hours=8,
        access="free",
    ),
    Resource(
        "opa",
        "Open Policy Agent",
        "tool",
        "https://www.openpolicyagent.org/docs/latest/",
        "infrastructure-as-code-security",
        "The policy language most IaC gates are written in. If you want "
        "plans rejected before they merge, this is the mechanism.",
        hours=10,
        access="free",
    ),
    Resource(
        "owasp-secrets",
        "OWASP Secrets Management Cheat Sheet",
        "guide",
        "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
        "secrets-management",
        "Storage, rotation, scoping and the difference between a secret "
        "that is encrypted and a secret that is safe.",
        hours=5,
        access="free",
    ),
    Resource(
        "trufflehog",
        "TruffleHog",
        "tool",
        "https://github.com/trufflesecurity/trufflehog",
        "secrets-management",
        "Verified secret detection: it calls the provider to check whether "
        "the key is live, which is the difference between a finding and a "
        "guess.",
        hours=6,
        access="free",
    ),
    Resource(
        "vault-docs",
        "HashiCorp Vault documentation",
        "guide",
        "https://developer.hashicorp.com/vault/docs",
        "secrets-management",
        "The reference design for secrets management: leases, dynamic "
        "credentials, and why a static secret in an env var is a design "
        "smell.",
        hours=12,
        access="free",
    ),
    Resource(
        "aws-ir-guide",
        "AWS Security Incident Response Guide",
        "whitepaper",
        "https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html",
        "cloud-forensics",
        "The cloud-specific incident workflow: what evidence survives in an "
        "account, and how to capture it before it is gone.",
        hours=8,
        access="free",
    ),
    Resource(
        "cloudtrail-guide",
        "AWS CloudTrail User Guide",
        "guide",
        "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html",
        "cloud-forensics",
        "The log every AWS investigation is built on. Reading the event "
        "structure is the prerequisite for any cloud timeline.",
        hours=6,
        access="free",
    ),
    Resource(
        "mastering-bitcoin",
        "Mastering Bitcoin",
        "book",
        "https://github.com/bitcoinbook/bitcoinbook",
        "blockchain-security",
        "The mechanics underneath the security: keys, signatures, scripts "
        "and the transaction model that most contract bugs assume.",
        hours=40,
        access="free",
    ),
    Resource(
        "ethereum-security",
        "Ethereum: Smart contract security",
        "guide",
        "https://ethereum.org/en/developers/docs/smart-contracts/security/",
        "blockchain-security",
        "The canonical list of contract-level failure modes, from "
        "reentrancy to random-number misuse.",
        hours=6,
        access="free",
    ),
    Resource(
        "birsan-depconfusion",
        "Alex Birsan: Dependency Confusion",
        "paper",
        "https://medium.com/@alex.birsan/dependency-confusion-71e8664c4e4a",
        "dependency-confusion-research",
        "The original write-up: one trick, applied to Apple, Microsoft and "
        "dozens of other companies, all through package resolution order.",
        hours=4,
        access="free",
    ),
    Resource(
        "cyclonedx",
        "CycloneDX",
        "standard",
        "https://cyclonedx.org/",
        "supply-chain-security",
        "The SBOM format with the widest tool support, and the one most CI "
        "systems can emit without extra work.",
        hours=4,
        access="free",
    ),
    Resource(
        "snort",
        "Snort",
        "tool",
        "https://www.snort.org/",
        "ids-ips",
        "The rule language you will most often be asked to write in, and "
        "still the most widely deployed IDS.",
        hours=8,
        access="free",
    ),
    Resource(
        "suricata",
        "Suricata",
        "tool",
        "https://suricata.io/",
        "ids-ips",
        "Multi-threaded IDS/IPS with protocol parsers. Its rule syntax is "
        "close to Snort's, with better performance characteristics.",
        hours=8,
        access="free",
    ),
    Resource(
        "zeek",
        "Zeek",
        "tool",
        "https://zeek.org/",
        "ids-ips",
        "Network security monitoring that emits structured logs rather than "
        "alerts, which is what you actually need for hunting.",
        hours=12,
        access="free",
    ),
    Resource(
        "nist-800-61",
        "NIST SP 800-61: Incident Handling Guide",
        "standard",
        "https://csrc.nist.gov/pubs/sp/800/61/r2/final",
        "incident-handling",
        "The four-phase incident lifecycle that most organisations' "
        "procedures are a restatement of.",
        hours=6,
        access="free",
    ),
    Resource(
        "project-zero-0day",
        "Project Zero: 0day In the Wild",
        "paper",
        "https://googleprojectzero.blogspot.com/p/0day.html",
        "public-vulnerability-writeups",
        "A running index of exploited-in-the-wild vulnerabilities, each "
        "with root-cause analysis. The best examples of what a real write- "
        "up looks like.",
        hours=20,
        access="free",
    ),
    Resource(
        "zettelkasten",
        "Zettelkasten: a system for notes that compound",
        "guide",
        "https://zettelkasten.de/",
        "personal-lab-notes",
        "A note-taking method built for research that spans years, which is "
        "what a security lab notebook is.",
        hours=4,
        access="free",
    ),
    Resource(
        "obsidian",
        "Obsidian",
        "tool",
        "https://obsidian.md/",
        "personal-lab-notes",
        "Plain-markdown notes with backlinks, stored as files you own. The "
        "right shape for lab notes that must survive a decade.",
        hours=2,
        access="free",
    ),
    Resource(
        "awesome-pentest",
        "awesome-pentest",
        "project",
        "https://github.com/enaqx/awesome-pentest",
        "security-portfolio",
        "A maintained index of the field's tooling. Useful for finding the "
        "gap that your own project fills.",
        hours=2,
        access="free",
    ),
    Resource(
        "htb",
        "Hack The Box",
        "lab",
        "https://www.hackthebox.com/",
        "security-portfolio",
        "Retired machines with public write-ups, which is how most people "
        "build the portfolio that gets them hired.",
        hours=60,
        access="paid",
    ),
)


#: Resource kinds, in a stable order.
KINDS = (
    KIND_LAB,
    KIND_COURSE,
    KIND_PAPER,
    KIND_BOOK,
    KIND_WHITEPAPER,
    KIND_TOOL,
    KIND_PROJECT,
    KIND_STANDARD,
    KIND_GUIDE,
)


class Library:
    """The index, with search."""

    def __init__(self, resources: tuple[Resource, ...] = LIBRARY) -> None:
        self._resources = list(resources)
        self._by_id = {r.id: r for r in self._resources}
        if len(self._by_id) != len(self._resources):
            raise ValueError("duplicate resource id in the library")

    def all(self) -> list[Resource]:
        return list(self._resources)

    def get(self, resource_id: str) -> Resource | None:
        return self._by_id.get(resource_id)

    def by_area(self, area: str) -> list[Resource]:
        return [r for r in self._resources if r.area == area]

    def by_kind(self, kind: str) -> list[Resource]:
        return [r for r in self._resources if r.kind == kind]

    def areas(self) -> list[str]:
        return sorted({r.area for r in self._resources})

    def search(self, term: str) -> list[Resource]:
        needle = term.lower().strip()
        if not needle:
            return self.all()
        hits = []
        for resource in self._resources:
            haystack = " ".join(
                (resource.title, resource.note, resource.area, resource.kind)
            ).lower()
            if needle in haystack:
                hits.append(resource)
        return hits

    def coverage(self) -> dict:
        """Which capability areas the library covers."""
        covered = {r.area for r in self._resources}
        return {
            "total": len(self._resources),
            "areas": len(covered),
            "by_kind": {
                kind: len(self.by_kind(kind))
                for kind in KINDS
                if self.by_kind(kind)
            },
        }

    def to_dict(self) -> dict:
        return {
            "resources": [r.to_dict() for r in self._resources],
            "coverage": self.coverage(),
        }


#: A ready-to-use library.
LIBRARY_INDEX = Library()
