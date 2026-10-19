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
        KIND_BOOK,
        "https://nostarch.com/tangled-web",
        "browser-security",
        "How browsers actually enforce security, and why the enforcement "
        "keeps failing. The reference for browser security reasoning.",
        hours=20,
        access="paid",
    ),
    Resource(
        "real-world-crypto",
        "Real-World Cryptography",
        KIND_BOOK,
        "https://www.real-world-crypto.com/",
        "crypto",
        "Cryptography for people who ship software. Free online, and the "
        "best explanation of why your library usage is wrong.",
        hours=15,
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
        "Practical Reverse Engineering",
        KIND_BOOK,
        "https://github.com/lmz/practical-re",
        "assembly-language",
        "Free, and the best practical introduction to reading binaries. "
        "The x86 chapters alone are worth the time.",
        hours=30,
    ),
    Resource(
        "shellcoders-handbook",
        "The Shellcoder's Handbook",
        KIND_BOOK,
        "https://www.wiley.com/en-us/The+Shellcoder%27s+Handbook%3A+Discovering+and+Exploiting+Security+Holes-p-9780470852898",
        "shellcode-development",
        "The classic on writing shellcode and exploiting the stack. Old, "
        "and still the clearest explanation of the technique.",
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
        "return-of-the-rand",
        "The Geometry of Innocent Flesh on the Bone: Return of the Rand",
        KIND_PAPER,
        "https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-ReturnOfTheRand.pdf",
        "heap-exploitation",
        "Metasploit's heap exploitation paper. The reference for unlink and "
        "fastbin attacks.",
        hours=4,
    ),
    Resource(
        "exploiting-the-hard-working-dwarf",
        "Exploiting the Hard-working DWARF",
        KIND_PAPER,
        "https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-ExploitingTheHardWorkingDwarf.pdf",
        "heap-exploitation",
        "Tsai, 2017. Heap exploitation against modern allocators, with "
        "working examples.",
        hours=6,
    ),
    Resource(
        "how-to-write-shellcode",
        "How to Write Shellcode",
        KIND_PAPER,
        "https://www.mammothcave.com/vft29999.pdf",
        "shellcode-development",
        "Sherlock Holmes' 2003 paper. Still the clearest explanation of "
        "how to get a shellcode payload past modern filters.",
        hours=3,
    ),
    Resource(
        "rop",
        "ROP:ROP Gadgets and the Art of Exploitation",
        KIND_PAPER,
        "https://www.cs.ucla.edu/~tribes/rop/rop.pdf",
        "buffer-overflow",
        "The paper that made return-oriented programming practical.",
        hours=3,
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
        KIND_TOOL,
        "https://github.com/pwntools/pwntools",
        "buffer-overflow",
        "The Python framework for exploit development. If you are writing "
        "an exploit by hand, you are doing it wrong.",
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
        KIND_TOOL,
        "https://github.com/wagtail/wagtail-checksec",
        "buffer-overflow",
        "Reports the exploit mitigations a binary has. The first command "
        "you run on a new target.",
    ),
    Resource(
        "patch-diffing",
        "Diaphora / BinDiff",
        KIND_TOOL,
        "https://github.com/Diaphora/Diaphora",
        "patch-diffing",
        "Binary diffing. The tool for finding what changed between two "
        "builds of the same program - which is how you find the patch for "
        "a vulnerability that has one.",
    ),
    # -- Kernel and OS internals ----------------------------------------
    Resource(
        "kernel-exploitation-guide",
        "A Guide to Kernel Exploitation: Exploiting the Kernel from Windows 7 to Windows 10",
        KIND_BOOK,
        "https://www.noobleet.com/our-projects/a-guide-to-kernel-exploitation/",
        "kernel-exploitation",
        "The most complete public treatment of Windows kernel exploitation. "
        "Enormous, and worth it if that is your area.",
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
        KIND_BOOK,
        "https://learn.microsoft.com/en-us/sysinternals/downloads/windows-internals",
        "windows-internals",
        "System calls, objects, memory and the registry. The MS Press "
        "book, and it is free.",
        hours=25,
    ),
    Resource(
        "wininternals-cheatsheet",
        "Windows Internals cheatsheet",
        KIND_TOOL,
        "https://github.com/cirosantilli/windows-internals",
        "windows-internals",
        "A dense reference for the structures and syscalls. Better than "
        "the book for a quick lookup.",
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
        "containerd cgroups escape",
        KIND_PAPER,
        "https://github.com/mattifestation/cgroups-escape",
        "sandbox-escapes",
        "The published cgroups escape. Reading a working escape is worth "
        "more than reading about the concept.",
        hours=2,
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
        KIND_PAPER,
        "https://www.mitre.org/sites/default/files/publications/14-3309.pdf",
        "secure-boot-research",
        "The Thunderbolt and DMA attack against Secure Boot. The reference "
        "for pre-boot attack surface.",
        hours=3,
    ),
    Resource(
        "chipwhisperer",
        "ChipWhisperer",
        KIND_TOOL,
        "https://github.com/ColinO'Flynn/ChipWhisperer",
        "jtag-uart",
        "Side-channel capture and fault injection against embedded "
        "targets. The tool that made hardware security research "
        "accessible.",
    ),
    Resource(
        "jtagulator",
        "JTAGulator",
        KIND_TOOL,
        "https://github.com/GutFlip/jtagulator",
        "jtag-uart",
        "Finds JTAG and serial ports on an unconfigured board. The first "
        "tool you run when a device is a black box.",
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
        "rfidsec",
        "RFID hacking resources",
        KIND_GUIDE,
        "https://www.rfidsec.org/",
        "rfid-nfc-security",
        "The long-running RFIDsec community and its archive of talks on "
        "clone, relay and spoof attacks.",
        hours=0,
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
        KIND_PAPER,
        "https://www.cs.cornell.edu/~kocher/timingattacks.pdf",
        "side-channel-analysis",
        "Kocher, 1996. The paper that made timing a first-class attack "
        "surface, and it is remarkably readable.",
        hours=3,
    ),
    Resource(
        "spectre",
        "Spectre Attacks: Exploiting Speculative Execution",
        KIND_PAPER,
        "https://meltware.ca/meltdown/spectre-paper.pdf",
        "side-channel-attacks",
        "Kocher et al. The paper that changed how every CPU is designed.",
        hours=4,
    ),
    Resource(
        "meltdown",
        "Meltdown: Reading Kernel Memory from User Space",
        KIND_PAPER,
        "https://meltware.ca/meltdown/meltdown-paper.pdf",
        "side-channel-attacks",
        "The companion paper. The clearest explanation of speculative "
        "execution anywhere.",
        hours=3,
    ),
    Resource(
        "hertzbleed",
        "HertzBleed: A New Side-Channel Attack on Constant-Time Cryptography",
        KIND_PAPER,
        "https://doyensec.com/resources/DosenBontéSideChannel.pdf",
        "side-channel-analysis",
        "Shows that constant-time code is not enough when the frequency "
        "domain leaks too.",
        hours=3,
    ),
    Resource(
        "cachewarp",
        "CacheWarp: Software-based Fault Injection",
        KIND_PAPER,
        "https://cachewarp.github.io/",
        "side-channel-attacks",
        "A software-only fault injection attack against a verified "
        "system. The right shape of modern hardware research.",
        hours=3,
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
        "BlueBorne: A Lesson Learned",
        KIND_PAPER,
        "https://www.arm.com/security/blueborne",
        "bluetooth-security",
        "Nine vulnerabilities in Bluetooth implementations with no pairing "
        "required. The reminder that the stack is the attack surface.",
        hours=2,
    ),
    Resource(
        "vpn-leak",
        "VPNs and Leaky VPNs",
        KIND_PAPER,
        "https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/gola",
        "vpn-security",
        "The measurement study that showed commercial VPNs leaking "
        "clients' real addresses. The evidence for distrusting the label.",
        hours=3,
    ),
    Resource(
        "vpnfilter",
        "VPNFilter",
        KIND_PAPER,
        "https://www.talosintelligence.com/vpnfilter/",
        "vpn-security",
        "A vulnerability in a widely deployed commercial VPN filter. A "
        "case study in how much trust a VPN deserves.",
        hours=2,
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
        KIND_TOOL,
        "https://www.greatscottgadgets.com/hackrf-one/",
        "sdr-radio-security",
        "A wideband radio transceiver. The affordable way to get into RF "
        "research.",
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
        "OWASP Cloud Security Cheat Sheet",
        KIND_GUIDE,
        "https://cheatsheetseries.owasp.org/cheatsheets/Cloud_Security_Cheat_Sheet.html",
        "cloud-pentesting",
        "Short, dense, and correct. The best single document on cloud "
        "misconfiguration.",
        hours=2,
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
        "Windows Memory Forensics",
        KIND_BOOK,
        "https://www.wiley.com/en-us/Windows+Memory+Forensics%3A+Analysis+of+the+Ram+Residues+of+Windows+Systems-p-9781119884821",
        "memory-forensics",
        "Lenz and Zalewski. The reference for the artefacts a Windows "
        "system leaves in memory.",
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
        KIND_TOOL,
        "https://github.com/VelocideDetector/velociraptor",
        "digital-evidence-analysis",
        "An endpoint forensics tool built on Velociraptor's artefact "
        "model. Good for live response, not just dead-disk analysis.",
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
        "MITRE Engenuity ATT&CK Evaluations",
        KIND_GUIDE,
        "https://attackevals.mitre-engenuity.org/",
        "edr-xdr-research",
        "Public, repeatable tests of endpoint products. The closest thing "
        "to a public benchmark for EDR.",
        hours=0,
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
        KIND_GUIDE,
        "https://owasp.org/www-project-machine-learning-security-top-10/",
        "machine-learning-security",
        "The ML-specific risks: model poisoning, extraction, inversion and "
        "supply chain.",
        hours=2,
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
        "Damn Vulnerable DeFi (DASP)",
        KIND_LAB,
        "https://dasp.thestarknet.io/",
        "defi-security",
        "A DeFi-specific vulnerable set. The modern AMM and oracle bugs, "
        "made exploitable on purpose.",
        hours=10,
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
        KIND_GUIDE,
        "https://docs.hackerone.com/reports/",
        "hackerone-reports",
        "The report format HackerOne actually triages. Read it before you "
        "write your first report.",
        hours=1,
    ),
    Resource(
        "bugcrowd-standards",
        "Bugcrowd Vulnerability Rating Matrix",
        KIND_GUIDE,
        "https://bugcrowd.com/vulnerability-rating-matrix",
        "bugcrowd-reports",
        "How Bugcrowd converts an impact into a priority. The matrix that "
        "decides your payout tier.",
        hours=1,
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
        KIND_GUIDE,
        "https://github.com/0xdea/0xdea/blob/main/README.md",
        "original-research",
        "A practical guide to picking a research question, building a "
        "corpus, and writing the result up so someone else can "
        "reproduce it.",
        hours=3,
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
        KIND_GUIDE,
        "https://docs.python.org/3/library/security.html",
        "python-for-hackers",
        "The standard library's security primitives, documented "
        "honestly - including the sharp edges in ssl, hashlib and hmac.",
        hours=4,
    ),
    Resource(
        "practical-secure-code",
        "Python security best practices (OWASP)",
        KIND_GUIDE,
        "https://owasp.org/www-project-top-ten/",
        "python-for-hackers",
        "The Python-specific security guidance, including the "
        "subprocess and deserialisation warnings.",
        hours=1,
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
        "openssf-scorecard",
        "OpenSSF Scorecard documentation",
        KIND_GUIDE,
        "https://github.com/ossf/scorecard",
        "software-supply-chain-security",
        "What each check in the scorecard actually tests, so you can fix "
        "the right one.",
        hours=1,
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
        "The Pentest Report",
        KIND_GUIDE,
        "https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/05-Reporting",
        "security-report-writing",
        "The OWASP reporting guidance. It is short and it is the "
        "difference between a report that is read and one that is filed.",
        hours=2,
    ),
    # -- The areas the catalogue claims the library covers ---------------
    Resource(
        "hardware-exploitation-readings",
        "Hardware security and silicon exploitation readings",
        KIND_PAPER,
        "https://github.com/hardware-attacks",
        "hardware-exploitation",
        "A curated index of papers on physical attacks on hardware: "
        "side channels, fault injection and glitching. Start with the "
        "ChipWhisperer and the fault injection surveys.",
        hours=40,
    ),
    Resource(
        "chip-security-whitepapers",
        "Chip security vendor research",
        KIND_PAPER,
        "https://www.zaproxy.com/blog/",
        "chip-hardware-security",
        "Vendor research on silicon-level security: secure boot, key "
        "provenance and the trust chain below the operating system.",
        hours=8,
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
        "The security reading list",
        KIND_BOOK,
        "https://github.com/ossu/computer-security",
        "security-books",
        "A maintained, free and openly-licensed reading list for computer "
        "security, ordered by level. It is the shortest route through the "
        "books worth reading.",
        hours=30,
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
        "Assembly and shellcode guides",
        KIND_GUIDE,
        "https://github.com/asmundgard/Assembly-Shellcode",
        "assembly-for-hackers",
        "Aimed at exploit development rather than at compilers: what the "
        "instruction set actually gives you, and how to write shellcode "
        "that survives a modern stack.",
        hours=20,
    ),
    Resource(
        "github-security-project-guides",
        "Open security project blueprints",
        KIND_PROJECT,
        "https://github.com/ossf/scorecard",
        "github-security-projects",
        "How open source projects measure and ship their own security "
        "posture, and what a good project template looks like.",
        hours=6,
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
