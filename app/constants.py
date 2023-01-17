# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

# User / authentication constants

AUTH_LOCAL = True
AUTH_LDAP = False
ROLE_USER = "0"
ROLE_ADMIN = "1"
ROLE_GUEST = "2"

# Analysis constants

IGNORE_EXTENSIONS = {".min.js"}
IGNORE_FOLDERS = {"vendor", "test", "Test"}

# Project constants

STATUS_NEW = 0
STATUS_FINISHED = 1
STATUS_ANALYZING = 2
STATUS_ERROR = 3
STATUS_PENDING = 4
STATUS_ABORTED = 5
PROJECTS_SRC_PATH = "data/projects/"
APP_INSP_PATH="app/third-party/app-inspector/ApplicationInspector_linux_1.6.26/ApplicationInspector.CLI"
EXTRACT_FOLDER_NAME = "extract"
SCC_PATH = "app/third-party/scc/scc"

# Rule constants

SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
RULES_PATH = "data/rules/"
RULES_ADMIN_PATH ="data/rules/AdminRules/"
RULE_EXTENSIONS = {".yaml", ".yml"}
OWASP_TOP10_LINKS = {
    "A01": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    "A02": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    "A03": "https://owasp.org/Top10/A03_2021-Injection/",
    "A04": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
    "A05": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    "A06": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    "A07": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    "A08": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
    "A09": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
    "A10": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
}
# https://cwe.mitre.org/top25/archive/2020/2020_cwe_top25.html#methodology
TOP40_CWE_SEVERITIES = {
    "CWE-79": SEVERITY_MEDIUM,
    "CWE-787": SEVERITY_HIGH,
    "CWE-20": SEVERITY_HIGH,
    "CWE-125": SEVERITY_HIGH,
    "CWE-119": SEVERITY_HIGH,
    "CWE-89": SEVERITY_HIGH,
    "CWE-200": SEVERITY_HIGH,
    "CWE-416": SEVERITY_HIGH,
    "CWE-352": SEVERITY_HIGH,
    "CWE-78": SEVERITY_HIGH,
    "CWE-190": SEVERITY_HIGH,
    "CWE-22": SEVERITY_HIGH,
    "CWE-476": SEVERITY_MEDIUM,
    "CWE-287": SEVERITY_HIGH,
    "CWE-434": SEVERITY_HIGH,
    "CWE-732": SEVERITY_MEDIUM,
    "CWE-94": SEVERITY_HIGH,
    "CWE-522": SEVERITY_HIGH,
    "CWE-611": SEVERITY_HIGH,
    "CWE-798": SEVERITY_HIGH,
    "CWE-502": SEVERITY_HIGH,
    "CWE-269": SEVERITY_HIGH,
    "CWE-400": SEVERITY_HIGH,
    "CWE-306": SEVERITY_HIGH,
    "CWE-862": SEVERITY_MEDIUM,
    "CWE-426": SEVERITY_HIGH,
    "CWE-918": SEVERITY_HIGH,
    "CWE-295": SEVERITY_HIGH,
    "CWE-863": SEVERITY_MEDIUM,
    "CWE-284": SEVERITY_HIGH,
    "CWE-77": SEVERITY_HIGH,
    "CWE-401": SEVERITY_MEDIUM,
    "CWE-532": SEVERITY_MEDIUM,
    "CWE-362": SEVERITY_MEDIUM,
    "CWE-601": SEVERITY_MEDIUM,
    "CWE-835": SEVERITY_MEDIUM,
    "CWE-704": SEVERITY_HIGH,
    "CWE-415": SEVERITY_HIGH,
    "CWE-770": SEVERITY_HIGH,
    "CWE-59": SEVERITY_HIGH,
}

# Language constants

LANGUAGES_DEVICONS = {
    "Python": "devicon-python-plain",
    "C": "devicon-c-plain",
    "JavaScript": "devicon-javascript-plain",
    "TypeScript": "devicon-typescript-plain",
    "JSON": "devicon-devicon-plain",
    "PHP": "devicon-php-plain",
    "Java": "devicon-java-plain",
    "Go": "devicon-go-plain",
    "OCaml": "devicon-ocaml-plain",
    "Ruby": "devicon-ruby-plain",
    "Kotlin": "devicon-kotlin-plain",
    "Bash": "devicon-bash-plain",
    "Rust": "devicon-rust-plain",
    "Scala": "devicon-scala-plain",
    "Solidity": "devicon-solidity-plain",
    "Terraform": "devicon-terraform-plain",
    "Generic": "devicon-devicon-plain"
}