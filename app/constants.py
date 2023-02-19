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
#CDXGEN = "cdxgen"
DEPSCAN_RESULT_FILE = "sbom-bom.vex.json"
DEPSCAN_RESULT_FOLDER = "dependencies"
#BOM_FILE="sbom-bom.json"
DEPSCAN = "depscan"
APPLICATION_INSPECTOR="app/third-party/app-inspector/ApplicationInspector_linux_1.6.26/ApplicationInspector.CLI"

# Project constants

STATUS_NEW = 0
STATUS_FINISHED = 1
STATUS_ANALYZING = 2
STATUS_ERROR = 3
STATUS_PENDING = 4
STATUS_ABORTED = 5
PROJECTS_SRC_PATH = "data/projects/"
EXTRACT_FOLDER_NAME = "extract"
SCC = "app/third-party/scc/scc"

# Rule constants

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_INFO = "info"
RULES_PATH = "data/rules/"
LOCAL_RULES ="local_rules"
LOCAL_RULES_PATH ="data/rules/" + LOCAL_RULES + "/"
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
    "Generic": "devicon-devicon-plain",
    "Swift": "devicon-swift-plain",
    "C#": "devicon-csharp-plain"
}