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

IGNORE_LIST = ".min.js,.spec.ts,/nodes_modules/,/pods/,/vendor/,/test/,/tests/,/Test/,/Tests/,mock,Mock"
RESULT_FOLDER = "reports"
SCAN_LOGS_FOLDER = "logs"
DEPSCAN = "depscan"
APPLICATION_INSPECTOR="app/third-party/app-inspector/ApplicationInspector_linux_1.9.22/ApplicationInspector.CLI"
SEMGREP = "semgrep"
SEMGREP_MAX_FILES = 10000
SEMGREP_TIMEOUT = 3600 # 1 hour
DEPSCAN_TIMEOUT = 1800 # 30 minutes
APPLICATION_INSPECTOR_TIMEOUT=900 # 15 minutes

# Project constants

STATUS_NEW = 0
STATUS_FINISHED = 1
STATUS_ANALYZING = 2
STATUS_ERROR = 3
STATUS_PENDING = 4
STATUS_ABORTED = 5
PROJECTS_SRC_PATH = "data/projects/"
EXTRACT_FOLDER_NAME = "extract"
EXPORT_FOLDER_NAME = "exports"
SCC = "app/third-party/scc/scc"

# Vulnerability occurence Status

TO_REVIEW = {"id": 0, "name": "To review"}
CONFIRMED = {"id": 1, "name": "Confirmed"}
FALSE_POSITIVE = {"id": 2, "name": "False positive"}

STATUS = [TO_REVIEW, CONFIRMED, FALSE_POSITIVE]

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
    "C#": "devicon-csharp-plain",
    "Yaml": "devicon-yaml-plain",
    "HCL": "devicon-nomad-plain"
}

# Mapping for depscan insights
INSIGHTS_MAPPING = {
    "vendor_confirmed": "Vendor Confirmed",
    "has_PoC": "Has PoC",
    "direct_usage": "Direct usage",
    "direct_dep": "Direct dependency",
    "distro_specific": "Distro specific",
    "known_exploit": "Known Exploits",
    "exploitable": "Exploitable",
    "flagged_weakness": "Flagged weakness",
    "suppress_for_containers": "Suppress for containers",
    "uninstall_candidate": "Uninstall candidate",
    "indirect_dependency": "Indirect dependency",
    "local_install": "Local install",
    "reachable_Bounty_target": "Reachable Bounty target",
    "bug_Bounty_target": "Bug Bounty target",
    "reachable": "Reachable",
    "reachable_and_Exploitable": "Reachable and Exploitable",
    "malicious": "Malicious",
}

INSIGHTS_ICONS = {
    "vendor_confirmed": "fa-solid fa-certificate",
    "has_PoC": "fa-solid fa-vial",
    "direct_usage": "fa-solid fa-arrow-right-to-bracket",
    "direct_dep": "fa-solid fa-square-up-right",
    "distro_specific": "fa-brands fa-linux",
    "known_exploit": "fa-solid fa-book-skull",
    "exploitable": "fa-solid fa-skull-crossbones",
    "flagged_weakness": "fa-solid fa-flag",
    "suppress_for_containers": "fa-solid fa-scissors",
    "uninstall_candidate": "fa-solid fa-trash",
    "indirect_dependency": "fa-solid fa-diamond-turn-right",
    "local_install": "fa-solid fa-boxes-packing",
    "reachable_Bounty_target": "fa-solid fa-road-circle-exclamation",
    "bug_Bounty_target": "fa-solid fa-money-bill",
    "reachable": "fa-regular fa-circle-dot",
    "reachable_and_Exploitable": "fa-solid fa-bullseye",
    "malicious": "fa-solid fa-skull"
}

INSIGHTS_COLORS = {
    "vendor_confirmed": "navy",
    "has_PoC": "warning",
    "direct_usage": "purple",
    "direct_dep": "info",
    "distro_specific": "light",
    "known_exploit": "danger",
    "exploitable": "danger",
    "flagged_weakness": "gray-dark",
    "suppress_for_containers": "gray",
    "uninstall_candidate": "pink",
    "indirect_dependency": "light",
    "local_install": "lime",
    "reachable_Bounty_target": "fuchsia",
    "bug_Bounty_target": "lightblue",
    "reachable": "orange",
    "reachable_and_Exploitable": "danger",
    "malicious": "danger"
}