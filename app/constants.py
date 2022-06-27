# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

# Analysis constants

IGNORE_EXTENSIONS = {".min.js"}
IGNORE_FOLDERS = {"vendor", "test", "Test"}

# Project constants

STATUS_NEW = 0
STATUS_FINISHED = 1
STATUS_ANALYZING = 2
STATUS_ERROR = 3
STATUS_PENDING = 4
PROJECTS_SRC_PATH = "data/projects/"
APP_INSP_PATH="app/third-party/app-inspector/ApplicationInspector_linux_1.4.24/ApplicationInspector.CLI"
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
    "A1": "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection.html",
    "A2": "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication.html",
    "A3": "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure.html",
    "A4": "https://owasp.org/www-project-top-ten/2017/A4_2017-XML_External_Entities_(XXE).html",
    "A5": "https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control.html",
    "A6": "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration.html",
    "A7": "https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS).html",
    "A8": "https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization.html",
    "A9": "https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities.html",
    "A10": "https://owasp.org/www-project-top-ten/2017/A10_2017-Insufficient_Logging%2526Monitoring.html",
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
    "Generic": "devicon-devicon-plain"
}