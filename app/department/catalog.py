"""Department resolution constants and regex catalogs."""

from __future__ import annotations

import re


def normalize_dept_signal(value: str) -> str:
    """Normalize free-form labels for deterministic department matching."""
    normalized = (value or "").strip().lower().replace("&", " and ")
    normalized = re.sub(r"[^a-z0-9\s\-/]", " ", normalized)
    return re.sub(r"\s+", " ", normalized).strip()


CANONICAL_DEPTS = {
    "Administration",
    "Engineering",
    "Finance",
    "Human Resources",
    "Information Technology",
    "Operations",
    "Sales",
    "Supply Chain",
}

LOCAL_AC_DEPT_PRIORITY = [
    "Information Technology",
    "Human Resources",
    "Engineering",
    "Finance",
    "Sales",
    "Supply Chain",
    "Operations",
    "Administration",
]

LOCAL_AC_FIELD_WEIGHTS = {
    "costCenterDescription": 105,
    "assignedDept": 100,
    "homeDept": 95,
    "occupationalClassifications": 85,
    "jobTitle": 70,
    "businessTitle": 65,
    "businessUnit": 50,
    "department": 45,
    "managerDepartment": 40,
    "titleInference": 55,
}

LOCAL_AC_DIRECT_MAP = {
    "operations": "Operations",
    "operaciones": "Operations",
    "administration": "Administration",
    "administrative": "Administration",
    "administrative support workers": "Administration",
    "supply chain": "Supply Chain",
    "information technology": "Information Technology",
    "information tech": "Information Technology",
    "it": "Information Technology",
    "human resources": "Human Resources",
    "hr": "Human Resources",
    "recursos humanos": "Human Resources",
    "engineering": "Engineering",
    "finance": "Finance",
    "finanzas": "Finance",
    "sales": "Sales",
    "sales and marketing": "Sales",
    "ventas": "Sales",
}

LOCAL_AC_RULES = [
    ("Information Technology", 40, re.compile(r"\binformation technology\b")),
    ("Information Technology", 35, re.compile(r"\binformation tech\b")),
    ("Information Technology", 20, re.compile(r"\bit\s*-")),
    ("Information Technology", 25, re.compile(r"\btecnolog")),
    ("Human Resources", 40, re.compile(r"\bhuman resources\b")),
    ("Human Resources", 35, re.compile(r"\brecursos humanos\b")),
    ("Human Resources", 25, re.compile(r"\bhr\b")),
    ("Engineering", 40, re.compile(r"\bengineering\b")),
    ("Engineering", 35, re.compile(r"\bengineer")),
    ("Engineering", 30, re.compile(r"\bingenier")),
    ("Engineering", 30, re.compile(r"\beng\s*-")),
    ("Engineering", 25, re.compile(r"\br\s*&\s*d\b")),
    ("Engineering", 25, re.compile(r"\bresearch\b")),
    ("Engineering", 25, re.compile(r"\bdevelopment\b")),
    ("Finance", 40, re.compile(r"\bfinance\b")),
    ("Finance", 35, re.compile(r"\bfinanzas\b")),
    ("Finance", 30, re.compile(r"\bfin\s*-")),
    ("Finance", 25, re.compile(r"\baccount")),
    ("Finance", 25, re.compile(r"\bcontab")),
    ("Sales", 40, re.compile(r"\bsales\b")),
    ("Sales", 35, re.compile(r"\bmarketing\b")),
    ("Sales", 35, re.compile(r"\bventas\b")),
    ("Sales", 30, re.compile(r"\bnatl\s*acct")),
    ("Sales", 30, re.compile(r"\bnational\s*acct")),
    ("Supply Chain", 40, re.compile(r"\bsupply chain\b")),
    ("Supply Chain", 35, re.compile(r"\bcadena de suministros\b")),
    ("Supply Chain", 30, re.compile(r"\bdistribution\b")),
    ("Supply Chain", 30, re.compile(r"\bdist\b")),
    ("Supply Chain", 30, re.compile(r"\bwarehouse\b")),
    ("Supply Chain", 25, re.compile(r"\blogistics\b")),
    ("Supply Chain", 20, re.compile(r"\bshipping\b")),
    ("Supply Chain", 20, re.compile(r"\breceiving\b")),
    ("Supply Chain", 20, re.compile(r"\bpurchase\b")),
    ("Supply Chain", 20, re.compile(r"\bprocurement\b")),
    ("Supply Chain", 20, re.compile(r"\bforklift\b")),
    ("Operations", 40, re.compile(r"\boperations\b")),
    ("Operations", 35, re.compile(r"\boperaciones\b")),
    ("Operations", 35, re.compile(r"\bmanufactur")),
    ("Operations", 35, re.compile(r"\bproduction\b")),
    ("Operations", 35, re.compile(r"\bmfg\b")),
    ("Operations", 30, re.compile(r"\bquality\b")),
    ("Operations", 30, re.compile(r"\bqa\b")),
    ("Operations", 30, re.compile(r"\boperatives\b")),
    ("Operations", 30, re.compile(r"\blaborers\b")),
    ("Operations", 25, re.compile(r"direct labor")),
    ("Operations", 25, re.compile(r"\bidl\b")),
    ("Operations", 25, re.compile(r"\bops\b")),
    ("Operations", 25, re.compile(r"\bops support\b")),
    ("Operations", 25, re.compile(r"\bops mgt\b")),
    ("Operations", 20, re.compile(r"\bextrusion\b")),
    ("Operations", 20, re.compile(r"\bthermoforming\b")),
    ("Operations", 20, re.compile(r"\bweld\b")),
    ("Operations", 20, re.compile(r"\broto\b")),
    ("Operations", 20, re.compile(r"\bvalue add\b")),
    ("Operations", 20, re.compile(r"\bsanta fe\b")),
    ("Administration", 40, re.compile(r"\badministration\b")),
    ("Administration", 35, re.compile(r"\badministrative services?\b")),
    ("Administration", 35, re.compile(r"\badministrative assistant\b")),
    ("Administration", 35, re.compile(r"\bexecutive assistant\b")),
    ("Administration", 35, re.compile(r"\breceptionist\b")),
    ("Administration", 30, re.compile(r"\boffice administrator\b")),
    ("Administration", 30, re.compile(r"\boffice manager\b")),
    ("Administration", 25, re.compile(r"\badmin\b")),
]

AMBIGUOUS_REFERENCE_VALUES = {
    "Professionals",
    "First/Mid-Level Officials and Managers",
    "Administrative Support Workers",
    "Mexico Corporate",
}

AMBIGUOUS_REFERENCE_VALUES_NORMALIZED = {normalize_dept_signal(v) for v in AMBIGUOUS_REFERENCE_VALUES}
CANONICAL_BY_SIGNAL = {normalize_dept_signal(dept): dept for dept in CANONICAL_DEPTS}

DEPARTMENT_NORMALIZATION_ALIASES = {
    "information tech": "Information Technology",
    "it": "Information Technology",
    "recursos humanos": "Human Resources",
    "finanzas": "Finance",
    "sales and marketing": "Sales",
}

LOW_CONFIDENCE_FIELDS = {"occupationalClassifications", "department"}
CONFIDENCE_RANK = {"LOW": 1, "MED": 2, "HIGH": 3}

TITLE_INFERENCE_RULES = [
    (
        "Engineering",
        "MED",
        80,
        re.compile(
            r"\bmfng\s*eng\b|\bmanufacturing\s*eng\b|\bmfg\s*eng\b|\bsr\s*eng\b|\bengineer(ing)?\b|\beng\b"
        ),
    ),
    (
        "Supply Chain",
        "MED",
        75,
        re.compile(
            r"\bmat\s*mngt\b|\bmaterials?\s*management\b|\bmaterial\s*mngt\b|\bdemand\s*plng\b|\bdemand\s*planning\b|\blogistics\b|\bdistribution\b|\bshipping\b|\binventory\b|\bplanner\b|\bbuyer\b|\bsourcing\b|\bprocurement\b"
        ),
    ),
    (
        "Information Technology",
        "MED",
        75,
        re.compile(
            r"\bend user services?\b|\beus\b|\bbi analyst\b|\bsystems?\b|\bnetwork\b|\bsecurity\b|\bit\b"
        ),
    ),
    (
        "Finance",
        "MED",
        75,
        re.compile(
            r"\baccounting\b|\baccounts?\s*payable\b|\baccounts?\s*receivable\b|\bcredit\s*&?\s*collect\b|\bcontroller\b|\bar\b|\bap\b"
        ),
    ),
    ("Sales", "MED", 75, re.compile(r"\baccount executive\b|\bcustomer service\b|\baccount management\b")),
    ("Human Resources", "MED", 75, re.compile(r"\bhuman resources\b|\bhr generalist\b")),
    (
        "Administration",
        "MED",
        75,
        re.compile(
            r"\badministrative assistant\b|\bexecutive assistant\b|"
            r"\breceptionist\b|\boffice administrator\b|\boffice manager\b|"
            r"\badministrative services?\b"
        ),
    ),
]

STRONG_ADMIN_TITLE_PATTERNS = [
    re.compile(r"\badministrative assistant\b"),
    re.compile(r"\bexecutive assistant\b"),
    re.compile(r"\breceptionist\b"),
    re.compile(r"\boffice administrator\b"),
    re.compile(r"\boffice manager\b"),
    re.compile(r"\badministrative services?\b"),
]
