"""Department Resolution V2 logic and supporting heuristics."""

from __future__ import annotations

import re
from typing import Any, Optional

from ..adp_client import extract_assignment_field, extract_business_title, extract_department


def _normalize_dept_signal(value: str) -> str:
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

_LOCAL_AC_DEPT_PRIORITY = [
    "Information Technology",
    "Human Resources",
    "Engineering",
    "Finance",
    "Sales",
    "Supply Chain",
    "Operations",
    "Administration",
]

_LOCAL_AC_FIELD_WEIGHTS = {
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

_LOCAL_AC_DIRECT_MAP = {
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

_LOCAL_AC_RULES = [
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

_AMBIGUOUS_REFERENCE_VALUES_NORMALIZED = {_normalize_dept_signal(v) for v in AMBIGUOUS_REFERENCE_VALUES}

_CANONICAL_BY_SIGNAL = {_normalize_dept_signal(dept): dept for dept in CANONICAL_DEPTS}

_DEPARTMENT_NORMALIZATION_ALIASES = {
    "information tech": "Information Technology",
    "it": "Information Technology",
    "recursos humanos": "Human Resources",
    "finanzas": "Finance",
    "sales and marketing": "Sales",
}

_LOW_CONFIDENCE_FIELDS = {"occupationalClassifications", "department"}
_CONFIDENCE_RANK = {"LOW": 1, "MED": 2, "HIGH": 3}

_TITLE_INFERENCE_RULES = [
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

_STRONG_ADMIN_TITLE_PATTERNS = [
    re.compile(r"\badministrative assistant\b"),
    re.compile(r"\bexecutive assistant\b"),
    re.compile(r"\breceptionist\b"),
    re.compile(r"\boffice administrator\b"),
    re.compile(r"\boffice manager\b"),
    re.compile(r"\badministrative services?\b"),
]


def normalize_department_name(value: str) -> str:
    """Normalize department values for comparisons and guardrails."""
    cleaned = re.sub(r"\s+", " ", (value or "").strip())
    if not cleaned:
        return ""
    if re.match(r"^information technology\s*\|", cleaned, flags=re.IGNORECASE):
        return "Information Technology"
    normalized = _normalize_dept_signal(cleaned)
    if normalized in _DEPARTMENT_NORMALIZATION_ALIASES:
        return _DEPARTMENT_NORMALIZATION_ALIASES[normalized]
    if normalized in _CANONICAL_BY_SIGNAL:
        return _CANONICAL_BY_SIGNAL[normalized]
    return cleaned


def _is_canonical_department(value: str) -> bool:
    """Return True when a value normalizes to one of the canonical departments."""
    return normalize_department_name(value) in CANONICAL_DEPTS


def _is_ambiguous_reference_value(value: str) -> bool:
    """Return True when a value is in the ambiguous reference list."""
    return _normalize_dept_signal(value) in _AMBIGUOUS_REFERENCE_VALUES_NORMALIZED


def _confidence_for_source(source: str, explicit_canonical: bool) -> str:
    """Map a source to confidence level."""
    if source in {"costCenterDescription", "assignedDept", "homeDept"}:
        return "HIGH"
    if source in {"managerDepartment", "titleInference"}:
        return "MED"
    if source in {"occupationalClassifications", "department"}:
        return "MED" if explicit_canonical else "LOW"
    return "LOW"


def _confidence_label(rank: int) -> str:
    """Convert numeric confidence rank to label."""
    for label, value in _CONFIDENCE_RANK.items():
        if value == rank:
            return label
    return "LOW"


def _is_customer_service_assigned_dept(source: str, value: str) -> bool:
    """Detect the customer service assignedDept override case."""
    if source not in {"assignedDept", "costCenterDescription"}:
        return False
    return _normalize_dept_signal(value).startswith("customer service")


def _is_explicit_admin_assigned_dept(value: str) -> bool:
    """Detect explicit admin-coded assigned department values."""
    normalized = _normalize_dept_signal(value)
    if normalized.startswith("admin"):
        return True
    explicit_markers = (
        "administrative svcs",
        "administrative services",
        "office administrator",
        "office manager",
        "admin services",
    )
    return any(marker in normalized for marker in explicit_markers)


def infer_department_from_title(title: str) -> dict:
    """Infer department from titles with patterns tuned to current dataset abbreviations."""
    normalized = _normalize_dept_signal(title)
    if not normalized:
        return {
            "department": "",
            "confidence": "",
            "reason": "",
            "isStrongAdmin": False,
        }

    scores: dict[str, int] = {}
    best_conf_rank: dict[str, int] = {}
    reasons: dict[str, list[str]] = {}
    for dept, confidence, weight, pattern in _TITLE_INFERENCE_RULES:
        if not pattern.search(normalized):
            continue
        scores[dept] = scores.get(dept, 0) + weight
        best_conf_rank[dept] = max(best_conf_rank.get(dept, 0), _CONFIDENCE_RANK[confidence])
        reasons.setdefault(dept, []).append(f"title:{title}")

    if not scores:
        return {
            "department": "",
            "confidence": "",
            "reason": "",
            "isStrongAdmin": False,
        }

    ranked = sorted(
        scores.items(),
        key=lambda item: (
            -best_conf_rank.get(item[0], 0),
            -item[1],
            _LOCAL_AC_DEPT_PRIORITY.index(item[0]),
        ),
    )
    chosen_dept = ranked[0][0]
    strong_admin = any(p.search(normalized) for p in _STRONG_ADMIN_TITLE_PATTERNS)
    return {
        "department": chosen_dept,
        "confidence": _confidence_label(best_conf_rank.get(chosen_dept, 1)),
        "reason": reasons.get(chosen_dept, [""])[0],
        "isStrongAdmin": strong_admin,
    }


def _make_candidate(
    department: str,
    source: str,
    reference_field: str,
    reference_value: str,
    confidence: str,
    reason: str,
    rule_weight: int = 0,
    is_direct: bool = False,
) -> dict:
    """Build a scored candidate record."""
    score = (
        (_CONFIDENCE_RANK.get(confidence, 1) * 1000)
        + _LOCAL_AC_FIELD_WEIGHTS.get(source, 30)
        + rule_weight
        + (80 if is_direct else 0)
    )
    return {
        "department": department,
        "source": source,
        "referenceField": reference_field,
        "referenceValue": reference_value,
        "confidence": confidence,
        "confidenceRank": _CONFIDENCE_RANK.get(confidence, 1),
        "reason": reason,
        "score": score,
        "ambiguousReference": _is_ambiguous_reference_value(reference_value),
    }


def _map_signal_candidates(source: str, raw_value: str) -> list[dict[str, Any]]:
    """Map one raw signal to one or more department candidates."""
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    normalized = _normalize_dept_signal(raw_value)
    if not normalized:
        return candidates

    def add_candidate(
        department: str,
        confidence: str,
        reason: str,
        rule_weight: int = 0,
        is_direct: bool = False,
    ):
        """Append a unique candidate for a signal, skipping ambiguous admin noise."""
        if department == "Administration" and _is_ambiguous_reference_value(raw_value):
            return
        key = (department, source, reason)
        if key in seen:
            return
        seen.add(key)
        candidates.append(
            _make_candidate(
                department=department,
                source=source,
                reference_field=source,
                reference_value=raw_value,
                confidence=confidence,
                reason=reason,
                rule_weight=rule_weight,
                is_direct=is_direct,
            )
        )

    if _is_customer_service_assigned_dept(source, raw_value):
        add_candidate(
            department="Sales",
            confidence="HIGH",
            reason=f"{source}:{raw_value} (customer_service_override)",
            rule_weight=120,
            is_direct=True,
        )

    explicit_canonical = _CANONICAL_BY_SIGNAL.get(normalized)
    if explicit_canonical:
        add_candidate(
            department=explicit_canonical,
            confidence=_confidence_for_source(source, explicit_canonical=True),
            reason=f"{source}:{raw_value} (explicit_canonical)",
            rule_weight=90,
            is_direct=True,
        )

    direct_match = _LOCAL_AC_DIRECT_MAP.get(normalized)
    if direct_match:
        add_candidate(
            department=direct_match,
            confidence=_confidence_for_source(source, explicit_canonical=False),
            reason=f"{source}:{raw_value} (direct)",
            rule_weight=80,
            is_direct=True,
        )

    for department, rule_weight, pattern in _LOCAL_AC_RULES:
        if pattern.search(normalized):
            add_candidate(
                department=department,
                confidence=_confidence_for_source(source, explicit_canonical=False),
                reason=f"{source}:{raw_value}",
                rule_weight=rule_weight,
            )

    return candidates


def _admin_assignment_allowed(signals: list, manager_department: str, title_info: dict) -> bool:
    """Return True when assigning Administration is strongly supported."""
    if normalize_department_name(manager_department) == "Administration":
        return True
    for source, value in signals:
        if source in {
            "costCenterDescription",
            "assignedDept",
            "homeDept",
        } and _is_explicit_admin_assigned_dept(value):
            return True
    if title_info.get("isStrongAdmin"):
        return True
    return False


def _pick_best_candidate(candidates: list[dict[str, Any]], admin_allowed: bool) -> Optional[dict[str, Any]]:
    """Pick best department candidate using confidence first and score second."""
    if not candidates:
        return None

    by_dept: dict[str, dict[str, Any]] = {}
    for candidate in candidates:
        dept = candidate["department"]
        slot = by_dept.setdefault(
            dept,
            {
                "department": dept,
                "score": 0,
                "bestConfidenceRank": 0,
                "evidence": [],
                "reasons": [],
            },
        )
        slot["score"] += candidate["score"]
        slot["bestConfidenceRank"] = max(slot["bestConfidenceRank"], candidate["confidenceRank"])
        slot["evidence"].append(candidate)
        slot["reasons"].append(candidate["reason"])

    ranked = sorted(
        by_dept.values(),
        key=lambda item: (
            -item["bestConfidenceRank"],
            -(item["score"] - (250 if item["department"] == "Administration" and not admin_allowed else 0)),
            _LOCAL_AC_DEPT_PRIORITY.index(item["department"]),
        ),
    )
    winner = ranked[0]
    primary = sorted(
        winner["evidence"],
        key=lambda item: (-item["confidenceRank"], -item["score"]),
    )[0]
    reason_trace = " | ".join(dict.fromkeys(winner["reasons"]))
    return {
        "department": winner["department"],
        "confidence": _confidence_label(winner["bestConfidenceRank"]),
        "evidenceUsed": primary["source"],
        "referenceField": primary["referenceField"],
        "referenceValue": primary["referenceValue"],
        "primaryReason": primary["reason"],
        "reasonTrace": reason_trace,
        "ambiguousReference": primary["ambiguousReference"],
    }


def _is_low_confidence_candidate(candidate: dict) -> bool:
    """Return True when evidence should not override manager-aligned current dept."""
    if not candidate:
        return True
    if candidate.get("source") in _LOW_CONFIDENCE_FIELDS:
        return True
    if candidate.get("ambiguousReference"):
        return True
    return candidate.get("confidence") == "LOW"


def _fallback_from_context(
    current_department: str,
    manager_department: str,
    title_department: str,
    reason_prefix: str,
) -> dict:
    """Apply the safer fallback chain for ambiguous/admin-gated cases."""
    current_raw = (current_department or "").strip()
    current_norm = normalize_department_name(current_raw)
    manager_norm = normalize_department_name(manager_department)
    title_norm = normalize_department_name(title_department)

    if current_raw:
        return {
            "department": current_norm or current_raw,
            "changeAllowed": False,
            "blockReason": f"{reason_prefix}_keep_current",
        }
    if manager_norm in CANONICAL_DEPTS:
        return {
            "department": manager_norm,
            "changeAllowed": True,
            "blockReason": f"{reason_prefix}_use_manager",
        }
    if title_norm in CANONICAL_DEPTS:
        return {
            "department": title_norm,
            "changeAllowed": True,
            "blockReason": f"{reason_prefix}_use_title",
        }
    return {
        "department": None,
        "changeAllowed": False,
        "blockReason": f"{reason_prefix}_needs_review",
    }


def resolve_local_ac_department(
    emp,
    current_ad_department: str = "",
    manager_department: str = "",
) -> dict:
    """
    Resolve department with candidate scoring, confidence, and guardrails.

    Business rules that are easy to miss:
    - Prefer high-confidence direct signals over inferred/ambiguous signals.
    - Do not override a manager-aligned current department with low-confidence evidence.
    - Gate Administration assignments unless explicit admin evidence is present.
    - Fall back to current -> manager -> title when evidence is weak/ambiguous.
    """
    signals = _collect_local_ac_department_signals(emp)
    title = extract_business_title(emp) or extract_assignment_field(emp, "jobTitle") or ""
    title_info = infer_department_from_title(title)
    manager_norm = normalize_department_name(manager_department)
    current_norm = normalize_department_name(current_ad_department)

    candidates = []
    for source, raw_value in signals:
        candidates.extend(_map_signal_candidates(source, raw_value))

    legacy_department = extract_department(emp)
    if legacy_department:
        candidates.extend(_map_signal_candidates("department", legacy_department))

    if manager_norm in CANONICAL_DEPTS:
        candidates.append(
            _make_candidate(
                department=manager_norm,
                source="managerDepartment",
                reference_field="managerDepartment",
                reference_value=manager_department,
                confidence="MED",
                reason=f"managerDepartment:{manager_department}",
                rule_weight=40,
                is_direct=True,
            )
        )

    title_department = normalize_department_name(title_info.get("department", ""))
    if title_department in CANONICAL_DEPTS:
        candidates.append(
            _make_candidate(
                department=title_department,
                source="titleInference",
                reference_field="title",
                reference_value=title,
                confidence=title_info.get("confidence") or "LOW",
                reason=title_info.get("reason") or f"title:{title}",
                rule_weight=45,
            )
        )

    admin_allowed = _admin_assignment_allowed(signals, manager_norm, title_info)
    chosen = _pick_best_candidate(candidates, admin_allowed)

    if not chosen:
        fallback = _fallback_from_context(
            current_department=current_ad_department,
            manager_department=manager_department,
            title_department=title_department,
            reason_prefix="no_candidate",
        )
        return {
            "proposedDepartment": fallback["department"],
            "proposedDepartmentV2": fallback["department"],
            "changeAllowed": fallback["changeAllowed"],
            "blockReason": fallback["blockReason"],
            "evidenceUsed": "",
            "confidence": "",
            "titleInferredDept": title_department,
            "departmentChangeReferenceField": "",
            "departmentChangeReferenceValue": "",
            "departmentChangePrimaryReason": "",
            "departmentChangeReasonTrace": "",
        }

    has_conflicting_low_candidate = any(
        normalize_department_name(candidate["department"]) != current_norm
        and _is_low_confidence_candidate(candidate)
        for candidate in candidates
    )
    has_ambiguous_low_signal = any(
        source in _LOW_CONFIDENCE_FIELDS and _is_ambiguous_reference_value(raw_value)
        for source, raw_value in signals
    ) or _is_ambiguous_reference_value(legacy_department)
    # Guardrail: keep the current department when manager/current align and only
    # weak or ambiguous evidence suggests a different value.
    if (
        current_norm
        and manager_norm
        and current_norm == manager_norm
        and (has_conflicting_low_candidate or has_ambiguous_low_signal)
    ):
        kept = current_norm or (current_ad_department or "").strip()
        return {
            "proposedDepartment": kept,
            "proposedDepartmentV2": kept,
            "changeAllowed": False,
            "blockReason": "blocked_by_manager_alignment",
            "evidenceUsed": chosen["evidenceUsed"],
            "confidence": chosen["confidence"],
            "titleInferredDept": title_department,
            "departmentChangeReferenceField": chosen["referenceField"],
            "departmentChangeReferenceValue": chosen["referenceValue"],
            "departmentChangePrimaryReason": chosen["primaryReason"],
            "departmentChangeReasonTrace": chosen["reasonTrace"],
        }

    # Guardrail: "Administration" is intentionally conservative because broad
    # labels in ADP can over-classify users into admin.
    if chosen["department"] == "Administration" and not admin_allowed:
        fallback = _fallback_from_context(
            current_department=current_ad_department,
            manager_department=manager_department,
            title_department=title_department,
            reason_prefix="admin_gated",
        )
        return {
            "proposedDepartment": fallback["department"],
            "proposedDepartmentV2": fallback["department"],
            "changeAllowed": fallback["changeAllowed"],
            "blockReason": fallback["blockReason"],
            "evidenceUsed": chosen["evidenceUsed"],
            "confidence": chosen["confidence"],
            "titleInferredDept": title_department,
            "departmentChangeReferenceField": chosen["referenceField"],
            "departmentChangeReferenceValue": chosen["referenceValue"],
            "departmentChangePrimaryReason": chosen["primaryReason"],
            "departmentChangeReasonTrace": chosen["reasonTrace"],
        }

    # Guardrail: ambiguous reference values should not force a department change.
    if chosen["ambiguousReference"]:
        fallback = _fallback_from_context(
            current_department=current_ad_department,
            manager_department=manager_department,
            title_department=title_department,
            reason_prefix="ambiguous_reference_value",
        )
        return {
            "proposedDepartment": fallback["department"],
            "proposedDepartmentV2": fallback["department"],
            "changeAllowed": fallback["changeAllowed"],
            "blockReason": fallback["blockReason"],
            "evidenceUsed": chosen["evidenceUsed"],
            "confidence": chosen["confidence"],
            "titleInferredDept": title_department,
            "departmentChangeReferenceField": chosen["referenceField"],
            "departmentChangeReferenceValue": chosen["referenceValue"],
            "departmentChangePrimaryReason": chosen["primaryReason"],
            "departmentChangeReasonTrace": chosen["reasonTrace"],
        }

    resolved_department = normalize_department_name(chosen["department"]) or chosen["department"]
    return {
        "proposedDepartment": resolved_department,
        "proposedDepartmentV2": resolved_department,
        "changeAllowed": True,
        "blockReason": "",
        "evidenceUsed": chosen["evidenceUsed"],
        "confidence": chosen["confidence"],
        "titleInferredDept": title_department,
        "departmentChangeReferenceField": chosen["referenceField"],
        "departmentChangeReferenceValue": chosen["referenceValue"],
        "departmentChangePrimaryReason": chosen["primaryReason"],
        "departmentChangeReasonTrace": chosen["reasonTrace"],
    }


def _collect_local_ac_department_signals(emp):
    """Collect candidate department signals across ADP worker fields."""
    signals = []
    seen = set()

    def add(source: str, value: str):
        """Record one non-empty signal while deduplicating repeated values."""
        raw_val = (value or "").strip()
        if not raw_val:
            return
        key = (source, raw_val)
        if key in seen:
            return
        seen.add(key)
        signals.append((source, raw_val))

    wa = emp.get("workAssignments", [])
    if not wa or not isinstance(wa[0], dict):
        return signals

    assignment = wa[0]

    def add_org_units(units, source: str, expected_type: str):
        """Pull organizational-unit names and optional cost-center descriptions."""
        if not isinstance(units, list):
            return
        for ou in units:
            if not isinstance(ou, dict):
                continue
            type_code = ou.get("typeCode", {}).get("codeValue", "").strip().lower()
            if type_code != expected_type:
                continue
            name_code = ou.get("nameCode", {})
            val = ""
            if isinstance(name_code, dict):
                val = (
                    name_code.get("shortName")
                    or name_code.get("longName")
                    or name_code.get("name")
                    or name_code.get("codeValue")
                    or ""
                )
            add(source, val)
            if expected_type == "department":
                cost_center_desc = ""
                if isinstance(name_code, dict):
                    cost_center_desc = (
                        name_code.get("longName") or name_code.get("shortName") or name_code.get("name") or ""
                    )
                add("costCenterDescription", cost_center_desc)

    add_org_units(assignment.get("assignedOrganizationalUnits", []), "assignedDept", "department")
    add_org_units(assignment.get("homeOrganizationalUnits", []), "homeDept", "department")
    add_org_units(assignment.get("assignedOrganizationalUnits", []), "businessUnit", "business unit")
    add_org_units(assignment.get("homeOrganizationalUnits", []), "businessUnit", "business unit")

    occ = assignment.get("occupationalClassifications", [])
    if isinstance(occ, list):
        for item in occ:
            if not isinstance(item, dict):
                continue
            code = item.get("classificationCode", {})
            if not isinstance(code, dict):
                continue
            val = code.get("shortName") or code.get("longName") or code.get("name") or ""
            add("occupationalClassifications", val)

    add("jobTitle", assignment.get("jobTitle", ""))
    add("businessTitle", extract_business_title(emp) or "")

    business_unit = assignment.get("businessUnit", {})
    if isinstance(business_unit, dict):
        add("businessUnit", business_unit.get("name", ""))

    return signals


def map_local_ac_department(
    emp,
    current_ad_department: str = "",
    manager_department: str = "",
) -> str:
    """Backward-compatible department mapper that returns only the chosen department."""
    resolved = resolve_local_ac_department(
        emp,
        current_ad_department=current_ad_department,
        manager_department=manager_department,
    )
    mapped = resolved.get("proposedDepartmentV2")
    if mapped:
        return mapped
    return "Administration"
