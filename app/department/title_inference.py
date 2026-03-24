"""Title-based inference helpers for department resolution."""

from __future__ import annotations

from .catalog import (
    CONFIDENCE_RANK,
    LOCAL_AC_DEPT_PRIORITY,
    STRONG_ADMIN_TITLE_PATTERNS,
    TITLE_INFERENCE_RULES,
    normalize_dept_signal,
)
from .normalization import confidence_label


def infer_department_from_title(title: str) -> dict:
    """Infer department from titles with patterns tuned to the current dataset."""
    normalized = normalize_dept_signal(title)
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
    for dept, confidence, weight, pattern in TITLE_INFERENCE_RULES:
        if not pattern.search(normalized):
            continue
        scores[dept] = scores.get(dept, 0) + weight
        best_conf_rank[dept] = max(best_conf_rank.get(dept, 0), CONFIDENCE_RANK[confidence])
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
            LOCAL_AC_DEPT_PRIORITY.index(item[0]),
        ),
    )
    chosen_dept = ranked[0][0]
    strong_admin = any(pattern.search(normalized) for pattern in STRONG_ADMIN_TITLE_PATTERNS)
    return {
        "department": chosen_dept,
        "confidence": confidence_label(best_conf_rank.get(chosen_dept, 1)),
        "reason": reasons.get(chosen_dept, [""])[0],
        "isStrongAdmin": strong_admin,
    }
