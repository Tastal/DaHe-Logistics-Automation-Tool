from __future__ import annotations

from dataclasses import dataclass
from typing import Final

SHANXI_GUIENBO: Final = "shanxi_guienbo"
SHANGHAI_JINYISHENG: Final = "shanghai_jinyisheng"
DEFAULT_CONTRACT_SUBJECT_CODE: Final = SHANXI_GUIENBO


@dataclass(frozen=True, slots=True)
class ContractSubject:
    code: str
    label: str


CONTRACT_SUBJECTS: Final = (
    ContractSubject(code=SHANXI_GUIENBO, label="山西贵恩博"),
    ContractSubject(code=SHANGHAI_JINYISHENG, label="上海晋亿晟"),
)
CONTRACT_SUBJECT_CODES: Final = frozenset(
    subject.code for subject in CONTRACT_SUBJECTS
)
CONTRACT_SUBJECT_LABELS: Final = {
    subject.code: subject.label for subject in CONTRACT_SUBJECTS
}


class ContractSubjectError(ValueError):
    """Raised when a Chengfeng contract-subject identity is unknown."""


def require_contract_subject_code(value: object) -> str:
    if not isinstance(value, str) or value not in CONTRACT_SUBJECT_CODES:
        raise ContractSubjectError("contract subject is invalid")
    return value


def contract_subject_label(code: str) -> str:
    try:
        return CONTRACT_SUBJECT_LABELS[require_contract_subject_code(code)]
    except KeyError as exc:  # pragma: no cover - guarded by validation
        raise ContractSubjectError("contract subject is invalid") from exc
