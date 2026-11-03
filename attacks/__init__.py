"""Scripted adversary: one module per attack in SCOPE.md's threat model (A1-A6)."""

from . import a1_edit, a2_delete, a3_reorder, a4_forge, a5_spoof, a6_rollback
from .base import Attack
from .formats import AuditFmt, Doc, NaiveFmt, TranscriptFmt
from .session import Session, record_session

ALL_ATTACKS = (
    a1_edit.ATTACK,
    a2_delete.DELETE,
    a2_delete.TRUNCATE,
    a3_reorder.ATTACK,
    a4_forge.ATTACK,
    a5_spoof.ATTACK,
    a6_rollback.ATTACK,
)

__all__ = ["ALL_ATTACKS", "Attack", "AuditFmt", "Doc", "NaiveFmt", "Session", "TranscriptFmt", "record_session"]
