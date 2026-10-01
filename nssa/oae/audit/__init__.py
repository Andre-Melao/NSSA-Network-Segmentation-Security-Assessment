"""Audit Intelligence layer for the OAE.

Turns PolicyFindings into AuditFindings, one per exposed service, via: flatten
to per-host RawFindings, correlate by (dst_ip, dst_port, proto), build
ViolatedRules, select representative paths, assign priority (destination
criticality dominates), and sort by priority.

Each AuditFinding answers "Who can reach this service, and why?"; priority
answers "Which exposed service should the auditor look at first?"

Entry point: build_audit_findings()
"""

from nssa.oae.audit.aggregation import build_audit_findings
from nssa.oae.audit.models import (
    AuditFinding,
    FindingReason,
    HostRef,
    IMPLICIT_DEFAULT_DENY,
    RawFinding,
    ViolatedRule,
)
from nssa.oae.audit.priority import DEFAULT_SECONDARY_FACTORS, ScoringFactor

__all__ = [
    "build_audit_findings",
    "DEFAULT_SECONDARY_FACTORS",
    "AuditFinding",
    "FindingReason",
    "HostRef",
    "IMPLICIT_DEFAULT_DENY",
    "RawFinding",
    "ScoringFactor",
    "ViolatedRule",
]
