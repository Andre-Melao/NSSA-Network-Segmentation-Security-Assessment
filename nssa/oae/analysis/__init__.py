"""OAE analysis package.

Reachability layer — builds a destination-centric index from the observed graph:
  ReachabilityEvidence, ReachabilityIndex, build_reachability_index

Classification layer — compares the index against the segmentation policy:
  FindingType, Confidence, FindingCandidate, PolicyFinding
  classify_reachability_evidence, classify_reachability_index, aggregate_candidates
"""

from nssa.oae.analysis.reachability import (
    ReachabilityEvidence,
    ReachabilityIndex,
    build_reachability_index,
)
from nssa.oae.analysis.finding import (
    Confidence,
    FindingCandidate,
    FindingType,
    PolicyFinding,
    aggregate_candidates,
    classify_reachability_evidence,
    classify_reachability_index,
)

__all__ = [
    # Reachability
    "ReachabilityEvidence",
    "ReachabilityIndex",
    "build_reachability_index",
    # Classification
    "Confidence",
    "FindingCandidate",
    "FindingType",
    "PolicyFinding",
    "aggregate_candidates",
    "classify_reachability_evidence",
    "classify_reachability_index",
]
