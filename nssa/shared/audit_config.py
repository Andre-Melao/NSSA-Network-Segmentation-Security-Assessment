"""AuditConfiguration: the single-artifact container for an audit run.

Not a merged domain model: SegmentationPolicy, Deployment and Authentication
stay independent; this only bundles references so the auditor manages one file.
Only audit_config_parser.py constructs one, and nothing after
extract_runtime_configuration() sees the whole thing.

RuntimeConfiguration is the subset an APU invocation may receive. It has no
field for Authentication, so credentials cannot reach an APU by construction.
"""

from __future__ import annotations

from dataclasses import dataclass

from nssa.shared.authentication import Authentication
from nssa.shared.deployment import Deployment
from nssa.shared.policy import SegmentationPolicy


@dataclass(slots=True)
class AuditConfiguration:
    """Everything one audit run's configuration file declares.

    policy         - the audited network's intended segmentation (SPM).
    deployment     - how the audit executes (Probes); never absent, an empty
                     Deployment() when no Probes are declared. Execution mode
                     is per Probe (see ProbeConfig.execution).
    authentication - how the auditor's machine authenticates to external
                     systems; None when no 'authentication' section is declared.
                     Auditor-machine-only (see extract_runtime_configuration()).
    """

    policy: SegmentationPolicy
    deployment: Deployment
    authentication: Authentication | None = None


@dataclass(frozen=True, slots=True)
class RuntimeConfiguration:
    """What an APU invocation (local or remote) may receive.

    Has no 'authentication' field, so nothing downstream can read, log, hash or
    forward credentials; a type property, not a runtime check.
    """

    policy: SegmentationPolicy
    deployment: Deployment


def extract_runtime_configuration(config: AuditConfiguration) -> RuntimeConfiguration:
    """Reduce an AuditConfiguration to exactly what an APU may receive.

    The one boundary between the auditor's configuration and a probing process,
    called once after parsing in nssa.apu.cli and nssa.oae.cli. Everything after
    is built from the returned RuntimeConfiguration alone.
    """
    return RuntimeConfiguration(policy=config.policy, deployment=config.deployment)
