# NSSA

**Network Segmentation Security Assessment**

NSSA is a tool for assessing whether deployed network infrastructure
enforces administrator-declared network segmentation policy.

It combines active connectivity probing with deterministic offline analysis
to identify connectivity that is inconsistent with the declared policy.

## How It Works

NSSA separates evidence collection from policy analysis.

```text
AuditConfiguration
        │
        ▼
   Active Probe Unit
        │
        │ signed evidence
        ▼
Offline Analysis Engine
        │
        ├── Evidence validation
        ├── Reachability analysis
        ├── Policy comparison
        └── Finding aggregation
                │
                ▼
        Deterministic findings
                │
                ▼
        Optional LLM enrichment
```

The policy is expressed through the **Segmentation Policy Model (SPM)**,
which defines Groups, workloads, connectivity Rules, and Mandatory Transit
Paths.

NSSA uses a closed-world model: connectivity is authorised only when it is
represented by the declared policy.

NSSA evaluates **enforcement of the supplied policy**. It does not assess
whether the policy itself is secure, optimal, or well designed.

## Assessment Modes

NSSA supports two probing modes:

- **Representative mode** — a Probe represents one or more Groups and
  provides group-level evidence.
- **Host mode** — a Probe corresponds to an individual workload, enabling
  host-level and intra-group validation.

Policy granularity and probing granularity are independent.

## Findings

The deterministic analysis identifies:

- Group isolation violations
- Host-scoped access violations
- Mandatory transit path bypasses
- Undeclared connectivity

Findings are derived from observed connectivity evidence and aggregated at
the destination/service level.

## Installation

NSSA requires Python and can be installed from the repository:

```bash
pip install .
```

This provides the following command-line tools:

```text
nssa-run
nssa-probe
nssa-evaluate
```

## Usage

An assessment is initiated with an Audit Configuration:

```bash
nssa-run <audit-configuration.json>
```

The Audit Configuration contains the declared policy and
deployment and information.

The configuration defines the SPM used by NSSA to determine the connectivity
that is authorised by the administrator. An example configuration is provided in `config_examples/audit_config.json`

## Validation

NSSA was evaluated using controlled GNS3 network testbeds in which
segmentation policy and network state were deliberately modified to assess
different enforcement scenarios.

## Limitations

NSSA's results depend on the completeness and correctness of the supplied
policy.

Active probing provides evidence from specific network vantage points and
does not provide omniscient knowledge of the network.

Representative Mode provides weaker host-level semantics than Host Mode.

UDP observations can be more ambiguous than TCP observations.

Policy-derived reachability is analytical and must not be interpreted as
observed network traffic.

The current evaluation does not establish enterprise-scale or near-linear
scalability.

External or Internet-based vantage points have not been validated as a
first-class assessment capability.

## Responsible Use

NSSA performs active network probing. It must only be used against networks
and systems for which the operator has appropriate authorization.

## Research

NSSA was developed as part of an MSc dissertation in Network Security.

The dissertation provides the detailed architecture, methodology,
experimental evaluation, assumptions, and limitations of the approach.

