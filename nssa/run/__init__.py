"""nssa-run: an auditor-facing coordination layer over the NSSA pipeline.

Not to be confused with nssa.apu.orchestrator (a Host Mode Probe's fan-out to
its workloads); this package sits above it (Auditor -> Probes -> OAE). It has no
audit logic: it never classifies, correlates, hashes, signs, or reads artifact
content beyond a probe_id/policy_hash sanity check for resume (see executor.py).
Its only job is to reduce the manual steps between nssa-probe and nssa-evaluate,
which remain independently usable.
"""
