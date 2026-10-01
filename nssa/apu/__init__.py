"""APU: Active Probing Unit.

Deployed inside each network segment to generate and execute targeted probes and
produce signed result artifacts for OAE analysis.

  Planning  - derive test cases from the SPM (ECM, TCM, lateral discovery, safety-net)
  Execution - issue probes, record states (OPEN / CLOSED / FILTERED)
  Signing   - attach Ed25519 signature and policy hash

No policy reasoning or classification happens here; that is the OAE's role.

Entry point: nssa.apu.engine.APUEngine
"""
