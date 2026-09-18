# Implementation status after measurement review

## Added and exercised

- Format-matched YARA-X audits: one frozen PHP rule on 1,897 WordPress PHP files,
  and one frozen PowerShell rule on 114 Pester source files. Both returned zero
  matches; this is single-project, presumed-benign coverage, not ecosystem FP proof.
  Source positive controls pass for PowerShell but fail for the frozen PHP rule;
  that PHP rule is not operationally validated and was not silently retuned.
- Paired copilot selection evaluator, including conditional success denominators,
  rejected responses, abstentions, and a clearly labeled scripted residual-risk probe.
  External live-model evaluation exists as an explicit opt-in command but was not run.
- Corpus-review audit and guarded held-out split evaluation: sample identity,
  family/project/time leakage, review/adjudication metadata and minimum test-set size.
- Bounded stripped-Go ELF pclntab function recovery, malformed-data checks, and
  validation against a real locally compiled stripped Go 1.22 binary.
- README headline measurement table and a concrete static behavior-capability label
  policy; the original eight-fixture labels/scores remain frozen and provisional.

## Still missing

| Area | Remaining work / dependency |
|---|---|
| Scientific validation | Independently annotated malware corpus, real second reviewers, family/time-disjoint held-out samples, calibrated weights and external validation |
| FP coverage | More independent PHP/PowerShell projects; PE-targeting rules with licensed Windows/Wine goodware; broad PyPI/npm corpora where corresponding rules apply |
| Copilot evaluation | Repeated live-model manipulation tests and independently reviewed relevance labels; universal injection immunity is not a deliverable |
| Performance | IOC/string cost profiling and optimization, bounded mmap/chunked whole-pipeline analysis, CPU process pools, full persistent-store/lineage migration |
| Analysis depth | .NET IL/resource decryption, Rust demangling, older/other-container Go layouts, FLOSS-style decoding, real family extractors, tree-sitter deobfuscation |
| New lanes | Email and recursive delivery containers; PCAP/JA3/JA4; guest eBPF; comprehensive runtime evasion reporting; Frida Windows worker |
| Detection deployment | Real SIEM telemetry replay, Suricata engine/PCAP validation, cross-corpus FP/recall tests, deployment approval workflow |
| YARA generation validation | Correct the frozen PHP rule's raw-source false negative in a separately versioned rule/audit; require raw-source positive controls, not just synthetic anchors |
| Sandbox infrastructure | Licensed Windows guest and real CAPE validation; matching memory symbols; hardware PT/Xen/SMM environment |
| Operations | SSO/SCIM, HA storage/database orchestration, production backup/load/containment validation |

## GitHub About/topics

Desired values are recorded in `.github/repository-metadata.json`. Repository
metadata needs authenticated GitHub API/CLI access; SSH git credentials only
provide repository transport. At review time the About description/topics were
empty and no GitHub API token/CLI authentication was configured. Once authenticated:

```bash
gh repo edit theloav/sandworm \
  --description 'Evidence-driven malware analysis with disposable Linux sandboxes, detection-as-code, and reproducible evaluation.' \
  --add-topic malware-analysis,reverse-engineering,detection-engineering,yara,sigma,mitre-attack,prompt-injection,python
```

The metadata JSON is not automatically applied by pushing Git commits. Never put
GitHub credentials in the repository or share them in a chat transcript.
