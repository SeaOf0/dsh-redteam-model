---
name: attack-mapping-analysis
description: Map adversary TTPs, detections, and intelligence products to MITRE ATT&CK for gap analysis, coverage scoring, and detection engineering prioritization.
---

# MITRE ATT&CK Mapping and Analysis

## QUICK START

1. **Export your current detection rules** with MITRE technique tags from your SIEM.
2. **Build a coverage matrix** scoring each technique 0-100.
3. **Identify priority gaps** by cross-referencing with threat actor profiles.
4. **Create a Navigator layer** for visual gap analysis.
5. **Build a detection roadmap** prioritized by threat relevance and feasibility.

```
Detection Rules --> ATT&CK Mapping --> Score Matrix --> Gap Analysis --> Roadmap
```

## METHODOLOGY

### 1. ATT&CK Data Model

MITRE ATT&CK Enterprise (v15+, updated bi-annually) contains:
- **14 tactics**: Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact
- **200+ techniques** with 400+ sub-techniques
- **130+ groups** (threat actors) mapped to techniques
- **700+ software** entries mapped to techniques

### 2. Exporting Current Detection Rules

**Splunk ES**:
```spl
| rest /services/saved/searches
| search disabled=0 action.correlationsearch.enabled=1
| table title, search, action.notable.param.severity,
    action.correlationsearch.annotations
| eval mitre_techniques=mvfilter(match('action.correlationsearch.annotations', "mitre_attack"))
```

**Microsoft Sentinel**:
```kql
SecurityAlert
| summarize count() by AlertName, ProductName
| join kind=inner (
    resources
    | where type == "microsoft.securityinsights/alertrules"
    | extend tactics = properties.tactics
) on $left.AlertName == $right.name
```

**Elastic Security**:
```
GET kibana/api/detection_engine/rules/_find
```

### 3. Building the Coverage Matrix

#### ATT&CK Navigator Layer Format

```json
{
    "name": "SOC Detection Coverage - 2025",
    "versions": {
        "attack": "16",
        "navigator": "5.1",
        "layer": "4.5"
    },
    "domain": "enterprise-attack",
    "description": "Current detection coverage mapping",
    "techniques": [
        {
            "techniqueID": "T1110",
            "tactic": "credential-access",
            "color": "#00ff00",
            "comment": "2 active rules - Brute Force via EventCode 4625",
            "score": 75,
            "metadata": [
                {"name": "rule_count", "value": "2"},
                {"name": "data_sources", "value": "Windows Security Log, Linux Auth"},
                {"name": "last_validated", "value": "2025-01-15"}
            ]
        },
        {
            "techniqueID": "T1059.001",
            "tactic": "execution",
            "color": "#00ff00",
            "comment": "3 rules - PowerShell Script Block Logging",
            "score": 85
        },
        {
            "techniqueID": "T1055",
            "tactic": "defense-evasion",
            "color": "#ff0000",
            "comment": "NO DETECTION - Requires Sysmon EventCode 8/10",
            "score": 0
        }
    ],
    "gradient": {
        "colors": ["#ff0000", "#ffff00", "#00ff00"],
        "minValue": 0,
        "maxValue": 100
    }
}
```

#### Scoring Framework

| Score | Color | Meaning | Criteria |
|-------|-------|---------|----------|
| 0 | Red | No detection | No rule, missing data source |
| 25 | Orange | Minimal | Rule exists but unvalidated |
| 50 | Yellow | Partial | Rule works but limited coverage |
| 75 | Light Green | Good | Validated rule, sufficient data |
| 100 | Green | Excellent | Multiple validated rules, tested via simulation |

**Detailed scoring formula**:
```
Score = Data Source (0-25) + Rule Quality (0-25) + Validation (0-25) + Enrichment (0-25)

Data Source:   25 = all required sources onboarded, 15 = primary available, 5 = incomplete, 0 = unavailable
Rule Quality:  25 = CIM-compliant with tuned thresholds, 15 = functional but noisy, 5 = basic untuned, 0 = none
Validation:    25 = adversary simulation tested, 15 = synthetic data tested, 5 = logic reviewed, 0 = unvalidated
Enrichment:    25 = asset + identity + TI context, 15 = basic enrichment, 5 = none, 0 = N/A
```

### 4. Gap Prioritization Framework

```
Priority = Technique Prevalence (0-10) x Impact (0-10) x Feasibility (0-10)
```

**Technique Prevalence** (based on ATT&CK Top Techniques and industry threat landscape):
- 10: Observed in >50% of incidents (T1566 Phishing, T1059 Command Scripting)
- 7-9: Common in sector-specific incidents
- 4-6: Occasionally observed
- 1-3: Rare or theoretical

**Top techniques to prioritize (2025)**:

| Technique | ID | Prevalence | Typical gap reason |
|-----------|-----|-----------|-------------------|
| Command Scripting | T1059 | Extreme | Requires script block logging |
| Phishing | T1566 | Extreme | Email gateway integration |
| Valid Accounts | T1078 | High | Needs behavioral baselines |
| Process Injection | T1055 | High | Needs Sysmon or EDR |
| Lateral Movement (RDP/SMB) | T1021 | High | Network segment visibility |
| Scheduled Task/Job | T1053 | High | Event log collection |
| Data Encryption Impact | T1486 | High | File system monitoring |
| Ingress Tool Transfer | T1105 | Medium | Network traffic analysis |

### 5. Mapping Threat Actor TTPs to Your Coverage

```python
from mitreattack.stix20 import MitreAttackData

def map_actor_to_coverage(attack_data_file, actor_attack_id, coverage_scores):
    """Compare threat actor techniques against your detection coverage."""
    mitre = MitreAttackData(attack_data_file)
    actor = mitre.get_object_by_attack_id(actor_attack_id, "groups")
    techniques = mitre.get_techniques_used_by_group(actor)

    gaps = []
    covered = []
    for item in techniques:
        tech = item["object"]
        tid = tech["external_references"][0]["external_id"]
        score = coverage_scores.get(tid, 0)
        entry = {"technique_id": tid, "name": tech["name"], "your_score": score}
        if score < 50:
            gaps.append(entry)
        else:
            covered.append(entry)

    return {
        "actor": actor_attack_id,
        "total_techniques": len(techniques),
        "covered": covered,
        "gaps": gaps,
        "coverage_percentage": len(covered) / max(len(techniques), 1) * 100,
    }

# Example: How well do you detect APT28 techniques?
result = map_actor_to_coverage(
    "enterprise-attack.json",
    "G0007",  # APT28
    {"T1566": 75, "T1059": 60, "T1078": 0, "T1055": 0, "T1110": 50}
)
print(f"APT28 coverage: {result['coverage_percentage']:.0f}%")
print(f"Critical gaps: {[g['technique_id'] for g in result['gaps'] if g['your_score'] == 0]}")
```

### 6. Detection Roadmap Template

```
Q1: Close critical gaps (score 0, high prevalence)
  Weeks 1-2:  Enable missing data sources (Sysmon, PowerShell logging)
  Weeks 3-4:  Build and test rules for top 5 gap techniques
  Weeks 5-8:  Validate via adversary simulation (Atomic Red Team)
  Weeks 9-12: Tune and operationalize

Q2: Improve partial coverage (score 25-50)
  - Add enrichment to existing rules
  - Add secondary detection methods
  - Validate via purple team exercises

Q3: Strengthen good coverage (score 50-75)
  - Add behavioral analytics
  - Implement detection-as-code pipeline
  - Cross-technique correlation rules

Q4: Sustain excellence (score 75-100)
  - Continuous testing with BAS tools
  - Automated coverage regression testing
  - Red team validation
```

### 7. Mapping Intelligence Products to ATT&CK

When consuming threat intelligence reports, extract technique mappings:

```python
def extract_attack_refs(report_text, mitre_version="15"):
    """Extract MITRE ATT&CK technique IDs from a threat report."""
    import re
    # Match patterns like T1059, T1059.001, T1566.001
    pattern = r'\b(T\d{4}(?:\.\d{3})?)\b'
    matches = re.findall(pattern, report_text)

    # Deduplicate and sort
    techniques = sorted(set(matches))

    # Map to tactic categories
    tactic_map = {
        "T1": "Reconnaissance", "T2": "Resource Development",
        "T1": "Initial Access", "T1": "Execution",
        "T1": "Persistence", "T1": "Privilege Escalation",
    }

    results = []
    for tid in techniques:
        results.append({
            "technique_id": tid,
            "source": "report_extraction",
            "confidence": "medium",  # Manual review recommended
        })
    return results
```

## EXAMPLES

### Example 1: SOC Coverage Assessment

```
Input: 142 active SIEM detection rules exported
Step 1: Map each rule to ATT&CK technique IDs
Step 2: Build Navigator layer with scores
Step 3: Calculate coverage: 31 of 200+ techniques have at least one rule
Step 4: Coverage = ~15% (industry average per CardinalOps 2025: 21%)
Step 5: Cross-reference with APT29 profile (40 techniques)
Step 6: Gap: Only 12 of 40 APT29 techniques detected (30% actor coverage)
Result: Priority roadmap targeting APT29's top 10 uncovered techniques
```

### Example 2: Mapping a Threat Intelligence Report

```
Input: Mandiant APT41 report mentioning T1566.001, T1059.001, T1053.005, T1055, T1078
Step 1: Extract technique IDs from report
Step 2: Check each against coverage matrix
Step 3: T1566.001 = score 75 (covered), T1059.001 = 85 (good)
Step 4: T1053.005 = 0 (GAP), T1055 = 0 (GAP), T1078 = 25 (weak)
Step 5: Alert: APT41 uses 3 techniques with no/weak detection
Step 6: Create hunting hypotheses for the gap techniques
```

### Example 3: Quarterly Coverage Improvement Tracking

```python
def track_coverage_progress(before_scores, after_scores):
    """Compare coverage scores between two assessment periods."""
    improvements = []
    regressions = []
    new_coverage = []

    all_techniques = set(list(before_scores.keys()) + list(after_scores.keys()))

    for tid in all_techniques:
        before = before_scores.get(tid, 0)
        after = after_scores.get(tid, 0)
        delta = after - before

        if before == 0 and after > 0:
            new_coverage.append({"technique": tid, "new_score": after})
        elif delta > 0:
            improvements.append({"technique": tid, "delta": delta})
        elif delta < 0:
            regressions.append({"technique": tid, "delta": delta})

    return {
        "total_techniques": len(all_techniques),
        "newly_covered": len(new_coverage),
        "improved": len(improvements),
        "regressed": len(regressions),
        "avg_score_before": sum(before_scores.values()) / max(len(before_scores), 1),
        "avg_score_after": sum(after_scores.values()) / max(len(after_scores), 1),
    }
```

## VALIDATION

### Coverage Assessment Checklist

- [ ] All active detection rules exported with MITRE technique mappings
- [ ] Each technique scored using the 4-quadrant formula (0-100)
- [ ] Navigator layer generated and reviewed by detection engineering team
- [ ] Gap analysis cross-referenced with at least 3 relevant threat actor profiles
- [ ] Data source inventory confirmed: required log sources for each gap technique
- [ ] Priority scores calculated using prevalence x impact x feasibility
- [ ] Quarterly roadmap created with measurable milestones
- [ ] Validation plan includes Atomic Red Team or equivalent simulation
- [ ] Results communicated to CISO with risk-ranked gap summary

### Continuous Validation

| Activity | Frequency | Owner |
|----------|-----------|-------|
| Coverage matrix update | Monthly | Detection Engineering |
| Navigator layer refresh | Quarterly | Threat Intelligence |
| Adversary simulation test | Quarterly | Red Team / Detection Eng |
| Gap priority re-assessment | Semi-annually | TI + Detection Eng |
| Full coverage audit | Annually | Security Leadership |

## REFERENCES

- MITRE ATT&CK: https://attack.mitre.org/
- ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/
- mitreattack-python: https://github.com/mitre-attack/mitreattack-python/
- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team/
- MITRE ATT&CK Evaluations: https://attackevals.mitre.org/
- CardinalOps Detection Coverage Report: https://cardinalops.com/state-of-detection/
- MITRE D3FEND (countermeasures): https://d3fend.mitre.org/
