---
name: adversary-profile-tracking
description: Build and maintain structured threat actor profiles, track campaigns, map TTPs to ATT&CK, and assess organizational risk from specific adversary groups.
---

# Adversary Profile Tracking

## QUICK START

1. **Identify relevant threat actors** for your industry, geography, and technology stack.
2. **Gather profile data** from MITRE ATT&CK Groups, vendor reports, and OSINT.
3. **Map TTPs to ATT&CK** using structured technique lists per actor.
4. **Assess detection coverage** against each actor's technique set.
5. **Produce tailored profiles** for executive, SOC, and technical audiences.
6. **Track campaign updates** quarterly to keep profiles current.

```
Threat Landscape --> Actor Identification --> TTP Mapping --> Coverage Assessment --> Profile Distribution
```

## METHODOLOGY

### 1. Actor Identification and Prioritization

Cross-reference your organization's profile against known adversary targeting patterns.

**Selection criteria**:
- Industry match: Does the actor target your sector?
- Geography: Does the actor operate in your region?
- Technology overlap: Does the actor exploit technologies you use?
- Recent activity: Has the actor been active in the past 12 months?

**Source databases**:
- MITRE ATT&CK Groups: 130+ documented actors with TTP mappings
- CrowdStrike adversary naming: BEAR=Russia, PANDA=China, KITTEN=Iran, CHOLLIMA=DPRK, SPIDER=Crime
- Mandiant M-Trends: Annual statistics on actor targeting by sector
- CISA Known Exploited Vulnerabilities: Links CVEs to specific actors

**Prioritize** 5-10 actors most likely to target your organization.

### 2. Structured Profile Template

```python
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

@dataclass
class ThreatActorProfile:
    """Structured threat actor profile for intelligence production."""
    # Identity
    primary_name: str
    aliases: List[str] = field(default_factory=list)
    attack_group_id: Optional[str] = None  # e.g., G0016 for APT29
    vendor_names: dict = field(default_factory=dict)  # {"crowdstrike": "Cozy Bear", "mandiant": "APT29"}

    # Classification
    sponsor: Optional[str] = None  # Suspected nation-state sponsor
    motivation: List[str] = field(default_factory=list)  # espionage, financial, disruption, IP-theft
    actor_type: str = ""  # nation-state, criminal, hacktivist, insider

    # Targeting
    targeted_sectors: List[str] = field(default_factory=list)
    targeted_geographies: List[str] = field(default_factory=list)
    targeting_notes: str = ""

    # Capability
    sophistication: str = ""  # low, moderate, high, advanced
    custom_malware: List[str] = field(default_factory=list)
    zero_day_capability: bool = False
    supply_chain_capability: bool = False
    notable_tools: List[str] = field(default_factory=list)

    # Campaign history
    notable_campaigns: List[dict] = field(default_factory=list)
    first_observed: Optional[str] = None
    last_observed: Optional[str] = None

    # ATT&CK mapping
    techniques: List[dict] = field(default_factory=list)  # {"id": "T1566", "name": "Phishing", "tactics": ["initial-access"]}

    # Metadata
    profile_version: str = "1.0"
    last_updated: str = field(default_factory=lambda: datetime.now().isoformat())
    confidence_level: str = "medium"  # low, medium, high
    source_references: List[str] = field(default_factory=list)
```

### 3. Gathering Profile Data from Multiple Sources

```python
import requests

class ActorProfiler:
    def __init__(self, vt_key=None, otx_key=None, shodan_key=None):
        self.vt_key = vt_key
        self.otx_key = otx_key
        self.shodan_key = shodan_key

    def search_alienvault_otx(self, actor_name):
        """Search AlienVault OTX for threat actor pulses."""
        headers = {"X-OTX-API-KEY": self.otx_key}
        url = f"https://otx.alienvault.com/api/v1/search/pulses?q={actor_name}&limit=20"
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code == 200:
            pulses = resp.json().get("results", [])
            reports = []
            for pulse in pulses:
                reports.append({
                    "source": "AlienVault OTX",
                    "title": pulse.get("name", ""),
                    "created": pulse.get("created", ""),
                    "description": pulse.get("description", "")[:500],
                    "tags": pulse.get("tags", []),
                    "indicator_count": len(pulse.get("indicators", [])),
                })
            return reports
        return []

    def search_virustotal_collections(self, actor_name):
        """Search VirusTotal for samples tagged with actor name."""
        headers = {"x-apikey": self.vt_key}
        params = {"query": f"tag:{actor_name.lower().replace(' ', '-')}"}
        resp = requests.get(
            "https://www.virustotal.com/api/v3/intelligence/search",
            headers=headers, params=params, timeout=30
        )
        if resp.status_code == 200:
            return resp.json().get("data", [])
        return []

    def get_mitre_attack_techniques(self, attack_json_path, group_attack_id):
        """Extract ATT&CK techniques for a given group."""
        from mitreattack.stix20 import MitreAttackData
        mitre = MitreAttackData(attack_json_path)
        group = mitre.get_object_by_attack_id(group_attack_id, "groups")
        if not group:
            return []

        techniques = mitre.get_techniques_used_by_group(group)
        results = []
        for item in techniques:
            tech = item["object"]
            tid = tech["external_references"][0]["external_id"]
            tactics = [p["phase_name"] for p in tech.get("kill_chain_phases", [])]
            results.append({"id": tid, "name": tech["name"], "tactics": tactics})
        return results
```

### 4. Campaign Tracking

```python
@dataclass
class CampaignTracker:
    """Track observed campaigns linked to threat actors."""
    campaign_name: str
    linked_actors: List[str]
    first_seen: str
    last_seen: str
    target_sectors: List[str]
    techniques_used: List[str]  # ATT&CK technique IDs
    iocs: List[dict] = field(default_factory=list)
    malware_families: List[str] = field(default_factory=list)
    status: str = "active"  # active, dormant, concluded
    source_refs: List[str] = field(default_factory=list)

def link_campaign_to_actor(campaign, actor_profile):
    """Associate a campaign with an actor profile and update TTP mapping."""
    for tech_id in campaign.techniques_used:
        if tech_id not in [t["id"] for t in actor_profile.techniques]:
            actor_profile.techniques.append({
                "id": tech_id,
                "name": "From campaign: " + campaign.campaign_name,
                "tactics": [],
                "source": "campaign_observation",
            })
    if campaign.campaign_name not in [c.get("name") for c in actor_profile.notable_campaigns]:
        actor_profile.notable_campaigns.append({
            "name": campaign.campaign_name,
            "period": f"{campaign.first_seen} to {campaign.last_seen}",
            "status": campaign.status,
        })
    return actor_profile
```

### 5. Detection Coverage Assessment per Actor

```python
def assess_actor_coverage(actor_profile, coverage_scores):
    """Assess your detection posture against a specific threat actor."""
    total = len(actor_profile.techniques)
    if total == 0:
        return {"error": "No techniques mapped for this actor"}

    covered = 0
    partially_covered = 0
    gaps = []

    for tech in actor_profile.techniques:
        score = coverage_scores.get(tech["id"], 0)
        if score >= 75:
            covered += 1
        elif score >= 25:
            partially_covered += 1
        else:
            gaps.append({
                "technique_id": tech["id"],
                "technique_name": tech["name"],
                "tactics": tech.get("tactics", []),
                "your_score": score,
                "priority": "critical" if score == 0 else "high",
            })

    return {
        "actor": actor_profile.primary_name,
        "total_techniques": total,
        "well_covered": covered,
        "partial_coverage": partially_covered,
        "gaps": gaps,
        "coverage_percentage": round(covered / total * 100, 1),
        "risk_level": "critical" if covered / total < 0.3 else "high" if covered / total < 0.5 else "moderate",
    }
```

### 6. Profile Packaging for Different Audiences

**Executive Summary (1 page)**:
- Who is the actor and what is their motivation
- Recent activity relevant to our organization
- Top 3 risk actions we should prioritize
- Investment recommendation with ROI framing

**SOC Analyst Briefing (3-5 pages)**:
- Full TTP list with ATT&CK IDs and detection status
- IOC checklist with source attribution
- Hunting hypotheses derived from actor techniques
- Playbook triggers for actor-specific alert patterns

**Technical Appendix**:
- YARA rules for actor-associated malware
- Sigma detection rules for actor techniques
- STIX 2.1 JSON objects for TIP import
- Infrastructure fingerprints (SSL certs, JA3 hashes, naming patterns)

### 7. Profile Maintenance Cadence

| Activity | Frequency | Trigger |
|----------|-----------|---------|
| Full profile review | Quarterly | Scheduled |
| Campaign update | As observed | New campaign reporting |
| TTP refresh | Semi-annually | ATT&CK version update |
| Coverage reassessment | Monthly | Detection rule changes |
| Executive briefing refresh | Quarterly | Board reporting cycle |

## EXAMPLES

### Example 1: Profiling APT29 (Cozy Bear)

```
Step 1: Identify APT29 as relevant (targets: government, energy, technology)
Step 2: Gather from MITRE ATT&CK (G0016), Mandiant, CrowdStrike
Step 3: Map 40+ techniques across initial-access, execution, persistence, defense-evasion, credential-access, lateral-movement, collection, exfiltration
Step 4: Assess coverage: 12/40 techniques detected (30%)
Step 5: Critical gaps: T1055 (Process Injection), T1078 (Valid Accounts), T1534 (Internal Spearphishing)
Step 6: Produce profiles for CISO (risk brief) and SOC (TTP hunting guide)
```

### Example 2: Tracking a Ransomware Campaign

```python
# Track LockBit 3.0 campaign targeting healthcare
campaign = CampaignTracker(
    campaign_name="LockBit3-Healthcare-2025-Q1",
    linked_actors=["LockBit 3.0 Affiliates"],
    first_seen="2025-01-15",
    last_seen="2025-03-20",
    target_sectors=["healthcare"],
    techniques_used=["T1566", "T1059", "T1486", "T1490", "T1021"],
    malware_families=["LockBit 3.0"],
    status="dormant",
)

# Assess risk to organization
if "healthcare" in my_org.sectors:
    coverage = assess_actor_coverage(lockbit_profile, my_coverage_scores)
    if coverage["risk_level"] == "critical":
        alert_soc(f"LockBit gap: {len(coverage['gaps'])} undetected techniques")
```

### Example 3: OSINT Actor Profile Build

```python
profiler = ActorProfiler(vt_key="...", otx_key="...")

# Step 1: Gather from multiple OSINT sources
otx_reports = profiler.search_alienvault_otx("APT41")
vt_samples = profiler.search_virustotal_collections("APT41")
mitre_techs = profiler.get_mitre_attack_techniques("enterprise-attack.json", "G0096")

# Step 2: Build structured profile
profile = ThreatActorProfile(
    primary_name="APT41",
    aliases=["Double Dragon", "Barium", "Winnti"],
    attack_group_id="G0096",
    sponsor="China",
    motivation=["espionage", "financial"],
    actor_type="nation-state",
    targeted_sectors=["healthcare", "telecom", "technology", "gaming"],
    sophistication="advanced",
    zero_day_capability=True,
    supply_chain_capability=True,
    techniques=mitre_techs,
    profile_version="1.0",
)

# Step 3: Assess against our coverage
risk = assess_actor_coverage(profile, my_detection_scores)
print(f"APT41 risk: {risk['risk_level']} ({risk['coverage_percentage']}% covered)")
```

## VALIDATION

### Profile Quality Checklist

- [ ] Actor identified with ATT&CK Group ID (if available)
- [ ] Aliases documented from at least 2 vendor naming schemes
- [ ] Motivation and targeting supported by cited sources
- [ ] TTP list derived from MITRE ATT&CK (not just IOC lists)
- [ ] Campaign history includes dates and source references
- [ ] Detection coverage gap analysis completed
- [ ] Profile tailored to 3 audience levels (executive, SOC, technical)
- [ ] TLP classification applied before any external sharing
- [ ] Profile versioned and timestamped
- [ ] Quarterly review scheduled in calendar

### Attribution Confidence Framework

| Level | Criteria | How to express |
|-------|----------|----------------|
| High | Multiple independent sources, malware match, infrastructure overlap, TTP consistency | "We assess with high confidence that..." |
| Medium | Some source agreement, partial TTP match, limited infrastructure correlation | "We assess that..." |
| Low | Single source, possible shared tooling, ambiguous indicators | "There are indicators suggesting..." |

Never present attribution as certain. Always state confidence level and acknowledge alternative hypotheses.

## REFERENCES

- MITRE ATT&CK Groups: https://attack.mitre.org/groups/
- CrowdStrike Threat Actor Naming: https://www.crowdstrike.com/adversaries/
- Mandiant APT Groups: https://www.mandiant.com/resources/blog
- MITRE ATT&CK ICD (Intel): https://center-for-threat-informed-defense.github.io/intelligence-control-determination/
- Diamond Model of Intrusion Analysis: https://www.activeresponse.org/the-diamond-model/
- Analysis of Competing Hypotheses (ACH): https://www.cia.gov/resources/csi/studies-in-intelligence/
- STIX 2.1 Intrusion Set SDO: https://docs.oasis-open.org/cti/stix/v2.1/csprd02/stix-v2.1-csprd02.html
