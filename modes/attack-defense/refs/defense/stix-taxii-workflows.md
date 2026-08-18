---
name: stix-taxii-workflows
description: Produce and consume STIX 2.1 threat intelligence objects over TAXII 2.1 feeds, with validation, normalization, and multi-platform routing.
---

# STIX/TAXII Workflows

## QUICK START

1. **Discover** the TAXII server collections available to you.
2. **Poll** new objects added since your last fetch using `added_after` timestamps.
3. **Validate** every STIX object against the OASIS STIX 2.1 specification.
4. **Parse and normalize** -- extract indicators, relationships, threat actors, campaigns.
5. **Route** objects to the right consumer: SIEM, TIP, EDR, firewall.
6. **Produce** your own STIX bundles for partner sharing via TAXII push.

```
TAXII Discovery --> Poll Collection --> Validate Bundle --> Parse Objects --> Route to Consumers
```

## METHODOLOGY

### 1. STIX 2.1 Object Model

STIX 2.1 objects fall into four categories:

| Category | Objects | Purpose |
|----------|---------|---------|
| **SDO** (Domain Objects) | Indicator, Malware, Threat-Actor, Campaign, Attack-Pattern, Tool, Infrastructure, Vulnerability, Identity, Location, Note, Report | Describe threat concepts |
| **SCO** (Cyber-Observable Objects) | IPv4-Addr, Domain-Name, URL, File, Email-Addr, Process, Network-Traffic, Artifact | Describe observed data |
| **SRO** (Relationship Objects) | Relationship, Sighting | Link objects together |
| **Meta Objects** | Marking-Definition (TLP), Language-Content, Extension-Definition | Provide context |

**Key relationships**:
- `Indicator --> indicates --> Malware`
- `Threat-Actor --> uses --> Malware`
- `Threat-Actor --> uses --> Attack-Pattern`
- `Campaign --> uses --> Attack-Pattern`
- `Infrastructure --> hosts --> Malware`

### 2. TAXII 2.1 Architecture

TAXII defines three RESTful service types:
- **Discovery**: Returns server metadata and available API roots.
- **API Root**: Contains collections; the primary interaction point.
- **Collection**: A logical grouping of STIX objects, accessed via GET (read) or POST (write).

```
Server --> API Roots --> Collections --> Objects (STIX Bundles)
```

### 3. Consuming TAXII Feeds

```python
from taxii2client.v21 import Server, Collection, as_pages
from datetime import datetime, timedelta, timezone
import json

class TAXIIConsumer:
    """Poll TAXII 2.1 collections and extract actionable IOCs."""

    def __init__(self, server_url, user="", password=""):
        self.server = Server(server_url, user=user, password=password)
        self.last_poll = {}

    def discover_collections(self):
        """List all available API roots and collections."""
        collections = []
        for api_root in self.server.api_roots:
            for collection in api_root.collections:
                collections.append({
                    "api_root": api_root.title,
                    "collection_id": collection.id,
                    "title": collection.title,
                    "can_read": collection.can_read,
                    "can_write": collection.can_write,
                })
        return collections

    def poll_collection(self, collection_url, added_after=None, user="", password=""):
        """Poll a specific collection for new STIX objects."""
        collection = Collection(collection_url, user=user, password=password)

        if added_after is None:
            added_after = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()

        all_objects = []
        for envelope in as_pages(
            collection.get_objects,
            per_request=100,
            added_after=added_after,
        ):
            objects = envelope.get("objects", [])
            all_objects.extend(objects)

        self.last_poll[collection_url] = datetime.now(timezone.utc).isoformat()
        return all_objects

    def extract_indicators(self, objects):
        """Extract actionable indicators from STIX objects."""
        indicators = []
        for obj in objects:
            if obj.get("type") == "indicator":
                indicators.append({
                    "id": obj.get("id"),
                    "name": obj.get("name", ""),
                    "pattern": obj.get("pattern", ""),
                    "pattern_type": obj.get("pattern_type", ""),
                    "valid_from": obj.get("valid_from", ""),
                    "valid_until": obj.get("valid_until", ""),
                    "indicator_types": obj.get("indicator_types", []),
                    "confidence": obj.get("confidence", 0),
                    "tlp": self._extract_tlp(obj),
                })
        return indicators

    def _extract_tlp(self, obj):
        """Extract TLP marking from STIX object."""
        for marking in obj.get("object_marking_refs", []):
            if "tlp-" in marking.lower():
                return marking.split("/")[-1]
        return "TLP:WHITE"

# Usage: Poll MITRE ATT&CK TAXII
consumer = TAXIIConsumer("https://cti-taxii.mitre.org/taxii2/")
collections = consumer.discover_collections()

ENTERPRISE_ATTACK = "95ecc380-afe9-11e4-9b6c-751b66dd541e"
objects = consumer.poll_collection(
    f"https://cti-taxii.mitre.org/stix/collections/{ENTERPRISE_ATTACK}/"
)
indicators = consumer.extract_indicators(objects)
```

### 4. Validating STIX 2.1 Objects

```python
import stix2

REQUIRED_SDO_FIELDS = ["id", "type", "spec_version", "created", "modified"]
REQUIRED_INDICATOR_FIELDS = REQUIRED_SDO_FIELDS + ["pattern", "pattern_type", "valid_from"]

def validate_stix_bundle(bundle_dict):
    """Validate a STIX bundle against the 2.1 specification."""
    errors = []

    try:
        bundle = stix2.parse(bundle_dict, allow_custom=True)
    except Exception as e:
        return [f"Bundle parse error: {e}"]

    for obj in bundle.objects:
        obj_type = obj.get("type", getattr(obj, "type", "unknown"))

        # Validate required fields
        if obj_type == "indicator":
            for field in REQUIRED_INDICATOR_FIELDS:
                if not hasattr(obj, field) and field not in obj:
                    errors.append(f"Indicator {obj.get('id', '?')} missing field: {field}")

            # Validate confidence range
            confidence = obj.get("confidence", getattr(obj, "confidence", None))
            if confidence is not None and not (0 <= confidence <= 100):
                errors.append(f"Indicator {obj.get('id', '?')} confidence out of range: {confidence}")

            # Validate pattern syntax
            pattern = obj.get("pattern", getattr(obj, "pattern", ""))
            pattern_type = obj.get("pattern_type", getattr(obj, "pattern_type", ""))
            if pattern_type == "stix" and not pattern.startswith("["):
                errors.append(f"Indicator {obj.get('id', '?')} invalid STIX pattern syntax")

        elif obj_type == "relationship":
            for field in ["source_ref", "target_ref", "relationship_type"]:
                if not hasattr(obj, field) and field not in obj:
                    errors.append(f"Relationship missing field: {field}")

    return errors

def validate_before_import(bundle_dict):
    """Gate: only import if validation passes."""
    errors = validate_stix_bundle(bundle_dict)
    if errors:
        print(f"VALIDATION FAILED: {len(errors)} errors")
        for err in errors[:10]:
            print(f"  - {err}")
        return False
    return True
```

### 5. Producing STIX 2.1 Bundles

```python
from stix2 import (
    Bundle, Indicator, Malware, ThreatActor, Campaign,
    Relationship, AttackPattern, Identity, MarkingDefinition
)
import uuid
from datetime import datetime

def create_threat_intelligence_bundle():
    """Build a STIX 2.1 bundle for sharing with partners."""
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
    org = Identity(name="ACERT", identity_class="organization")

    indicator = Indicator(
        id=f"indicator--{uuid.uuid4()}",
        created=now,
        modified=now,
        name="Suspicious C2 Domain",
        description="Domain observed in APT28 phishing campaign targeting energy sector",
        pattern="[domain-name:value = 'c2.evil-example.com']",
        pattern_type="stix",
        pattern_version="2.1",
        valid_from=now,
        indicator_types=["malicious-activity"],
        confidence=85,
        object_marking_refs=[stix2.TLP_AMBER],
        created_by_ref=org.id,
    )

    malware = Malware(
        id=f"malware--{uuid.uuid4()}",
        created=now,
        modified=now,
        name="SUNBURST",
        malware_types=["trojan", "backdoor"],
        is_family=False,
        created_by_ref=org.id,
    )

    relationship = Relationship(
        id=f"relationship--{uuid.uuid4()}",
        created=now,
        modified=now,
        relationship_type="indicates",
        source_ref=indicator.id,
        target_ref=malware.id,
        created_by_ref=org.id,
    )

    bundle = Bundle(objects=[org, indicator, malware, relationship], allow_custom=True)
    return bundle

# Export for TAXII push or file sharing
bundle = create_threat_intelligence_bundle()
print(bundle.serialize(pretty=True))
```

### 6. Routing Objects to Consumer Platforms

```python
def route_stix_objects(objects, siem_api, tip_api, edr_api):
    """Route STIX objects to appropriate consumer systems."""
    routing = {"siem": 0, "tip": 0, "edr": 0, "skipped": 0}

    for obj in objects:
        obj_type = obj.get("type", getattr(obj, "type", ""))

        if obj_type == "indicator":
            # Indicators go to SIEM watchlists and EDR threat intel
            pattern = obj.get("pattern", "")
            siem_api.add_indicator(obj["id"], pattern, obj.get("confidence", 50))
            edr_api.add_ioc(pattern)
            routing["siem"] += 1
            routing["edr"] += 1

        elif obj_type in ("threat-actor", "intrusion-set", "campaign"):
            # Threat context goes to TIP for analyst review
            tip_api.upsert_entity(obj)
            routing["tip"] += 1

        elif obj_type == "malware":
            # Malware families go to both TIP and EDR
            tip_api.upsert_entity(obj)
            edr_api.add_malware_family(obj.get("name", ""))
            routing["tip"] += 1
            routing["edr"] += 1

        elif obj_type == "course-of-action":
            # Mitigation guidance goes to security team wiki
            routing["skipped"] += 1

        else:
            routing["skipped"] += 1

    return routing
```

### 7. TLP Enforcement in Pipeline

```python
TLP_HIERARCHY = {
    "TLP:RED": 4,
    "TLP:AMBER+STRICT": 3.5,
    "TLP:AMBER": 3,
    "TLP:GREEN": 2,
    "TLP:CLEAR": 1,
    "TLP:WHITE": 1,
}

MAX_TLP_FOR_PARTNER = "TLP:GREEN"

def enforce_tlp_before_share(objects, max_tlp=MAX_TLP_FOR_PARTNER):
    """Filter out objects above the allowed TLP level."""
    max_level = TLP_HIERARCHY.get(max_tlp, 1)
    allowed = []
    blocked = 0

    for obj in objects:
        markings = obj.get("object_marking_refs", [])
        obj_tlp = "TLP:CLEAR"  # default if no marking
        for m in markings:
            for tlp_name in TLP_HIERARCHY:
                if tlp_name.lower().replace(":", "").replace("+", "") in m.lower():
                    obj_tlp = tlp_name
                    break

        if TLP_HIERARCHY.get(obj_tlp, 1) <= max_level:
            allowed.append(obj)
        else:
            blocked += 1

    print(f"TLP filter: {len(allowed)} allowed, {blocked} blocked (max: {max_tlp})")
    return allowed
```

## EXAMPLES

### Example 1: Polling CISA AIS Feed Daily

```python
# Daily automated poll of CISA Automated Indicator Sharing
consumer = TAXIIConsumer(
    "https://ais.cisa.gov/taxii2/",
    user="org_cert_user",
    password="cert_api_key"
)

yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
objects = consumer.poll_collection(
    "https://ais.cisa.gov/api1/collections/financial-sector/",
    added_after=yesterday
)

errors = validate_stix_bundle({"type": "bundle", "id": "bundle--temp", "objects": objects})
if not errors:
    indicators = consumer.extract_indicators(objects)
    route_stix_objects(objects, siem, tip, edr)
    print(f"Processed {len(indicators)} indicators from CISA AIS")
```

### Example 2: Sharing STIX Bundle with ISAC Partner

```python
# Create and push a STIX bundle to partner TAXII server
bundle = create_threat_intelligence_bundle()

# Filter to TLP:GREEN before sharing
objects = json.loads(bundle.serialize())["objects"]
filtered = enforce_tlp_before_share(objects, max_tlp="TLP:GREEN")

# Push to partner TAXII collection
partner_collection = Collection(
    "https://partner-taxii.isac.org/api1/collections/shared/",
    user="our_org_user",
    password="our_api_key"
)
partner_collection.add_objects({"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": filtered})
```

### Example 3: Building a Local TAXII Server

```python
# Using medallion library for a local TAXII 2.1 server
# pip install medallion

from medallion import application, register_blueprints

config = {
    "backend": {
        "module": "medallion.backends.memory_backend",
        "module_config": {"filename": "local_taxii_data.json"},
    },
    "users": {
        "admin": {"password": "admin_password_hash"},
        "partner_readonly": {"password": "partner_password_hash"},
    },
}

app = application.build_app(config)
register_blueprints(app)
app.run(host="0.0.0.0", port=9000)
# Now partners can poll https://our-server:9000/taxii2/
```

## VALIDATION

### Checklist for STIX/TAXII Pipeline

- [ ] TAXII discovery endpoint returns correct API roots and collections
- [ ] Polling uses `added_after` timestamp to avoid re-processing old data
- [ ] All ingested STIX objects pass `validate_stix_bundle()` before import
- [ ] Confidence values are in range 0-100
- [ ] TLP markings enforced before outbound sharing
- [ ] Indicator patterns use valid STIX pattern syntax (`[type:property = 'value']`)
- [ ] Relationships have valid `source_ref`, `target_ref`, and `relationship_type`
- [ ] Custom objects use `x-` prefix and `allow_custom=True`
- [ ] Poll interval respects server rate limits
- [ ] Last-poll timestamp persisted across restarts
- [ ] Error handling logs but does not halt pipeline on individual object failures

### Integration Test

```python
def test_round_trip():
    """Create a bundle, serialize, parse, validate, and extract."""
    bundle = create_threat_intelligence_bundle()
    raw = json.loads(bundle.serialize())

    errors = validate_stix_bundle(raw)
    assert not errors, f"Validation failed: {errors}"

    consumer = TAXIIConsumer.__new__(TAXIIConsumer)
    indicators = consumer.extract_indicators(raw["objects"])
    assert len(indicators) >= 1, "No indicators extracted"
    assert indicators[0]["confidence"] > 0, "Confidence not preserved"
    print("Round-trip test passed")
```

## REFERENCES

- OASIS STIX 2.1 Specification: https://docs.oasis-open.org/cti/stix/v2.1/
- OASIS TAXII 2.1 Specification: https://docs.oasis-open.org/cti/taxii/v2.1/
- stix2 Python Library: https://stix2.readthedocs.io/
- taxii2-client: https://github.com/oasis-open/cti-python-taxii-client
- MITRE ATT&CK TAXII: https://cti-taxii.mitre.org/
- medallion TAXII Server: https://github.com/oasis-open/cti-taxii-server
- NIST SP 800-150: Guide to Cyber Threat Information Sharing
