---
name: misp-opencti-integration
description: Deploy and operate MISP and OpenCTI threat intelligence platforms for feed aggregation, indicator correlation, STIX-native enrichment, and SIEM integration.
---

# MISP and OpenCTI Integration

## QUICK START

1. **Deploy the platform** -- Docker Compose for MISP or OpenCTI.
2. **Enable core OSINT feeds** -- CIRCL OSINT, abuse.ch, Botvrij, AlienVault OTX.
3. **Configure enrichment connectors** -- VirusTotal, Shodan, AbuseIPDB for OpenCTI; enrichment modules for MISP.
4. **Set up SIEM integration** -- TAXII export or direct API push to Splunk/Sentinel.
5. **Define sharing groups** -- TLP classification and distribution scope.

```
OSINT Feeds --> MISP/OpenCTI --> Auto-Correlation --> Enrichment --> SIEM/SOAR/EDR
```

## METHODOLOGY

### 1. Platform Selection

| Criteria | MISP | OpenCTI |
|----------|------|---------|
| Data model | MISP JSON (STIX export available) | Native STIX 2.1 |
| Best for | ISAC/community sharing, government CERTs | Graph-based analysis, ATT&CK integration |
| Feed ecosystem | 80+ built-in OSINT feeds | Connector marketplace (100+ connectors) |
| API | PyMISP (Python) | pycti (Python), GraphQL API |
| UI | Event-centric, functional | Graph visualization, modern UI |
| Deployment | Docker, native LAMP | Docker Compose (ElasticSearch + Redis + RabbitMQ) |

### 2. MISP Deployment and Feed Configuration

```yaml
# docker-compose.yml for MISP
version: '3.8'
services:
  misp:
    image: coolacid/misp-docker:core-latest
    container_name: misp
    restart: unless-stopped
    ports:
      - "443:443"
    environment:
      - MYSQL_HOST=misp-db
      - MYSQL_DATABASE=misp
      - MYSQL_USER=misp
      - MYSQL_PASSWORD=CHANGE_ME_DB
      - MISP_ADMIN_EMAIL=admin@org.com
      - MISP_ADMIN_PASSPHRASE=CHANGE_ME_ADMIN
      - MISP_BASEURL=https://misp.org.com
    volumes:
      - misp-data:/var/www/MISP/app/files
    depends_on:
      - misp-db
      - misp-redis

  misp-db:
    image: mysql:8.0
    environment:
      - MYSQL_DATABASE=misp
      - MYSQL_USER=misp
      - MYSQL_PASSWORD=CHANGE_ME_DB
      - MYSQL_ROOT_PASSWORD=CHANGE_ME_ROOT
    volumes:
      - misp-db-data:/var/lib/mysql

  misp-redis:
    image: redis:7

volumes:
  misp-data:
  misp-db-data:
```

#### Enable Default Feeds via PyMISP

```python
from pymisp import PyMISP

misp = PyMISP("https://misp.org.com", "YOUR_API_KEY", ssl=False)

RECOMMENDED_FEEDS = [
    "CIRCL OSINT Feed",
    "Botvrij.eu - Indicators of Compromise",
    "abuse.ch URLhaus Host file",
    "abuse.ch Feodo Tracker",
    "abuse.ch SSL Blacklist",
    "malwaredomainlist",
    "CyberCure - IP Feed",
]

feeds = misp.feeds()
for feed in feeds:
    feed_data = feed.get("Feed", {})
    if feed_data.get("name") in RECOMMENDED_FEEDS and not feed_data.get("enabled"):
        misp.enable_feed(feed_data["id"])
        misp.enable_feed_cache(feed_data["id"])
        print(f"Enabled: {feed_data['name']}")

# Add custom feed
misp.add_feed({
    "name": "Abuse.ch MalwareBazaar Recent",
    "provider": "abuse.ch",
    "url": "https://bazaar.abuse.ch/export/csv/recent/",
    "source_format": "csv",
    "input_source": "network",
    "enabled": True,
    "caching_enabled": True,
})
```

#### Search and Correlate in MISP

```python
from datetime import datetime, timedelta

def search_indicators(misp, value=None, ioc_type=None, tags=None, days=30):
    date_from = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    params = {"date_from": date_from, "published": True, "enforceWarninglist": True}
    if value:
        params["value"] = value
    if ioc_type:
        params["type_attribute"] = [ioc_type]
    if tags:
        params["tags"] = tags
    return misp.search(**params)

# Example: find all IP indicators tagged APT28 in last 90 days
results = search_indicators(misp, ioc_type="ip-dst", tags=["APT28"], days=90)
for event in results:
    attrs = event.get("Event", {}).get("Attribute", [])
    for attr in attrs:
        print(f"  {attr['type']}: {attr['value']} (event {event['Event']['id']})")
```

### 3. OpenCTI Deployment and Enrichment Connectors

```yaml
# docker-compose.yml for OpenCTI
version: '3'
services:
  opencti:
    image: opencti/platform:6.4.4
    environment:
      - APP__PORT=8080
      - APP__ADMIN__EMAIL=admin@opencti.io
      - APP__ADMIN__PASSWORD=ChangeMeNow
      - APP__ADMIN__TOKEN=your-admin-token-uuid
      - ELASTICSEARCH__URL=http://elasticsearch:9200
      - MINIO__ENDPOINT=minio
      - RABBITMQ__HOSTNAME=rabbitmq
    ports:
      - "8080:8080"
    depends_on:
      - elasticsearch
      - minio
      - rabbitmq
      - redis

  connector-virustotal:
    image: opencti/connector-virustotal:6.4.4
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=your-admin-token-uuid
      - CONNECTOR_ID=connector-virustotal-id
      - CONNECTOR_NAME=VirusTotal
      - CONNECTOR_SCOPE=StixFile,Artifact,IPv4-Addr,Domain-Name,Url
      - CONNECTOR_AUTO=true
      - VIRUSTOTAL_TOKEN=your-vt-api-key
      - VIRUSTOTAL_MAX_TLP=TLP:AMBER

  connector-shodan:
    image: opencti/connector-shodan:6.4.4
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=your-admin-token-uuid
      - CONNECTOR_ID=connector-shodan-id
      - CONNECTOR_NAME=Shodan
      - CONNECTOR_SCOPE=IPv4-Addr
      - CONNECTOR_AUTO=true
      - SHODAN_TOKEN=your-shodan-api-key
      - SHODAN_MAX_TLP=TLP:AMBER
```

#### Custom OpenCTI Enrichment Connector

```python
import os
from pycti import OpenCTIConnectorHelper
from stix2 import Bundle, Note

class GreyNoiseEnrichmentConnector:
    def __init__(self):
        config = {
            "opencti": {
                "url": os.environ.get("OPENCTI_URL"),
                "token": os.environ.get("OPENCTI_TOKEN"),
            },
            "connector": {
                "id": os.environ.get("CONNECTOR_ID"),
                "name": "GreyNoise",
                "scope": "IPv4-Addr",
                "auto": True,
                "type": "INTERNAL_ENRICHMENT",
            },
        }
        self.helper = OpenCTIConnectorHelper(config)
        self.helper.listen(self._process_message)

    def _process_message(self, data):
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)
        if not observable or observable["entity_type"] != "IPv4-Addr":
            return "Skipped: not an IPv4 address"

        ip = observable.get("value", "")
        import requests
        resp = requests.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            headers={"key": os.environ.get("GREYNOISE_API_KEY")},
            timeout=30,
        )
        if resp.status_code != 200:
            return f"GreyNoise lookup failed: {resp.status_code}"

        gn = resp.json()
        note = Note(
            content=f"## GreyNoise Enrichment\n- Classification: {gn.get('classification')}\n"
                    f"- Noise: {gn.get('noise')}\n- RIOT: {gn.get('riot')}\n"
                    f"- Name: {gn.get('name', 'N/A')}\n- Link: {gn.get('link', 'N/A')}",
            object_refs=[entity_id],
            abstract=f"GreyNoise: {gn.get('classification', 'unknown')}",
            allow_custom=True,
        )
        bundle = Bundle(objects=[note], allow_custom=True)
        self.helper.send_stix2_bundle(bundle.serialize())
        return f"Enriched {ip}: GreyNoise classification={gn.get('classification')}"
```

### 4. MISP-to-SIEM Integration

```python
def export_misp_to_splunk(misp, splunk_api, tag_filter=None, days=7):
    """Export MISP IOCs to Splunk ES threat intel framework."""
    events = misp.search(
        date_from=(datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d"),
        tags=tag_filter,
        published=True,
    )
    iocs = []
    for event in events:
        for attr in event.get("Event", {}).get("Attribute", []):
            if attr["type"] in ("ip-dst", "domain", "hostname", "url", "sha256", "md5"):
                iocs.append({
                    "time": event["Event"]["date"],
                    "ioc": attr["value"],
                    "type": attr["type"],
                    "event_id": event["Event"]["id"],
                    "threat_level": event["Event"].get("threat_level_id", "3"),
                    "tlp": next(
                        (t["name"] for t in event["Event"].get("Tag", [])
                         if t["name"].startswith("tlp:")), "tlp:white"
                    ),
                })
    splunk_api.upload_threat_intel(iocs)
    print(f"Pushed {len(iocs)} IOCs to Splunk ES")
```

### 5. Threat Landscape Analysis with MISP

```python
def analyze_landscape(misp, days=90):
    """Generate a threat landscape summary from MISP data."""
    events = misp.search(
        date_from=(datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d"),
        published=True,
    )

    attr_types = {}
    threat_actors = {}
    mitre_techniques = {}
    threat_levels = {"1": 0, "2": 0, "3": 0, "4": 0}

    for event in events:
        ev = event.get("Event", {})
        threat_levels[ev.get("threat_level_id", "4")] += 1

        for attr in ev.get("Attribute", []):
            t = attr["type"]
            attr_types[t] = attr_types.get(t, 0) + 1

        for tag in ev.get("Tag", []):
            name = tag["name"]
            if name.startswith("misp-galaxy:"):
                threat_actors[name] = threat_actors.get(name, 0) + 1
            if name.startswith("mitre-attack:"):
                mitre_techniques[name] = mitre_techniques.get(name, 0) + 1

    return {
        "period_days": days,
        "total_events": len(events),
        "threat_level_distribution": threat_levels,
        "top_attribute_types": sorted(attr_types.items(), key=lambda x: -x[1])[:10],
        "top_threat_actors": sorted(threat_actors.items(), key=lambda x: -x[1])[:10],
        "top_mitre_techniques": sorted(mitre_techniques.items(), key=lambda x: -x[1])[:10],
    }
```

## EXAMPLES

### Example 1: Deploying MISP and Ingesting First Feed

```
Step 1: docker compose up -d   (MISP + MySQL + Redis)
Step 2: pip install pymisp
Step 3: misp = PyMISP("https://misp.local", "API_KEY")
Step 4: Enable CIRCL OSINT Feed, fetch 24h of data
Step 5: Search for recent events tagged "tlp:white"
Step 6: Export IOCs to Splunk watchlist via API
Result: 1,200 IOCs ingested, 340 correlated, 120 pushed to SIEM
```

### Example 2: OpenCTI Custom Enrichment Pipeline

```
Step 1: docker compose up -d   (OpenCTI + ElasticSearch + Redis + RabbitMQ)
Step 2: Deploy VT, Shodan, AbuseIPDB connectors (auto=true)
Step 3: Ingest STIX bundle from ISAC partner
Step 4: Connectors auto-enrich new observables
Step 5: Query graph: "show all indicators linked to APT29 with confidence > 70"
Step 6: Export high-confidence IOCs via TAXII to SIEM
```

### Example 3: Cross-Platform Correlation

```python
# Query MISP for a domain, then cross-reference in OpenCTI
domain = "evil-c2.example.com"

# MISP search
misp_events = misp.search(value=domain, published=True)
misp_correlations = len(misp_events)

# OpenCTI query via GraphQL
from pycti import OpenCTIApiClient
opencti = OpenCTIApiClient("https://opencti.local", "API_KEY")
stix_observable = opencti.stix_cyber_observable.read(
    filters=[{"key": "value", "values": [domain]}]
)

# Combine results
combined = {
    "domain": domain,
    "misp_events": misp_correlations,
    "opencti_relationships": len(stix_observable.get("objectRefs", [])) if stix_observable else 0,
    "combined_confidence": "HIGH" if misp_correlations > 3 else "MEDIUM",
}
```

## VALIDATION

### Deployment Checklist

- [ ] Docker containers healthy (MISP/OpenCTI + databases + message queues)
- [ ] Admin account created with strong password, default credentials removed
- [ ] At least 3 OSINT feeds enabled and first fetch completed
- [ ] Enrichment connectors deployed with valid API keys
- [ ] SSL/TLS configured for all API endpoints
- [ ] TLP classification enforced on all shared events
- [ ] SIEM integration tested: IOCs appear in watchlist within 5 minutes
- [ ] Sharing groups configured to prevent TLP:RED data leakage
- [ ] Backup schedule configured (daily DB dump + file backup)
- [ ] Rate limiting configured for outbound API calls to external services

### Operational Health Metrics

| Metric | Target | Check frequency |
|--------|--------|-----------------|
| Feed sync success rate | > 98% | Daily |
| Enrichment connector uptime | > 99% | Hourly |
| New IOC ingestion rate | Baseline trend | Weekly |
| False positive rate (analyst feedback) | < 15% | Monthly |
| Storage growth rate | < 10% week-over-week | Weekly |
| API response time (p95) | < 2s | Continuous |

## REFERENCES

- MISP Project: https://www.misp-project.org/
- OpenCTI Platform: https://www.opencti.io/
- PyMISP Documentation: https://pymisp.readthedocs.io/
- OpenCTI Connectors: https://github.com/OpenCTI-Platform/connectors
- STIX 2.1 Specification: https://docs.oasis-open.org/cti/stix/v2.1/
- NIST SP 800-150: Guide to Cyber Threat Information Sharing
- TLP Version 2.0: https://www.first.org/tlp/
