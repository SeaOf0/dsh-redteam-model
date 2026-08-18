---
name: bloodhound-ad
description: >-
  BloodHound analysis for Active Directory. Covers SharpHound data collection, BloodHound CE deployment,
  Cypher queries, attack path analysis, graph-based AD recon, and exploitation planning.
---

# BloodHound AD Analysis

> **AI LOAD INSTRUCTION**: Use when performing BloodHound-based Active Directory reconnaissance, attack path discovery, and exploitation planning.

## Performing Active Directory BloodHound Analysis

### SharpHound Data Collection

```powershell
# Standard collection
SharpHound.exe -c All --ldapusername user --ldappassword pass

# DC-only (fastest — no session enumeration)
SharpHound.exe -c DCOnly

# Session data (run periodically)
SharpHound.exe -c Session

# From Linux
bloodhound-python -d domain.local -u user -p pass -dc DC01 -ns DC_IP -c all
```

### BloodHound CE Deployment

```bash
# Docker deployment
docker compose up -d

# Access UI at http://localhost:8080
# Default credentials: admin / password (change immediately)

# Import data
# Upload ZIP from SharpHound via UI or API
```

### Key Cypher Queries

```cypher
// Find shortest path to Domain Admins
MATCH p=shortestPath((u:User {owned:true})-[:AdminTo|HasSession|GenericAll|GenericWrite|WriteDacl|WriteOwner|ForceChangePassword*1..]->g:Group))
WHERE g.objectid ENDS WITH '-512' RETURN p

// Find all users with DCSync rights
MATCH p=(u:User)-[:DCSync|GenericAll|WriteDacl|WriteOwner]->(d:Domain) RETURN p

// Find computers with unconstrained delegation
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c

// Find AS-REP roastable users
MATCH (u:User {dontreqpreauth:true}) RETURN u

// Find Kerberoastable users
MATCH (u:User {hasspn:true}) RETURN u

// Find paths from Domain Users to Domain Admins
MATCH p=shortestPath((u:Group)-[:MemberOf|AdminTo|GenericAll|GenericWrite|WriteDacl*1..]->g:Group))
WHERE u.objectid ENDS WITH '-513' AND g.objectid ENDS WITH '-512' RETURN p
```

### Attack Path Prioritization

1. **Direct paths to DA**: Shortest chain from owned principals
2. **DCSync paths**: Any path granting replication rights
3. **Delegation abuse**: Unconstrained > Constrained > RBCD
4. **ACL chains**: GenericAll > WriteDACL > WriteOwner > GenericWrite
5. **Credential paths**: HasSession > AdminTo > SQLAdmin

## Conducting Internal Reconnaissance with BloodHound CE

### Custom Collection with SharpHound v2

```powershell
# SharpHound v2 with custom options
SharpHound.exe -c All --collectionmethod Session --loop --loopduration 02:00:00 --loopinterval 00:05:00

# Target specific OU
SharpHound.exe -c All --ldapusername user --ldappassword pass --searchbase "OU=Servers,DC=domain,DC=com"
```

### Advanced Cypher Queries for Attack Path Analysis

```cypher
// Find users that can read LAPS passwords
MATCH (u:User)-[:ReadLAPSPassword]->(c:Computer) RETURN u.name, c.name

// Find computers where Domain Users are local admin
MATCH p=(g:Group)-[:AdminTo]->(c:Computer)
WHERE g.objectid ENDS WITH '-513' RETURN p

// Find all paths through constrained delegation
MATCH (n)-[:AllowedToDelegate]->(m) RETURN n.name, m.name

// Find users with AdminCount=1 (protected accounts)
MATCH (u:User {admincount:true}) WHERE NOT u.name STARTS WITH 'KRBTGT' RETURN u.name

// Derivative local admin paths
MATCH p=shortestPath((u:User)-[:AdminTo|MemberOf*1..]->(c:Computer)) RETURN p LIMIT 50
```

## Exploiting Active Directory with BloodHound

### Graph-Based Recon Methodology

1. **Map domain structure**: Users, groups, computers, GPOs
2. **Identify high-value targets**: Domain Admins, Enterprise Admins, DC computer accounts
3. **Find attack paths**: Shortest path from current position to DA
4. **Exploit ACL chains**: GenericAll -> WriteDACL -> WriteOwner escalation
5. **Exploit delegation**: Unconstrained delegation on servers -> capture TGTs

### BloodHound-Guided Exploitation

```bash
# Step 1: Identify attack path
# In BloodHound UI: "Shortest Paths to Domain Admins from Owned Principals"

# Step 2: Exploit the path (example: GenericAll on user)
# Force change password
net user targetuser NewP@ss123 /domain

# Step 3: Use compromised account for next hop
crackmapexec smb TARGET -u targetuser -p 'NewP@ss123' --shares
```

## Tools

| Tool | Purpose |
|------|---------|
| BloodHound CE | Attack path visualization |
| SharpHound | Data collection (Windows) |
| bloodhound-python | Data collection (Linux) |
| Neo4j | Graph database backend |
| Cypher | Query language for path analysis |
