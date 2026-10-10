"""
STRIDE-per-Element threat generation rules and enumeration engine.
Implements standard Microsoft Threat Modeling methodology.
"""

from typing import List, Dict
from tools.model import ComponentType, STRIDECategory, IdentifiedThreat, SystemComponent

# Mapping: Which STRIDE threats apply to which element types
STRIDE_MATRIX: Dict[ComponentType, List[STRIDECategory]] = {
    ComponentType.EXTERNAL_ENTITY: [
        STRIDECategory.SPOOFING,
        STRIDECategory.REPUDIATION,
    ],
    ComponentType.PROCESS: [
        STRIDECategory.SPOOFING,
        STRIDECategory.TAMPERING,
        STRIDECategory.REPUDIATION,
        STRIDECategory.INFORMATION_DISCLOSURE,
        STRIDECategory.DENIAL_OF_SERVICE,
        STRIDECategory.ELEVATION_OF_PRIVILEGE,
    ],
    ComponentType.DATA_STORE: [
        STRIDECategory.TAMPERING,
        STRIDECategory.REPUDIATION,
        STRIDECategory.INFORMATION_DISCLOSURE,
        STRIDECategory.DENIAL_OF_SERVICE,
    ],
    ComponentType.DATA_FLOW: [
        STRIDECategory.TAMPERING,
        STRIDECategory.INFORMATION_DISCLOSURE,
        STRIDECategory.DENIAL_OF_SERVICE,
    ],
}

# Knowledge base of standard threats per component type and STRIDE category
THREAT_KNOWLEDGE_BASE: Dict[ComponentType, Dict[STRIDECategory, Dict[str, str]]] = {
    ComponentType.EXTERNAL_ENTITY: {
        STRIDECategory.SPOOFING: {
            "title": "Credential Stuffing or Session Hijacking",
            "description": "An adversary impersonates a legitimate user using stolen credentials or hijacked session cookies.",
            "impact": "Unauthorized access to student academic records and portal actions.",
            "mitigation": "Enforce MFA/FIDO2, short-lived signed session tokens, and IP/device posture binding."
        },
        STRIDECategory.REPUDIATION: {
            "title": "Unauthenticated Action Repudiation",
            "description": "A user performs high-risk transactions (e.g. course drops, grade edits) and later denies having initiated them.",
            "impact": "Inability to maintain non-repudiation in audit investigations.",
            "mitigation": "Immutable audit logging, cryptographic digital signatures, and forward-secure log shipping."
        }
    },
    ComponentType.PROCESS: {
        STRIDECategory.SPOOFING: {
            "title": "Service Identity Impersonation",
            "description": "Rogue microservice impersonates a trusted backend API worker.",
            "impact": "Attacker intercepts inter-service RPCs and poisons internal message queues.",
            "mitigation": "Deploy mTLS (Mutual TLS) with SPIFFE/SPIRE or Cloudflare Zero Trust service tokens."
        },
        STRIDECategory.TAMPERING: {
            "title": "Memory or Parameter Tampering (Injection Attacks)",
            "description": "Malicious payload manipulates backend execution flow via SQLi, command injection, or deserialization.",
            "impact": "Remote code execution or arbitrary backend database manipulation.",
            "mitigation": "Strict input validation, parameterized queries, and least-privilege service containers."
        },
        STRIDECategory.REPUDIATION: {
            "title": "Log Injection or Log Deletion",
            "description": "Adversary alters local execution logs or floods log storage to obfuscate unauthorized changes.",
            "impact": "Failure of compliance audits and lost forensic traceability.",
            "mitigation": "Centralized write-once log aggregation with cryptographic log hashing."
        },
        STRIDECategory.INFORMATION_DISCLOSURE: {
            "title": "Verbose Error Leaks or Memory Exposure",
            "description": "Application crashes leak stack traces, environment variables, or database connection strings.",
            "impact": "Attacker acquires reconnaissance details to pivot into deeper network segments.",
            "mitigation": "Sanitized error handling, custom generic 500 error pages, and secret management tools (Vault)."
        },
        STRIDECategory.DENIAL_OF_SERVICE: {
            "title": "Resource Starvation / ReDoS / Algorithmic Complexity Attack",
            "description": "Excessive or computationally asymmetric requests exhaust CPU, memory, or thread pools.",
            "impact": "Service outage during high-traffic windows (e.g. course registration rush).",
            "mitigation": "Cloudflare DDoS protection, rate limiting, connection pooling, and circuit breakers."
        },
        STRIDECategory.ELEVATION_OF_PRIVILEGE: {
            "title": "Broken Object Level Authorization (BOLA / IDOR)",
            "description": "Standard student account accesses administrator endpoints by manipulating record IDs.",
            "impact": "Privilege escalation leading to unauthorized grade modifications or administrative takeover.",
            "mitigation": "Enforce RBAC/ABAC authorization checks on every data access query."
        }
    },
    ComponentType.DATA_STORE: {
        STRIDECategory.TAMPERING: {
            "title": "Unauthorized Direct Database Modification",
            "description": "Attacker accesses database port directly to alter grade or financial ledgers.",
            "impact": "Data corruption and academic record integrity compromise.",
            "mitigation": "Restrict network access via Cloudflare Tunnels (no exposed public IPs), encrypt at rest."
        },
        STRIDECategory.REPUDIATION: {
            "title": "Unlogged Administrative Modifications",
            "description": "DBA or compromised root account updates database tables directly without logging.",
            "impact": "Undetectable modification of sensitive records.",
            "mitigation": "Enable database-level audit triggers and append-only write logs."
        },
        STRIDECategory.INFORMATION_DISCLOSURE: {
            "title": "Data Breach via Backup Exposure or Unencrypted Disk",
            "description": "Unencrypted backups or unsegmented storage buckets leak student PII and grades.",
            "impact": "Mass confidentiality breach, FERPA compliance violation.",
            "mitigation": "AES-256 database-level column encryption, IAM access controls, and strict DLP."
        },
        STRIDECategory.DENIAL_OF_SERVICE: {
            "title": "Storage Exhaustion or Connection Pool Locking",
            "description": "Unbounded table growth or deadlocks lock database read/write queries.",
            "impact": "System-wide failure and transaction failures.",
            "mitigation": "Disk quotas, query timeout limits, connection pool pooling (PgBouncer), and read replicas."
        }
    },
    ComponentType.DATA_FLOW: {
        STRIDECategory.TAMPERING: {
            "title": "Man-in-the-Middle (MitM) Packet Modification",
            "description": "Adversary alters unencrypted or weak cipher packets in transit over campus Wi-Fi.",
            "impact": "Manipulation of student submissions or financial payment parameters.",
            "mitigation": "Enforce TLS 1.3 with HSTS and Certificate Pinning."
        },
        STRIDECategory.INFORMATION_DISCLOSURE: {
            "title": "Traffic Eavesdropping / Packet Sniffing",
            "description": "Unencrypted plaintext HTTP traffic captured over rogue campus access points.",
            "impact": "Session token and password theft.",
            "mitigation": "Zero Trust network policy, WARP client encryption, and mandatory HTTPS."
        },
        STRIDECategory.DENIAL_OF_SERVICE: {
            "title": "SYN Flood / Network Pipe Saturation",
            "description": "Volumetric attack saturates campus ingress bandwidth.",
            "impact": "Inability for legitimate users to access on-campus hosted portals.",
            "mitigation": "Cloudflare Magic Transit and Anycast DDoS mitigation edge."
        }
    }
}


def enumerate_stride_threats(component: SystemComponent) -> List[IdentifiedThreat]:
    """Generates standard STRIDE threats for a given component."""
    applicable_categories = STRIDE_MATRIX.get(component.type, [])
    threats = []
    
    kb_for_type = THREAT_KNOWLEDGE_BASE.get(component.type, {})
    counter = 1
    for cat in applicable_categories:
        info = kb_for_type.get(cat, {
            "title": f"Generic {cat.value} Threat",
            "description": f"Potential {cat.value} vulnerability in {component.name}.",
            "impact": f"Negative impact on system {cat.value.lower()}.",
            "mitigation": "Apply defense-in-depth and security controls."
        })
        threat_id = f"THR-{component.id}-{counter:02d}"
        threats.append(IdentifiedThreat(
            id=threat_id,
            target_component=component.name,
            component_type=component.type,
            stride_category=cat,
            title=info["title"],
            description=info["description"],
            impact=info["impact"],
            recommended_mitigation=info["mitigation"]
        ))
        counter += 1
        
    return threats
