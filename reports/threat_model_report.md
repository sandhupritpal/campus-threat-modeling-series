# 🛡️ Threat Model Assessment: University Campus Student Portal & Grade Registry
**Methodology**: STRIDE-per-Element + DREAD Quantitative Risk Ranking  
**Total Components Evaluated**: `7`  
**Total Threats Identified**: `26`  
**Average System DREAD Score**: `7.4 / 10.0`  

## 📊 Executive Risk Summary
| Severity | Count | Proportion |
| :--- | :---: | :---: |
| 🔴 Critical (8.0 - 10.0) | 0 | 0.0% |
| 🟠 High (6.0 - 7.9) | 26 | 100.0% |
| 🟡 Medium (4.0 - 5.9) | 0 | 0.0% |
| 🟢 Low (1.0 - 3.9) | 0 | 0.0% |

## 🏛️ System Architecture Components
| ID | Component Name | Element Type | Trust Zone | Description |
| :--- | :--- | :--- | :--- | :--- |
| `COMP-01` | **Student Web & Mobile Browser** | `external_entity` | `Public Internet` | Student endpoints accessing course registration, exam timetables, and grades. |
| `COMP-02` | **Faculty Portal Workstation** | `external_entity` | `Campus Wi-Fi / Remote` | Instructor devices submitting grades, assignments, and curriculum updates. |
| `COMP-03` | **Campus Ingress API Gateway** | `process` | `Campus DMZ` | Reverse proxy routing student and faculty requests, terminating TLS. |
| `COMP-04` | **Student Record Microservice** | `process` | `Secure Campus Enclave` | Internal business logic handling course enrollment, degree progression, and GPAs. |
| `COMP-05` | **PostgreSQL Gradebook Database** | `data_store` | `Isolated Database Tier` | Relational database holding student grades, transcripts, and financial status. |
| `COMP-06` | **HTTPS Student Ingress Flow** | `data_flow` | `Public Internet -> Campus DMZ` | REST API traffic containing user credentials, course drop/add commands. |
| `COMP-07` | **Internal Service-to-Database SQL Flow** | `data_flow` | `Enclave -> Database Tier` | Database query flow transmitting grade modification queries and student transcript data. |

## 🎯 Identified Threat Matrix (STRIDE-per-Element)
| Threat ID | Component | STRIDE Category | Title | DREAD Score | Severity |
| :--- | :--- | :--- | :--- | :---: | :---: |
| `THR-COMP-01-01` | Student Web & Mobile Browser | `Spoofing` | **Credential Stuffing or Session Hijacking** | `7.4` | `High` |
| `THR-COMP-01-02` | Student Web & Mobile Browser | `Repudiation` | **Unauthenticated Action Repudiation** | `7.4` | `High` |
| `THR-COMP-02-01` | Faculty Portal Workstation | `Spoofing` | **Credential Stuffing or Session Hijacking** | `7.4` | `High` |
| `THR-COMP-02-02` | Faculty Portal Workstation | `Repudiation` | **Unauthenticated Action Repudiation** | `7.4` | `High` |
| `THR-COMP-03-01` | Campus Ingress API Gateway | `Spoofing` | **Service Identity Impersonation** | `7.4` | `High` |
| `THR-COMP-03-02` | Campus Ingress API Gateway | `Tampering` | **Memory or Parameter Tampering (Injection Attacks)** | `7.4` | `High` |
| `THR-COMP-03-03` | Campus Ingress API Gateway | `Repudiation` | **Log Injection or Log Deletion** | `7.4` | `High` |
| `THR-COMP-03-04` | Campus Ingress API Gateway | `Information Disclosure` | **Verbose Error Leaks or Memory Exposure** | `7.4` | `High` |
| `THR-COMP-03-05` | Campus Ingress API Gateway | `Denial of Service` | **Resource Starvation / ReDoS / Algorithmic Complexity Attack** | `7.4` | `High` |
| `THR-COMP-03-06` | Campus Ingress API Gateway | `Elevation of Privilege` | **Broken Object Level Authorization (BOLA / IDOR)** | `7.4` | `High` |
| `THR-COMP-04-01` | Student Record Microservice | `Spoofing` | **Service Identity Impersonation** | `7.4` | `High` |
| `THR-COMP-04-02` | Student Record Microservice | `Tampering` | **Memory or Parameter Tampering (Injection Attacks)** | `7.4` | `High` |
| `THR-COMP-04-03` | Student Record Microservice | `Repudiation` | **Log Injection or Log Deletion** | `7.4` | `High` |
| `THR-COMP-04-04` | Student Record Microservice | `Information Disclosure` | **Verbose Error Leaks or Memory Exposure** | `7.4` | `High` |
| `THR-COMP-04-05` | Student Record Microservice | `Denial of Service` | **Resource Starvation / ReDoS / Algorithmic Complexity Attack** | `7.4` | `High` |
| `THR-COMP-04-06` | Student Record Microservice | `Elevation of Privilege` | **Broken Object Level Authorization (BOLA / IDOR)** | `7.4` | `High` |
| `THR-COMP-05-01` | PostgreSQL Gradebook Database | `Tampering` | **Unauthorized Direct Database Modification** | `7.4` | `High` |
| `THR-COMP-05-02` | PostgreSQL Gradebook Database | `Repudiation` | **Unlogged Administrative Modifications** | `7.4` | `High` |
| `THR-COMP-05-03` | PostgreSQL Gradebook Database | `Information Disclosure` | **Data Breach via Backup Exposure or Unencrypted Disk** | `7.4` | `High` |
| `THR-COMP-05-04` | PostgreSQL Gradebook Database | `Denial of Service` | **Storage Exhaustion or Connection Pool Locking** | `7.4` | `High` |
| `THR-COMP-06-01` | HTTPS Student Ingress Flow | `Tampering` | **Man-in-the-Middle (MitM) Packet Modification** | `7.4` | `High` |
| `THR-COMP-06-02` | HTTPS Student Ingress Flow | `Information Disclosure` | **Traffic Eavesdropping / Packet Sniffing** | `7.4` | `High` |
| `THR-COMP-06-03` | HTTPS Student Ingress Flow | `Denial of Service` | **SYN Flood / Network Pipe Saturation** | `7.4` | `High` |
| `THR-COMP-07-01` | Internal Service-to-Database SQL Flow | `Tampering` | **Man-in-the-Middle (MitM) Packet Modification** | `7.4` | `High` |
| `THR-COMP-07-02` | Internal Service-to-Database SQL Flow | `Information Disclosure` | **Traffic Eavesdropping / Packet Sniffing** | `7.4` | `High` |
| `THR-COMP-07-03` | Internal Service-to-Database SQL Flow | `Denial of Service` | **SYN Flood / Network Pipe Saturation** | `7.4` | `High` |

## 🛠️ Detailed Threat Mitigations
### `THR-COMP-01-01`: Credential Stuffing or Session Hijacking
- **Target**: `Student Web & Mobile Browser` (external_entity)
- **STRIDE Classification**: Spoofing
- **Threat Description**: An adversary impersonates a legitimate user using stolen credentials or hijacked session cookies.
- **Business/Security Impact**: Unauthorized access to student academic records and portal actions.
- **DREAD Vector**: `D:8 R:7 E:7 A:8 D:7` (Total: **7.4** - High)
- **Recommended Mitigation (Zero Trust / DevSecOps)**: 
  > Enforce MFA/FIDO2, short-lived signed session tokens, and IP/device posture binding.

### `THR-COMP-01-02`: Unauthenticated Action Repudiation
- **Target**: `Student Web & Mobile Browser` (external_entity)
- **STRIDE Classification**: Repudiation
- **Threat Description**: A user performs high-risk transactions (e.g. course drops, grade edits) and later denies having initiated them.
- **Business/Security Impact**: Inability to maintain non-repudiation in audit investigations.
- **DREAD Vector**: `D:8 R:7 E:7 A:8 D:7` (Total: **7.4** - High)
- **Recommended Mitigation (Zero Trust / DevSecOps)**: 
  > Immutable audit logging, cryptographic digital signatures, and forward-secure log shipping.

### `THR-COMP-02-01`: Credential Stuffing or Session Hijacking
- **Target**: `Faculty Portal Workstation` (external_entity)
- **STRIDE Classification**: Spoofing
- **Threat Description**: An adversary impersonates a legitimate user using stolen credentials or hijacked session cookies.
- **Business/Security Impact**: Unauthorized access to student academic records and portal actions.
- **DREAD Vector**: `D:8 R:7 E:7 A:8 D:7` (Total: **7.4** - High)
- **Recommended Mitigation (Zero Trust / DevSecOps)**: 
  > Enforce MFA/FIDO2, short-lived signed session tokens, and IP/device posture binding.

### `THR-COMP-02-02`: Unauthenticated Action Repudiation
- **Target**: `Faculty Portal Workstation` (external_entity)
- **STRIDE Classification**: Repudiation
- **Threat Description**: A user performs high-risk transactions (e.g. course drops, grade edits) and later denies having initiated them.
- **Business/Security Impact**: Inability to maintain non-repudiation in audit investigations.
- **DREAD Vector**: `D:8 R:7 E:7 A:8 D:7` (Total: **7.4** - High)
- **Recommended Mitigation (Zero Trust / DevSecOps)**: 
  > Immutable audit logging, cryptographic digital signatures, and forward-secure log shipping.

### `THR-COMP-03-01`: Service Identity Impersonation
- **Target**: `Campus Ingress API Gateway` (process)
- **STRIDE Classification**: Spoofing
- **Threat Description**: Rogue microservice impersonates a trusted backend API worker.
- **Business/Security Impact**: Attacker intercepts inter-service RPCs and poisons internal message queues.
- **DREAD Vector**: `D:8 R:7 E:7 A:8 D:7` (Total: **7.4** - High)
- **Recommended Mitigation (Zero Trust / DevSecOps)**: 
  > Deploy mTLS (Mutual TLS) with SPIFFE/SPIRE or Cloudflare Zero Trust service tokens.

### `THR-COMP-03-02`: Memory or Parameter Tampering (Injection Attacks)
- **Target**: `Campus Ingress API Gateway` (process)
- **STRIDE Classification**: Tampering
- **Threat Description**: Malicious payload manipulates backend execution flow via SQLi, command injection, or deserialization.
- **Business/Security Impact**: Remote code execution or arbitrary backend database manipulation.
- **DREAD Vector**: `D:8 R:7 E:7 A:8 D:7` (Total: **7.4** - High)
- **Recommended Mitigation (Zero Trust / DevSecOps)**: 
  > Strict input validation, parameterized queries, and least-privilege service containers.

### `THR-COMP-03-03`: Log Injection or Log Deletion
- **Target**: `Campus Ingress API Gateway` (process)
- **STRIDE Classification**: Repudiation
- **Threat Description**: Adversary alters local execution logs or floods log storage to obfuscate unauthorized changes.
- **Business/Security Impact**: Failure of compliance audits and lost forensic traceability.
- **DREAD Vector**: `D:8 R:7 E:7 A:8 D:7` (Total: **7.4** - High)
- **Recommended Mitigation (Zero Trust / DevSecOps)**: 
  > Centralized write-once log aggregation with cryptographic log hashing.

### `THR-COMP-03-04`: Verbose Error Leaks or Memory Exposure
- **Target**: `Campus Ingress API Gateway` (process)
- **STRIDE Classification**: Information Disclosure
- **Threat Description**: Application crashes leak stack traces, environment variables, or database connection strings.
- **Business/Security Impact**: Attacker acquires reconnaissance details to pivot into deeper network segments.
- **DREAD Vector**: `D:8 R:7 E:7 A:8 D:7` (Total: **7.4** - High)
- **Recommended Mitigation (Zero Trust / DevSecOps)**: 
  > Sanitized error handling, custom generic 500 error pages, and secret management tools (Vault).

### `THR-COMP-03-05`: Resource Starvation / ReDoS / Algorithmic Complexity Attack
- **Target**: `Campus Ingress API Gateway` (process)
- **STRIDE Classification**: Denial of Service
- **Threat Description**: Excessive or computationally asymmetric requests exhaust CPU, memory, or thread pools.
- **Business/Security Impact**: Service outage during high-traffic windows (e.g. course registration rush).
- **DREAD Vector**: `D:8 R:7 E:7 A:8 D:7` (Total: **7.4** - High)
- **Recommended Mitigation (Zero Trust / DevSecOps)**: 
  > Cloudflare DDoS protection, rate limiting, connection pooling, and circuit breakers.

### `THR-COMP-03-06`: Broken Object Level Authorization (BOLA / IDOR)
- **Target**: `Campus Ingress API Gateway` (process)
- **STRIDE Classification**: Elevation of Privilege
- **Threat Description**: Standard student account accesses administrator endpoints by manipulating record IDs.
- **Business/Security Impact**: Privilege escalation leading to unauthorized grade modifications or administrative takeover.
- **DREAD Vector**: `D:8 R:7 E:7 A:8 D:7` (Total: **7.4** - High)
- **Recommended Mitigation (Zero Trust / DevSecOps)**: 
  > Enforce RBAC/ABAC authorization checks on every data access query.

### `THR-COMP-04-01`: Service Identity Impersonation
- **Target**: `Student Record Microservice` (process)
- **STRIDE Classification**: Spoofing
- **Threat Description**: Rogue microservice impersonates a trusted backend API worker.
- **Business/Security Impact**: Attacker intercepts inter-service RPCs and poisons internal message queues.
- **DREAD Vector**: `D:8 R:7 E:7 A:8 D:7` (Total: **7.4** - High)
- **Recommended Mitigation (Zero Trust / DevSecOps)**: 
  > Deploy mTLS (Mutual TLS) with SPIFFE/SPIRE or Cloudflare Zero Trust service tokens.

### `THR-COMP-04-02`: Memory or Parameter Tampering (Injection Attacks)
- **Target**: `Student Record Microservice` (process)
- **STRIDE Classification**: Tampering
- **Threat Description**: Malicious payload manipulates backend execution flow via SQLi, command injection, or deserialization.
- **Business/Security Impact**: Remote code execution or arbitrary backend database manipulation.
- **DREAD Vector**: `D:8 R:7 E:7 A:8 D:7` (Total: **7.4** - High)
- **Recommended Mitigation (Zero Trust / DevSecOps)**: 
  > Strict input validation, parameterized queries, and least-privilege service containers.

### `THR-COMP-04-03`: Log Injection or Log Deletion
- **Target**: `Student Record Microservice` (process)
- **STRIDE Classification**: Repudiation
- **Threat Description**: Adversary alters local execution logs or floods log storage to obfuscate unauthorized changes.
- **Business/Security Impact**: Failure of compliance audits and lost forensic traceability.
- **DREAD Vector**: `D:8 R:7 E:7 A:8 D:7` (Total: **7.4** - High)
- **Recommended Mitigation (Zero Trust / DevSecOps)**: 
  > Centralized write-once log aggregation with cryptographic log hashing.

### `THR-COMP-04-04`: Verbose Error Leaks or Memory Exposure
- **Target**: `Student Record Microservice` (process)
- **STRIDE Classification**: Information Disclosure
- **Threat Description**: Application crashes leak stack traces, environment variables, or database connection strings.
- **Business/Security Impact**: Attacker acquires reconnaissance details to pivot into deeper network segments.
- **DREAD Vector**: `D:8 R:7 E:7 A:8 D:7` (Total: **7.4** - High)
- **Recommended Mitigation (Zero Trust / DevSecOps)**: 
  > Sanitized error handling, custom generic 500 error pages, and secret management tools (Vault).

### `THR-COMP-04-05`: Resource Starvation / ReDoS / Algorithmic Complexity Attack
- **Target**: `Student Record Microservice` (process)
- **STRIDE Classification**: Denial of Service
- **Threat Description**: Excessive or computationally asymmetric requests exhaust CPU, memory, or thread pools.
- **Business/Security Impact**: Service outage during high-traffic windows (e.g. course registration rush).
- **DREAD Vector**: `D:8 R:7 E:7 A:8 D:7` (Total: **7.4** - High)
- **Recommended Mitigation (Zero Trust / DevSecOps)**: 
  > Cloudflare DDoS protection, rate limiting, connection pooling, and circuit breakers.

### `THR-COMP-04-06`: Broken Object Level Authorization (BOLA / IDOR)
- **Target**: `Student Record Microservice` (process)
- **STRIDE Classification**: Elevation of Privilege
- **Threat Description**: Standard student account accesses administrator endpoints by manipulating record IDs.
- **Business/Security Impact**: Privilege escalation leading to unauthorized grade modifications or administrative takeover.
- **DREAD Vector**: `D:8 R:7 E:7 A:8 D:7` (Total: **7.4** - High)
- **Recommended Mitigation (Zero Trust / DevSecOps)**: 
  > Enforce RBAC/ABAC authorization checks on every data access query.

### `THR-COMP-05-01`: Unauthorized Direct Database Modification
- **Target**: `PostgreSQL Gradebook Database` (data_store)
- **STRIDE Classification**: Tampering
- **Threat Description**: Attacker accesses database port directly to alter grade or financial ledgers.
- **Business/Security Impact**: Data corruption and academic record integrity compromise.
- **DREAD Vector**: `D:8 R:7 E:7 A:8 D:7` (Total: **7.4** - High)
- **Recommended Mitigation (Zero Trust / DevSecOps)**: 
  > Restrict network access via Cloudflare Tunnels (no exposed public IPs), encrypt at rest.

### `THR-COMP-05-02`: Unlogged Administrative Modifications
- **Target**: `PostgreSQL Gradebook Database` (data_store)
- **STRIDE Classification**: Repudiation
- **Threat Description**: DBA or compromised root account updates database tables directly without logging.
- **Business/Security Impact**: Undetectable modification of sensitive records.
- **DREAD Vector**: `D:8 R:7 E:7 A:8 D:7` (Total: **7.4** - High)
- **Recommended Mitigation (Zero Trust / DevSecOps)**: 
  > Enable database-level audit triggers and append-only write logs.

### `THR-COMP-05-03`: Data Breach via Backup Exposure or Unencrypted Disk
- **Target**: `PostgreSQL Gradebook Database` (data_store)
- **STRIDE Classification**: Information Disclosure
- **Threat Description**: Unencrypted backups or unsegmented storage buckets leak student PII and grades.
- **Business/Security Impact**: Mass confidentiality breach, FERPA compliance violation.
- **DREAD Vector**: `D:8 R:7 E:7 A:8 D:7` (Total: **7.4** - High)
- **Recommended Mitigation (Zero Trust / DevSecOps)**: 
  > AES-256 database-level column encryption, IAM access controls, and strict DLP.

### `THR-COMP-05-04`: Storage Exhaustion or Connection Pool Locking
- **Target**: `PostgreSQL Gradebook Database` (data_store)
- **STRIDE Classification**: Denial of Service
- **Threat Description**: Unbounded table growth or deadlocks lock database read/write queries.
- **Business/Security Impact**: System-wide failure and transaction failures.
- **DREAD Vector**: `D:8 R:7 E:7 A:8 D:7` (Total: **7.4** - High)
- **Recommended Mitigation (Zero Trust / DevSecOps)**: 
  > Disk quotas, query timeout limits, connection pool pooling (PgBouncer), and read replicas.

### `THR-COMP-06-01`: Man-in-the-Middle (MitM) Packet Modification
- **Target**: `HTTPS Student Ingress Flow` (data_flow)
- **STRIDE Classification**: Tampering
- **Threat Description**: Adversary alters unencrypted or weak cipher packets in transit over campus Wi-Fi.
- **Business/Security Impact**: Manipulation of student submissions or financial payment parameters.
- **DREAD Vector**: `D:8 R:7 E:7 A:8 D:7` (Total: **7.4** - High)
- **Recommended Mitigation (Zero Trust / DevSecOps)**: 
  > Enforce TLS 1.3 with HSTS and Certificate Pinning.

### `THR-COMP-06-02`: Traffic Eavesdropping / Packet Sniffing
- **Target**: `HTTPS Student Ingress Flow` (data_flow)
- **STRIDE Classification**: Information Disclosure
- **Threat Description**: Unencrypted plaintext HTTP traffic captured over rogue campus access points.
- **Business/Security Impact**: Session token and password theft.
- **DREAD Vector**: `D:8 R:7 E:7 A:8 D:7` (Total: **7.4** - High)
- **Recommended Mitigation (Zero Trust / DevSecOps)**: 
  > Zero Trust network policy, WARP client encryption, and mandatory HTTPS.

### `THR-COMP-06-03`: SYN Flood / Network Pipe Saturation
- **Target**: `HTTPS Student Ingress Flow` (data_flow)
- **STRIDE Classification**: Denial of Service
- **Threat Description**: Volumetric attack saturates campus ingress bandwidth.
- **Business/Security Impact**: Inability for legitimate users to access on-campus hosted portals.
- **DREAD Vector**: `D:8 R:7 E:7 A:8 D:7` (Total: **7.4** - High)
- **Recommended Mitigation (Zero Trust / DevSecOps)**: 
  > Cloudflare Magic Transit and Anycast DDoS mitigation edge.

### `THR-COMP-07-01`: Man-in-the-Middle (MitM) Packet Modification
- **Target**: `Internal Service-to-Database SQL Flow` (data_flow)
- **STRIDE Classification**: Tampering
- **Threat Description**: Adversary alters unencrypted or weak cipher packets in transit over campus Wi-Fi.
- **Business/Security Impact**: Manipulation of student submissions or financial payment parameters.
- **DREAD Vector**: `D:8 R:7 E:7 A:8 D:7` (Total: **7.4** - High)
- **Recommended Mitigation (Zero Trust / DevSecOps)**: 
  > Enforce TLS 1.3 with HSTS and Certificate Pinning.

### `THR-COMP-07-02`: Traffic Eavesdropping / Packet Sniffing
- **Target**: `Internal Service-to-Database SQL Flow` (data_flow)
- **STRIDE Classification**: Information Disclosure
- **Threat Description**: Unencrypted plaintext HTTP traffic captured over rogue campus access points.
- **Business/Security Impact**: Session token and password theft.
- **DREAD Vector**: `D:8 R:7 E:7 A:8 D:7` (Total: **7.4** - High)
- **Recommended Mitigation (Zero Trust / DevSecOps)**: 
  > Zero Trust network policy, WARP client encryption, and mandatory HTTPS.

### `THR-COMP-07-03`: SYN Flood / Network Pipe Saturation
- **Target**: `Internal Service-to-Database SQL Flow` (data_flow)
- **STRIDE Classification**: Denial of Service
- **Threat Description**: Volumetric attack saturates campus ingress bandwidth.
- **Business/Security Impact**: Inability for legitimate users to access on-campus hosted portals.
- **DREAD Vector**: `D:8 R:7 E:7 A:8 D:7` (Total: **7.4** - High)
- **Recommended Mitigation (Zero Trust / DevSecOps)**: 
  > Cloudflare Magic Transit and Anycast DDoS mitigation edge.

## 🌐 Cloudflare Zero Trust Architecture Alignment
1. **Eliminate Inbound Attack Surface**: Deploy `cloudflared` tunnels to front all internal backend processes without exposing public static IP addresses.
2. **Context-Aware Identity Verification**: Enforce Cloudflare Access policies validating student IdP (Okta/Google Workspace/Azure AD) + Device Posture checks before reaching student records.
3. **Encrypted Egress via WARP**: Route campus mobile/workstation traffic through Cloudflare Gateway to enforce DNS filtering, DLP, and SSL inspection.
