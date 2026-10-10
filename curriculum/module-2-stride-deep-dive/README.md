# Module 2: STRIDE Deep-Dive & Threat Identification

## 🎯 Learning Objectives
- Master the **STRIDE** taxonomy developed by Praerit Garg and Loren Kohnfelder at Microsoft.
- Learn **STRIDE-per-Element** methodology to systematically enumerate vulnerabilities without missing blind spots.
- Build attack trees for identified weaknesses.

---

## 🔍 The STRIDE Taxonomy

| Category | Security Property Violated | Definition | Example in Campus Systems |
| :--- | :--- | :--- | :--- |
| **S - Spoofing** | **Authenticity** | Pretending to be an authorized user or system component. | Stealing JWT cookies to submit grades as a faculty member. |
| **T - Tampering** | **Integrity** | Modifying data in memory, on disk, or in transit across networks. | Modifying tuition payment amount parameter in an unauthenticated POST request. |
| **R - Repudiation** | **Non-Repudiation** | Denying having performed an action due to lack of proof. | A student drops a scheduled exam and claims the system lost the registration. |
| **I - Information Disclosure** | **Confidentiality** | Exposing private or sensitive data to unauthorized actors. | Stack trace leaks student GPA and SSN in verbose 500 error responses. |
| **D - Denial of Service** | **Availability** | Degrading or exhausting system capacity so users cannot access services. | DDoS attack saturating campus web servers on the first day of class registration. |
| **E - Elevation of Privilege** | **Authorization** | Gaining unauthorized administrative or higher-tier permissions. | Exploiting an IDOR / BOLA vulnerability to promote a student account to Superadmin. |

---

## 📐 STRIDE-per-Element Mapping Rule

Not all threats apply to all elements! Use the standardized matrix:

| Element Type | S | T | R | I | D | E |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **External Entity** | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ |
| **Process** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Data Store** | ❌ | ✅ | ✅ | ✅ | ✅ | ❌ |
| **Data Flow** | ❌ | ✅ | ❌ | ✅ | ✅ | ❌ |

---

## 💻 Hands-on Exercise: Lab 2
Execute `python -m tools.stride_engine` to generate candidate threats for your target microservice.
