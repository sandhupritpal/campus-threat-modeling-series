# Module 3: Quantitative Risk Scoring (DREAD) & Prioritization

## 🎯 Learning Objectives
- Differentiate qualitative threat identification from quantitative risk ranking.
- Master the **DREAD** risk evaluation framework.
- Calculate business impact, prioritize remediation backlogs, and write engineering mitigation tickets.

---

## 🧮 The DREAD Scoring Formula

DREAD assigns a numerical score from **1 (Low)** to **10 (Critical)** across 5 risk dimensions:

$$\text{DREAD Risk Score} = \frac{\text{Damage} + \text{Reproducibility} + \text{Exploitability} + \text{Affected Users} + \text{Discoverability}}{5}$$

### Parameter Criteria:

| Dimension | Question to Ask | Score 1-3 (Low) | Score 4-7 (Medium) | Score 8-10 (Critical) |
| :--- | :--- | :--- | :--- | :--- |
| **D - Damage Potential** | If exploited, how bad is the destruction? | Minor info leak | Data loss / localized disruption | Full database wipeout / RCE |
| **R - Reproducibility** | How reliable is the exploit execution? | Complex race condition | Works occasionally under conditions | 100% reliable every script run |
| **E - Exploitability** | How much technical expertise is needed? | Advanced cryptanalysis required | Experienced pentester with custom tool | Novice / script-kiddie / browser address bar |
| **A - Affected Users** | What proportion of users are compromised? | Specific edge-case account | Segment of student cohort | All enrolled students, faculty, and admins |
| **D - Discoverability** | How easy is it for an adversary to spot? | Obscure internal timing flaw | Visible through API fuzzing | Cleartext parameter in public HTML form |

---

## 📊 Risk Severity Thresholds

- **8.0 – 10.0 (Critical)**: Stop ship / emergency hotfix required immediately.
- **6.0 – 7.9 (High)**: Must remediate within the current development sprint.
- **4.0 – 5.9 (Medium)**: Scheduled for mitigation in normal product backlog.
- **1.0 – 3.9 (Low)**: Accepted risk or defense-in-depth polish.
