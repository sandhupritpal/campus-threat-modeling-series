"""
Threat Model Report Exporter.
Produces formatted Markdown audit reports and JSON artifacts.
"""

import json
import os
from typing import List, Dict, Any
from tools.model import IdentifiedThreat, SystemComponent
from tools.dread_calculator import calculate_risk_summary


class ThreatReportExporter:
    """Generates structured threat modeling assessment reports."""

    @staticmethod
    def generate_markdown(
        system_name: str,
        components: List[SystemComponent],
        threats: List[IdentifiedThreat]
    ) -> str:
        summary = calculate_risk_summary(threats)
        
        md = []
        md.append(f"# 🛡️ Threat Model Assessment: {system_name}\n")
        md.append(f"**Methodology**: STRIDE-per-Element + DREAD Quantitative Risk Ranking  \n")
        md.append(f"**Total Components Evaluated**: `{len(components)}`  \n")
        md.append(f"**Total Threats Identified**: `{len(threats)}`  \n")
        md.append(f"**Average System DREAD Score**: `{summary['average_score']} / 10.0`  \n\n")

        md.append("## 📊 Executive Risk Summary\n")
        md.append("| Severity | Count | Proportion |\n")
        md.append("| :--- | :---: | :---: |\n")
        tot = max(len(threats), 1)
        md.append(f"| 🔴 Critical (8.0 - 10.0) | {summary['Critical']} | {(summary['Critical']/tot)*100:.1f}% |\n")
        md.append(f"| 🟠 High (6.0 - 7.9) | {summary['High']} | {(summary['High']/tot)*100:.1f}% |\n")
        md.append(f"| 🟡 Medium (4.0 - 5.9) | {summary['Medium']} | {(summary['Medium']/tot)*100:.1f}% |\n")
        md.append(f"| 🟢 Low (1.0 - 3.9) | {summary['Low']} | {(summary['Low']/tot)*100:.1f}% |\n\n")

        md.append("## 🏛️ System Architecture Components\n")
        md.append("| ID | Component Name | Element Type | Trust Zone | Description |\n")
        md.append("| :--- | :--- | :--- | :--- | :--- |\n")
        for c in components:
            md.append(f"| `{c.id}` | **{c.name}** | `{c.type.value}` | `{c.trust_zone}` | {c.description} |\n")
        md.append("\n")

        md.append("## 🎯 Identified Threat Matrix (STRIDE-per-Element)\n")
        md.append("| Threat ID | Component | STRIDE Category | Title | DREAD Score | Severity |\n")
        md.append("| :--- | :--- | :--- | :--- | :---: | :---: |\n")
        for t in threats:
            score_str = f"{t.dread_score.total_score:.1f}" if t.dread_score else "N/A"
            sev_str = t.dread_score.severity_level if t.dread_score else "Unscored"
            md.append(f"| `{t.id}` | {t.target_component} | `{t.stride_category.value}` | **{t.title}** | `{score_str}` | `{sev_str}` |\n")
        md.append("\n")

        md.append("## 🛠️ Detailed Threat Mitigations\n")
        for t in threats:
            md.append(f"### `{t.id}`: {t.title}\n")
            md.append(f"- **Target**: `{t.target_component}` ({t.component_type.value})\n")
            md.append(f"- **STRIDE Classification**: {t.stride_category.value}\n")
            md.append(f"- **Threat Description**: {t.description}\n")
            md.append(f"- **Business/Security Impact**: {t.impact}\n")
            if t.dread_score:
                d = t.dread_score
                md.append(f"- **DREAD Vector**: `D:{d.damage_potential} R:{d.reproducibility} E:{d.exploitability} A:{d.affected_users} D:{d.discoverability}` (Total: **{d.total_score}** - {d.severity_level})\n")
            md.append(f"- **Recommended Mitigation (Zero Trust / DevSecOps)**: \n  > {t.recommended_mitigation}\n\n")

        md.append("## 🌐 Cloudflare Zero Trust Architecture Alignment\n")
        md.append("1. **Eliminate Inbound Attack Surface**: Deploy `cloudflared` tunnels to front all internal backend processes without exposing public static IP addresses.\n")
        md.append("2. **Context-Aware Identity Verification**: Enforce Cloudflare Access policies validating student IdP (Okta/Google Workspace/Azure AD) + Device Posture checks before reaching student records.\n")
        md.append("3. **Encrypted Egress via WARP**: Route campus mobile/workstation traffic through Cloudflare Gateway to enforce DNS filtering, DLP, and SSL inspection.\n")

        return "".join(md)

    @staticmethod
    def save_reports(
        system_name: str,
        components: List[SystemComponent],
        threats: List[IdentifiedThreat],
        output_dir: str = "reports"
    ) -> None:
        os.makedirs(output_dir, exist_ok=True)
        md_text = ThreatReportExporter.generate_markdown(system_name, components, threats)
        
        with open(os.path.join(output_dir, "threat_model_report.md"), "w", encoding="utf-8") as f:
            f.write(md_text)

        json_data = {
            "system_name": system_name,
            "components": [c.model_dump() for c in components],
            "threats": [t.model_dump() for t in threats]
        }
        with open(os.path.join(output_dir, "threat_model.json"), "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2)
