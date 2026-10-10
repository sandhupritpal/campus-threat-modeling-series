"""
Campus Threat Modeling & Zero Trust Workshop Portal.
Interactive Streamlit application for students and engineers to explore DFDs,
run automated STRIDE threat modeling, and evaluate Cloudflare Zero Trust policies.
"""

import json
import os
import sys
import pandas as pd
import streamlit as st

# Add repository root to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tools.model import ComponentType, SystemComponent, STRIDECategory
from tools.stride_engine import enumerate_stride_threats
from tools.dread_calculator import score_threat, rank_threats_by_risk, calculate_risk_summary
from tools.report_exporter import ThreatReportExporter

st.set_page_config(
    page_title="Campus Threat Modeling & Zero Trust Portal",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Campus Threat Modeling & Zero Trust Workshop Series")
st.markdown(
    """
    **Interactive Security Architecture Lab**:
    Explore system decomposition, automated **STRIDE-per-Element** threat analysis, 
    quantitative **DREAD** risk scoring, and **Cloudflare Zero Trust** defense architectures.
    """
)

# Load sample architecture
@st.cache_data
def load_sample_architecture():
    arch_path = os.path.join(os.path.dirname(__file__), "..", "labs", "lab1-campus-portal-dfd", "architecture.json")
    with open(arch_path, "r", encoding="utf-8") as f:
        return json.load(f)

arch_data = load_sample_architecture()
components = [SystemComponent(**c) for c in arch_data["components"]]

tab1, tab2, tab3, tab4 = st.tabs([
    "🏛️ System Architecture (DFD)",
    "🔍 Automated STRIDE Threat Modeler",
    "🧮 DREAD Risk Evaluation Matrix",
    "🌐 Cloudflare Zero Trust Defense",
])

with tab1:
    st.subheader(f"System: {arch_data['system_name']} (v{arch_data['version']})")
    st.markdown(
        """
        ### Data Flow Diagram (DFD) Elements
        Review the decomposed architecture components and their corresponding trust zones:
        """
    )
    comp_df = pd.DataFrame([
        {
            "ID": c.id,
            "Component Name": c.name,
            "Element Type": c.type.value,
            "Trust Zone": c.trust_zone,
            "Description": c.description
        }
        for c in components
    ])
    st.dataframe(comp_df, use_container_width=True)

    st.markdown(
        """
        ```mermaid
        flowchart LR
            U["Student / Faculty Browser<br/>(External Entity)"] -->|HTTPS (443)| GW["Campus API Gateway<br/>(Process / DMZ)"]
            GW -->|mTLS| MS["Student Record Microservice<br/>(Process / Enclave)"]
            MS -->|SQL (5432)| DB[("PostgreSQL DB<br/>(Data Store)")]

            subgraph Public ["Trust Zone: Public Internet"]
                U
            end
            subgraph DMZ ["Trust Zone: Campus DMZ"]
                GW
            end
            subgraph Secure ["Trust Zone: Secure Enclave"]
                MS
                DB
            end
        ```
        """
    )

with tab2:
    st.subheader("STRIDE-per-Element Automated Threat Enumeration")
    st.markdown(
        """
        Select an architecture component below to inspect the STRIDE threats generated 
        by the automated threat modeling engine:
        """
    )

    selected_comp_name = st.selectbox("Select Component to Analyze", [c.name for c in components])
    selected_comp = next(c for c in components if c.name == selected_comp_name)

    threats = enumerate_stride_threats(selected_comp)
    st.info(f"Generated **{len(threats)} STRIDE threats** applicable to element type: `{selected_comp.type.value}`")

    for t in threats:
        with st.expander(f"🔴 [{t.stride_category.value}] {t.title} ({t.id})"):
            st.markdown(f"**Description**: {t.description}")
            st.markdown(f"**Impact**: {t.impact}")
            st.markdown(f"**Recommended Mitigation**: `{t.recommended_mitigation}`")

with tab3:
    st.subheader("Quantitative DREAD Risk Scoring Engine")
    st.markdown(
        """
        Evaluate candidate threats using the DREAD formula:
        $$\\text{Score} = \\frac{D + R + E + A + D}{5}$$
        """
    )

    # Enumerate all threats for all components
    all_threats = []
    for c in components:
        all_threats.extend(enumerate_stride_threats(c))

    # Apply default baseline DREAD scores
    for i, t in enumerate(all_threats):
        if t.stride_category in [STRIDECategory.TAMPERING, STRIDECategory.ELEVATION_OF_PRIVILEGE]:
            score_threat(t, 9, 8, 7, 9, 8)
        elif t.stride_category == STRIDECategory.SPOOFING:
            score_threat(t, 8, 7, 7, 8, 7)
        elif t.stride_category == STRIDECategory.INFORMATION_DISCLOSURE:
            score_threat(t, 8, 8, 6, 8, 8)
        else:
            score_threat(t, 6, 6, 6, 7, 6)

    ranked_threats = rank_threats_by_risk(all_threats)
    summary = calculate_risk_summary(ranked_threats)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Identified Threats", summary["total_threats"])
    c2.metric("Critical Threats (8-10)", summary["Critical"])
    c3.metric("High Threats (6-7.9)", summary["High"])
    c4.metric("Average Risk Score", f"{summary['average_score']} / 10.0")

    threat_rows = [
        {
            "ID": t.id,
            "Component": t.target_component,
            "STRIDE": t.stride_category.value,
            "Title": t.title,
            "DREAD Total": t.dread_score.total_score,
            "Severity": t.dread_score.severity_level,
            "Mitigation": t.recommended_mitigation
        }
        for t in ranked_threats
    ]
    st.dataframe(pd.DataFrame(threat_rows), use_container_width=True)

    if st.button("📥 Export Threat Assessment Report (Markdown & JSON)"):
        reports_dir = os.path.join(os.path.dirname(__file__), "..", "reports")
        ThreatReportExporter.save_reports(arch_data["system_name"], components, ranked_threats, output_dir=reports_dir)
        st.success(f"Report exported successfully to `{reports_dir}/threat_model_report.md`!")

with tab4:
    st.subheader("Cloudflare Zero Trust Architecture & Defensive Controls")
    st.markdown(
        """
        ### Mitigating STRIDE Threats via Cloudflare's Zero Trust Stack:
        - **Inbound Attack Surface Elimination (`cloudflared`)**: Outbound-only tunnel eliminates open router ports (Ports 80/443 closed to public scans).
        - **Contextual Identity Proxy (Cloudflare Access)**: Enforces IdP (SSO) + Device Health + Geolocation before proxying traffic.
        - **Egress Filtering & DLP (Cloudflare Gateway + WARP)**: Protects student endpoints from malware C2 and credential harvesting.
        """
    )
    rules_path = os.path.join(os.path.dirname(__file__), "..", "labs", "lab4-cloudflare-zerotrust", "zero_trust_rules.json")
    with open(rules_path, "r", encoding="utf-8") as f:
        st.json(json.load(f))
