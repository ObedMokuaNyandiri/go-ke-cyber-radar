"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    .GO.KE CYBER-SURFACE RADAR                              ║
║                  National Cyber-Attack Surface Intelligence                 ║
║                                                                            ║
║  A real-time dashboard mapping Kenya's government cyber-attack surface     ║
║  using passive reconnaissance — SSL inspection, DNS enumeration,           ║
║  HTTP header analysis, and Shodan integration.                             ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import streamlit as st
import pandas as pd
import warnings
from datetime import datetime, timezone

# Suppress SSL warnings for passive inspection
warnings.filterwarnings("ignore", message="Unverified HTTPS request")
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Page Configuration (must be first Streamlit call) ─────────────────────────
st.set_page_config(
    page_title=".GO.KE Cyber-Surface Radar",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Imports ───────────────────────────────────────────────────────────────────
from config import APP_TITLE, APP_SUBTITLE, COLORS, RiskLevel
from utils.helpers import (
    load_css, generate_demo_scan_results, classify_risk,
    risk_color, risk_emoji, format_timestamp,
)
from analysis.risk_engine import calculate_national_risk, calculate_ministry_risks
from analysis.threat_classifier import classify_threats, get_threat_summary
from analysis.vuln_correlator import VulnCorrelator
from components.scan_controls import render_sidebar_controls
from components.metrics_panel import render_metrics_bar, render_risk_gauge, render_scan_stats
from components.radar_map import render_radar_map, render_threat_legend
from components.threat_feed import render_threat_feed, render_threat_detail
from components.ssl_observatory import render_ssl_observatory
from components.ministry_breakdown import render_ministry_breakdown
from scanner.scan_orchestrator import ScanOrchestrator


# ── Load Custom CSS ───────────────────────────────────────────────────────────
css = load_css()
if css:
    st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)


# ── Session State Initialization ──────────────────────────────────────────────
if "scan_results" not in st.session_state:
    st.session_state.scan_results = []
if "threats" not in st.session_state:
    st.session_state.threats = []
if "summary" not in st.session_state:
    st.session_state.summary = {"scanned": False}
if "national_risk" not in st.session_state:
    st.session_state.national_risk = {}
if "ministry_risks" not in st.session_state:
    st.session_state.ministry_risks = {}
if "vuln_data" not in st.session_state:
    st.session_state.vuln_data = {}
if "scan_running" not in st.session_state:
    st.session_state.scan_running = False


# ── Sidebar Controls ─────────────────────────────────────────────────────────
controls = render_sidebar_controls()


# ── Handle Scan / Demo Load ──────────────────────────────────────────────────
if controls["start_scan"]:
    if controls["demo_mode"]:
        # Load demo data
        with st.spinner("Loading simulation data..."):
            results = generate_demo_scan_results()

            # Run analysis
            national_risk = calculate_national_risk(results)
            threats = classify_threats(results)
            threat_summary = get_threat_summary(threats)
            ministry_risks = calculate_ministry_risks(results)

            # Vulnerability correlation
            correlator = VulnCorrelator()
            vuln_data = correlator.correlate_all(results)

            # Build summary
            risk_levels = [r["risk_level"] for r in results]
            risk_scores = [r["risk_score"] for r in results]
            ssl_statuses = [r.get("ssl", {}).get("status", "unknown") for r in results]
            exposed_dbs = sum(
                1 for r in results
                for p in r.get("ports", [])
                if p.get("type") == "database"
            )

            summary = {
                "total": len(results),
                "scanned": True,
                "scan_duration": 2.4,
                "avg_risk": round(sum(risk_scores) / len(risk_scores), 1),
                "max_risk": max(risk_scores),
                "critical_count": risk_levels.count("CRITICAL"),
                "high_count": risk_levels.count("HIGH"),
                "medium_count": risk_levels.count("MEDIUM"),
                "low_count": risk_levels.count("LOW"),
                "info_count": risk_levels.count("INFO"),
                "total_findings": sum(len(r.get("findings", [])) for r in results),
                "ssl_expired": ssl_statuses.count("expired"),
                "ssl_expiring": ssl_statuses.count("expiring"),
                "ssl_missing": ssl_statuses.count("missing"),
                "ssl_valid": ssl_statuses.count("valid"),
                "exposed_databases": exposed_dbs,
                "errors": 0,
            }

            # Store in session
            st.session_state.scan_results = results
            st.session_state.threats = threats
            st.session_state.summary = summary
            st.session_state.national_risk = national_risk
            st.session_state.ministry_risks = ministry_risks
            st.session_state.vuln_data = vuln_data

    else:
        # Live scan
        st.session_state.scan_running = True
        orchestrator = ScanOrchestrator(shodan_api_key=controls.get("shodan_key"))

        progress_bar = st.progress(0, text="Initializing scan...")

        def update_progress(pct, domain):
            progress_bar.progress(int(pct), text=f"Scanning: {domain}")

        results = orchestrator.scan_all(progress_callback=update_progress)
        summary = orchestrator.get_summary()

        # Analysis
        national_risk = calculate_national_risk(results)
        threats = classify_threats(results)
        ministry_risks = calculate_ministry_risks(results)
        correlator = VulnCorrelator()
        vuln_data = correlator.correlate_all(results)

        # Store
        st.session_state.scan_results = results
        st.session_state.threats = threats
        st.session_state.summary = summary
        st.session_state.national_risk = national_risk
        st.session_state.ministry_risks = ministry_risks
        st.session_state.vuln_data = vuln_data
        st.session_state.scan_running = False

        progress_bar.empty()


# ── Render Scan Stats in Sidebar ──────────────────────────────────────────────
render_scan_stats(st.session_state.summary)


# ══════════════════════════════════════════════════════════════════════════════
# MAIN DASHBOARD LAYOUT
# ══════════════════════════════════════════════════════════════════════════════

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown(f"""
<div style="position: relative;">
    <div class="cyber-title">{APP_TITLE}</div>
    <div class="cyber-subtitle">{APP_SUBTITLE}</div>
</div>
""", unsafe_allow_html=True)

results = st.session_state.scan_results
summary = st.session_state.summary
threats = st.session_state.threats
national_risk = st.session_state.national_risk
ministry_risks = st.session_state.ministry_risks


# ── Empty State ───────────────────────────────────────────────────────────────
if not results:
    st.markdown("""
    <div style="
        text-align: center;
        padding: 80px 40px;
        color: #64748b;
    ">
        <div style="font-size: 4rem; margin-bottom: 16px; opacity: 0.6;">[•]</div>
        <div style="
            font-family: 'Orbitron', sans-serif;
            font-size: 1.2rem;
            color: #94a3b8;
            margin-bottom: 8px;
        ">RADAR STANDBY</div>
        <div style="
            font-family: 'Inter', sans-serif;
            font-size: 0.85rem;
            max-width: 500px;
            margin: 0 auto;
            line-height: 1.6;
        ">
            Launch a scan or enable Demo Mode from the sidebar
            to begin mapping the .go.ke cyber-attack surface.
        </div>
        <div style="
            margin-top: 24px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.7rem;
            color: #334155;
        ">
            Passive reconnaissance • SSL • DNS • HTTP Headers • Shodan
        </div>
    </div>
    """, unsafe_allow_html=True)

else:
    # ── Row 1: KPI Metrics ────────────────────────────────────────────────
    render_metrics_bar(summary, national_risk)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Row 2: Radar Map + Threat Feed ────────────────────────────────────
    map_col, feed_col = st.columns([3, 2])

    with map_col:
        st.markdown("""
        <div class="glass-panel-header">
            <span class="pulse-dot"></span>
            ATTACK SURFACE MAP — KENYA
        </div>
        """, unsafe_allow_html=True)

        render_radar_map(results)
        render_threat_legend()

    with feed_col:
        render_threat_feed(threats)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Row 3: National Risk Gauge + Quick Stats ──────────────────────────
    gauge_col, stats_col1, stats_col2 = st.columns([2, 1.5, 1.5])

    with gauge_col:
        render_risk_gauge(national_risk)

    with stats_col1:
        # Threat category breakdown
        threat_summary = get_threat_summary(threats)
        st.markdown("""
        <div class="glass-panel-header">STAT: THREATS BY CATEGORY</div>
        """, unsafe_allow_html=True)

        for category, count in sorted(
            threat_summary.get("by_category", {}).items(),
            key=lambda x: x[1], reverse=True
        ):
            pct = (count / max(len(threats), 1)) * 100
            st.markdown(f"""
            <div style="
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 6px 12px;
                margin-bottom: 4px;
                font-family: 'Inter', sans-serif;
                font-size: 0.75rem;
                color: #94a3b8;
            ">
                <span>{category}</span>
                <span style="
                    font-family: 'Orbitron', sans-serif;
                    color: #00f0ff;
                    font-size: 0.8rem;
                ">{count}</span>
            </div>
            <div style="
                width: 100%;
                height: 3px;
                background: #1e293b;
                border-radius: 2px;
                margin-bottom: 8px;
                overflow: hidden;
            ">
                <div style="
                    width: {pct}%;
                    height: 100%;
                    background: linear-gradient(90deg, #00f0ff, #3b82f6);
                    border-radius: 2px;
                "></div>
            </div>
            """, unsafe_allow_html=True)

    with stats_col2:
        # Vulnerability summary
        vuln_data = st.session_state.vuln_data
        st.markdown("""
        <div class="glass-panel-header">SEC: VULNERABILITIES</div>
        """, unsafe_allow_html=True)

        if vuln_data:
            by_sev = vuln_data.get("by_severity", {})
            st.markdown(f"""
            <div style="
                background: #0f1923;
                border: 1px solid #1e293b;
                border-radius: 8px;
                padding: 16px;
                font-family: 'JetBrains Mono', monospace;
                font-size: 0.75rem;
                line-height: 2;
            ">
                <div style="color: #e2e8f0; margin-bottom: 8px;">
                    Total: <span style="color: #00f0ff; font-family: 'Orbitron'; font-size: 1.2rem;">{vuln_data.get('total', 0)}</span>
                </div>
                <div style="color: #e2e8f0;">
                    Unique CVEs: <span style="color: #a855f7; font-family: 'Orbitron'; font-size: 1.2rem;">{vuln_data.get('unique_cves', 0)}</span>
                </div>
                <hr style="border-color: #1e293b; margin: 8px 0;">
                <div style="color: #ff003c;">CRITICAL: {by_sev.get('CRITICAL', 0)}</div>
                <div style="color: #ff6b35;">HIGH: {by_sev.get('HIGH', 0)}</div>
                <div style="color: #ffaa00;">MEDIUM: {by_sev.get('MEDIUM', 0)}</div>
                <div style="color: #00f0ff;">LOW: {by_sev.get('LOW', 0)}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Row 4: Tabbed Detail Views ────────────────────────────────────────
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "SEC: SSL Observatory",
        "ORG: Ministry Breakdown",
        "WARN: Threat Details",
        "DATA: Raw Data",
        "VULN: CVE Report",
    ])

    with tab1:
        render_ssl_observatory(results)

    with tab2:
        render_ministry_breakdown(ministry_risks)

    with tab3:
        st.markdown("""
        <div class="glass-panel-header">
            WARN: DETAILED THREAT ANALYSIS
        </div>
        """, unsafe_allow_html=True)

        # Filter options
        filter_col1, filter_col2 = st.columns(2)
        with filter_col1:
            level_filter = st.selectbox(
                "Filter by Severity",
                options=["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
            )
        with filter_col2:
            category_filter = st.selectbox(
                "Filter by Category",
                options=["All"] + list(set(t.get("category", "") for t in threats)),
            )

        filtered_threats = threats
        if level_filter != "All":
            filtered_threats = [t for t in filtered_threats if t.get("level") == level_filter]
        if category_filter != "All":
            filtered_threats = [t for t in filtered_threats if t.get("category") == category_filter]

        st.caption(f"Showing {len(filtered_threats)} of {len(threats)} threats")

        for threat in filtered_threats[:30]:
            render_threat_detail(threat)

    with tab4:
        st.markdown("""
        <div class="glass-panel-header">
            DATA: RAW SCAN DATA
        </div>
        """, unsafe_allow_html=True)

        # Build display dataframe
        rows = []
        for r in results:
            ssl_status = r.get("ssl", {}).get("status", "unknown")
            ssl_days = r.get("ssl", {}).get("days_remaining", "N/A")
            server = r.get("server", {}).get("banner", "N/A")
            ports = ", ".join(
                f"{p['port']}/{p['service']}"
                for p in r.get("ports", [])
                if p.get("type") != "standard"
            )
            findings = len(r.get("findings", []))
            headers_score = r.get("headers", {}).get("score", "N/A")

            rows.append({
                "Domain": r.get("domain", ""),
                "Ministry": r.get("ministry", ""),
                "Risk": r.get("risk_score", 0),
                "Level": r.get("risk_level", "INFO"),
                "SSL": ssl_status.upper(),
                "SSL Days": ssl_days,
                "Server": server or "N/A",
                "Exposed Ports": ports or "—",
                "Headers %": headers_score,
                "Findings": findings,
                "IP": r.get("ip", "N/A"),
            })

        df = pd.DataFrame(rows)
        df = df.sort_values("Risk", ascending=False)

        st.dataframe(
            df,
            use_container_width=True,
            height=500,
            column_config={
                "Risk": st.column_config.ProgressColumn(
                    "Risk Score",
                    min_value=0,
                    max_value=100,
                    format="%d",
                ),
                "Headers %": st.column_config.ProgressColumn(
                    "Header Score",
                    min_value=0,
                    max_value=100,
                    format="%d%%",
                ),
            },
        )

        # Download button
        csv = df.to_csv(index=False)
        st.download_button(
            "EXPORT CSV",
            csv,
            "go_ke_radar_scan_results.csv",
            "text/csv",
            use_container_width=True,
        )

    with tab5:
        st.markdown("""
        <div class="glass-panel-header">
            VULN: CVE CORRELATION REPORT
        </div>
        """, unsafe_allow_html=True)

        vuln_data = st.session_state.vuln_data
        if vuln_data and vuln_data.get("total", 0) > 0:
            # CVE list
            cve_list = vuln_data.get("cve_list", [])
            if cve_list:
                st.markdown(f"""
                <div style="
                    font-family: 'JetBrains Mono', monospace;
                    font-size: 0.72rem;
                    color: #94a3b8;
                    margin-bottom: 16px;
                ">
                    <strong style="color: #00f0ff;">{len(cve_list)}</strong> unique CVEs
                    identified across the scanned infrastructure.
                </div>
                """, unsafe_allow_html=True)

            # Vulnerability table
            vuln_rows = []
            for v in vuln_data.get("all", []):
                vuln_rows.append({
                    "Domain": v.get("domain", ""),
                    "Type": v.get("type", ""),
                    "CVE": v.get("cve", "N/A"),
                    "Severity": v.get("severity", v.get("risk", "N/A")),
                    "Title": v.get("title", ""),
                    "CVSS": v.get("cvss", "N/A"),
                })

            vuln_df = pd.DataFrame(vuln_rows)
            if not vuln_df.empty:
                vuln_df = vuln_df.sort_values("Severity", ascending=True)
                st.dataframe(vuln_df, use_container_width=True, height=400)
        else:
            st.markdown("""
            <div style="
                text-align: center;
                padding: 40px;
                color: #64748b;
                font-family: 'Inter', sans-serif;
            ">
                No CVE correlations found in current scan data.
            </div>
            """, unsafe_allow_html=True)


# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown("""
<div style="
    text-align: center;
    padding: 32px 0 16px 0;
    border-top: 1px solid #1e293b;
    margin-top: 40px;
">
    <div style="
        font-family: 'Orbitron', sans-serif;
        font-size: 0.65rem;
        color: #334155;
        letter-spacing: 3px;
        text-transform: uppercase;
    ">
        .GO.KE CYBER-SURFACE RADAR • PASSIVE RECONNAISSANCE ONLY
    </div>
    <div style="
        font-family: 'Inter', sans-serif;
        font-size: 0.6rem;
        color: #1e293b;
        margin-top: 4px;
    ">
        Data sourced from public records. No active exploitation.
    </div>
</div>
""", unsafe_allow_html=True)
