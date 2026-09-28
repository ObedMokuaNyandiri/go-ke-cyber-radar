"""
.GO.KE Cyber-Surface Radar — Metrics Panel Component
======================================================
Renders the top-level KPI metrics with animated cards
and the national risk gauge.
"""

import streamlit as st
import streamlit.components.v1 as components
from typing import Any, Dict

from config import COLORS, RiskLevel, RISK_COLORS
from utils.helpers import metric_card_html


def render_metrics_bar(summary: Dict[str, Any], national_risk: Dict[str, Any]) -> None:
    """Render the top KPI metrics bar."""

    if not summary.get("scanned"):
        # Empty state
        cols = st.columns(6)
        labels = ["Assets Scanned", "Critical Threats", "High Risk", "Avg Risk Score", "Exposed DBs", "Expired SSLs"]
        for i, col in enumerate(cols):
            with col:
                st.markdown(metric_card_html("—", labels[i], "cyan"), unsafe_allow_html=True)
        return

    col1, col2, col3, col4, col5, col6 = st.columns(6)

    with col1:
        st.markdown(metric_card_html(
            str(summary["total"]),
            "Assets Scanned",
            "cyan",
            icon="[O]",
        ), unsafe_allow_html=True)

    with col2:
        st.markdown(metric_card_html(
            str(summary["critical_count"]),
            "Critical Threats",
            "red" if summary["critical_count"] > 0 else "green",
            icon="[!]" if summary["critical_count"] > 0 else "[v]",
        ), unsafe_allow_html=True)

    with col3:
        st.markdown(metric_card_html(
            str(summary["high_count"]),
            "High Risk",
            "amber" if summary["high_count"] > 0 else "green",
            icon="[-]" if summary["high_count"] > 0 else "[v]",
        ), unsafe_allow_html=True)

    with col4:
        avg = summary["avg_risk"]
        color = "green" if avg < 30 else "amber" if avg < 60 else "red"
        st.markdown(metric_card_html(
            f"{avg}",
            "Avg Risk Score",
            color,
            icon="[#]",
        ), unsafe_allow_html=True)

    with col5:
        dbs = summary["exposed_databases"]
        st.markdown(metric_card_html(
            str(dbs),
            "Exposed Databases",
            "red" if dbs > 0 else "green",
            icon="[D]" if dbs > 0 else "[L]",
        ), unsafe_allow_html=True)

    with col6:
        expired = summary["ssl_expired"]
        st.markdown(metric_card_html(
            str(expired),
            "Expired SSLs",
            "red" if expired > 0 else "green",
            icon="[U]" if expired > 0 else "[L]",
        ), unsafe_allow_html=True)


def render_risk_gauge(national_risk: Dict[str, Any]) -> None:
    """Render the national cyber-risk gauge as a half-circle SVG."""

    score = national_risk.get("score", 0)
    grade = national_risk.get("grade", "N/A")
    level = national_risk.get("level", RiskLevel.INFO)

    # Color based on score
    if score >= 80:
        gauge_color = "#ff003c"
        glow = "0 0 30px rgba(255,0,60,0.4)"
    elif score >= 60:
        gauge_color = "#ff6b35"
        glow = "0 0 30px rgba(255,107,53,0.4)"
    elif score >= 40:
        gauge_color = "#ffaa00"
        glow = "0 0 30px rgba(255,170,0,0.4)"
    elif score >= 20:
        gauge_color = "#00f0ff"
        glow = "0 0 30px rgba(0,240,255,0.4)"
    else:
        gauge_color = "#00ff88"
        glow = "0 0 30px rgba(0,255,136,0.4)"

    # Calculate arc angle (0-180 degrees mapped to 0-100 score)
    angle = (score / 100) * 180
    # SVG arc coordinates
    import math
    import textwrap
    end_x = 150 + 120 * math.cos(math.radians(180 - angle))
    end_y = 140 - 120 * math.sin(math.radians(180 - angle))
    large_arc = 1 if angle > 90 else 0

    summary_text = national_risk.get("summary", "")
    level_text = level.value if isinstance(level, RiskLevel) else str(level)

    gauge_html = f"""<div style="
    text-align: center;
    padding: 20px;
    background: linear-gradient(145deg, #0f1923, #1a2332);
    border: 1px solid #1e293b;
    border-radius: 16px;
">
    <div style="
        font-family: 'Orbitron', sans-serif;
        font-size: 0.7rem;
        color: #64748b;
        text-transform: uppercase;
        letter-spacing: 3px;
        margin-bottom: 12px;
    ">National Cyber-Risk Index</div>

    <svg viewBox="0 0 300 180" style="max-width: 280px; filter: drop-shadow({glow});">
        <!-- Background arc -->
        <path d="M 30 140 A 120 120 0 0 1 270 140"
              fill="none" stroke="#1e293b" stroke-width="16" stroke-linecap="round"/>

        <!-- Score arc -->
        <path d="M 30 140 A 120 120 0 {large_arc} 1 {end_x:.1f} {end_y:.1f}"
              fill="none" stroke="{gauge_color}" stroke-width="16" stroke-linecap="round"
              style="filter: drop-shadow(0 0 8px {gauge_color}80);">
            <animate attributeName="stroke-dasharray" from="0 1000" to="1000 0"
                     dur="1.5s" fill="freeze" />
        </path>

        <!-- Center score -->
        <text x="150" y="125" text-anchor="middle"
              font-family="Orbitron" font-size="48" font-weight="800" fill="{gauge_color}">
            {score}
        </text>
        <text x="150" y="150" text-anchor="middle"
              font-family="Inter" font-size="13" fill="#64748b">
            / 100
        </text>

        <!-- Scale labels -->
        <text x="25" y="165" font-family="JetBrains Mono" font-size="10" fill="#00ff88">0</text>
        <text x="140" y="18" font-family="JetBrains Mono" font-size="10" fill="#ffaa00">50</text>
        <text x="268" y="165" font-family="JetBrains Mono" font-size="10" fill="#ff003c">100</text>
    </svg>

    <div style="
        font-family: 'Orbitron', sans-serif;
        font-size: 1.2rem;
        font-weight: 700;
        color: {gauge_color};
        margin-top: 8px;
        letter-spacing: 2px;
    ">GRADE: {grade}</div>

    <div style="
        font-family: 'Inter', sans-serif;
        font-size: 0.75rem;
        color: #94a3b8;
        margin-top: 8px;
        padding: 0 12px;
    ">{summary_text}</div>
</div>"""

    st.markdown(gauge_html, unsafe_allow_html=True)


def render_scan_stats(summary: Dict[str, Any]) -> None:
    """Render scan statistics in the sidebar."""
    if not summary.get("scanned"):
        return

    st.markdown(f"""
    <div style="
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.72rem;
        color: #94a3b8;
        background: #0f1923;
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 12px;
        line-height: 1.8;
    ">
        <div style="color: #00f0ff; font-weight: 600; margin-bottom: 4px;">SCAN STATISTICS</div>
        <div>Domains: <span style="color: #e2e8f0;">{summary['total']}</span></div>
        <div>Duration: <span style="color: #e2e8f0;">{summary.get('scan_duration', 0):.1f}s</span></div>
        <div>Findings: <span style="color: #e2e8f0;">{summary['total_findings']}</span></div>
        <div>SSL Valid: <span style="color: #00ff88;">{summary['ssl_valid']}</span></div>
        <div>SSL Expired: <span style="color: #ff003c;">{summary['ssl_expired']}</span></div>
        <div>SSL Expiring: <span style="color: #ffaa00;">{summary['ssl_expiring']}</span></div>
        <div>No SSL: <span style="color: #64748b;">{summary['ssl_missing']}</span></div>
        <div>Exposed DBs: <span style="color: #ff003c;">{summary['exposed_databases']}</span></div>
        <div>Errors: <span style="color: #64748b;">{summary['errors']}</span></div>
    </div>
    """, unsafe_allow_html=True)
