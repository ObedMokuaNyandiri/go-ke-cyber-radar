"""
.GO.KE Cyber-Surface Radar — Ministry Breakdown Component
============================================================
Displays per-ministry risk analysis in a card grid layout
with risk scores, domain counts, and key findings.
"""

import plotly.graph_objects as go
import streamlit as st
from typing import Any, Dict, List

from config import RiskLevel, RISK_COLORS
from utils.helpers import classify_risk, risk_color


def render_ministry_breakdown(ministry_risks: Dict[str, Dict[str, Any]]) -> None:
    """Render the ministry breakdown grid."""

    if not ministry_risks:
        st.info("No ministry data available. Run a scan or enable demo mode.")
        return

    # Sort by average risk (highest first)
    sorted_ministries = sorted(
        ministry_risks.items(),
        key=lambda x: x[1].get("avg_risk", 0),
        reverse=True,
    )

    # ── Risk Heatmap Bar Chart ────────────────────────────────────────────
    st.markdown("""
    <div class="glass-panel-header">
        ORG: MINISTRY RISK HEATMAP
    </div>
    """, unsafe_allow_html=True)

    ministry_names = [m[0] for m in sorted_ministries]
    risk_scores = [m[1].get("avg_risk", 0) for m in sorted_ministries]

    risk_colors_list = []
    for score in risk_scores:
        level = classify_risk(score)
        risk_colors_list.append(RISK_COLORS.get(level, "#64748b"))

    fig = go.Figure()

    fig.add_trace(go.Bar(
        y=ministry_names,
        x=risk_scores,
        orientation="h",
        marker=dict(
            color=risk_colors_list,
            line=dict(width=0),
            opacity=0.85,
        ),
        text=[f"{s:.0f}" for s in risk_scores],
        textposition="outside",
        textfont=dict(family="Orbitron", size=10, color="#94a3b8"),
        hovertemplate="<b>%{y}</b><br>Risk Score: %{x:.0f}<extra></extra>",
    ))

    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter", color="#94a3b8"),
        xaxis=dict(
            title=dict(text="Average Risk Score", font=dict(size=11)),
            range=[0, 105],
            gridcolor="rgba(30,41,59,0.3)",
        ),
        yaxis=dict(
            tickfont=dict(size=10, family="Inter"),
            autorange="reversed",
        ),
        margin=dict(l=180, r=50, t=10, b=40),
        height=max(350, len(sorted_ministries) * 28),
        showlegend=False,
    )

    # Add danger zone shading
    fig.add_vrect(x0=80, x1=105, fillcolor="rgba(255,0,60,0.05)", line_width=0)
    fig.add_vrect(x0=60, x1=80, fillcolor="rgba(255,107,53,0.03)", line_width=0)

    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False}, theme=None)

    # ── Ministry Cards Grid ───────────────────────────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("""
    <div class="glass-panel-header">
        DATA: MINISTRY DETAILS
    </div>
    """, unsafe_allow_html=True)

    # Display in 3-column grid
    cols_per_row = 3
    for row_start in range(0, len(sorted_ministries), cols_per_row):
        cols = st.columns(cols_per_row)
        for col_idx, col in enumerate(cols):
            ministry_idx = row_start + col_idx
            if ministry_idx >= len(sorted_ministries):
                break

            ministry_name, data = sorted_ministries[ministry_idx]

            with col:
                _render_ministry_card(ministry_name, data)


def _render_ministry_card(name: str, data: Dict[str, Any]) -> None:
    """Render a single ministry card."""
    avg_risk = data.get("avg_risk", 0)
    level = data.get("risk_level", classify_risk(avg_risk))
    color = risk_color(level) if isinstance(level, RiskLevel) else RISK_COLORS.get(RiskLevel(level.value if hasattr(level, 'value') else level), "#64748b")
    domain_count = data.get("domain_count", 0)
    finding_count = data.get("finding_count", 0)
    ssl_issues = data.get("ssl_issues", 0)
    exposed_ports = data.get("exposed_ports", 0)

    domains_list = ", ".join(data.get("domains", [])[:3])
    if len(data.get("domains", [])) > 3:
        domains_list += f" +{len(data['domains']) - 3} more"

    # Risk bar width
    bar_width = min(avg_risk, 100)

    st.markdown(f"""
    <div class="ministry-card">
        <div class="ministry-name">{name}</div>
        <div class="ministry-domains">{domains_list}</div>

        <div style="margin-top: 12px; display: flex; justify-content: space-between; align-items: flex-end;">
            <div class="ministry-risk" style="color: {color};">{avg_risk:.0f}</div>
            <div style="
                font-family: 'JetBrains Mono', monospace;
                font-size: 0.65rem;
                color: #64748b;
                text-align: right;
            ">
                {domain_count} domains<br>
                {finding_count} findings
            </div>
        </div>

        <!-- Risk bar -->
        <div style="
            width: 100%;
            height: 4px;
            background: #1e293b;
            border-radius: 2px;
            margin-top: 8px;
            overflow: hidden;
        ">
            <div style="
                width: {bar_width}%;
                height: 100%;
                background: {color};
                border-radius: 2px;
                transition: width 0.5s ease;
                box-shadow: 0 0 8px {color}80;
            "></div>
        </div>

        <!-- Mini stats -->
        <div style="
            display: flex;
            gap: 12px;
            margin-top: 10px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.62rem;
            color: #64748b;
        ">
            <span>SSL Issues: <span style="color: {'#ff003c' if ssl_issues > 0 else '#00ff88'};">{ssl_issues}</span></span>
            <span>Exposed: <span style="color: {'#ff003c' if exposed_ports > 0 else '#00ff88'};">{exposed_ports}</span></span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Small spacing between cards
    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
