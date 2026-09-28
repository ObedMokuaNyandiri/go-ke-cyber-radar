"""
.GO.KE Cyber-Surface Radar — Radar Map Component
====================================================
Renders the interactive Kenya threat map with plotly.
Shows pulsing threat dots color-coded by severity,
with a radar sweep overlay animation.
"""

import plotly.graph_objects as go
import streamlit as st
import streamlit.components.v1 as components
from typing import Any, Dict, List

from config import RISK_COLORS, RiskLevel, KENYA_CENTER


def render_radar_map(scan_results: List[Dict[str, Any]]) -> None:
    """Render the interactive Kenya radar map with threat indicators."""

    # Build data for map
    lats = []
    lons = []
    texts = []
    colors = []
    sizes = []
    custom_data = []

    for r in scan_results:
        loc = r.get("location", {})
        lat = loc.get("lat", KENYA_CENTER["lat"])
        lon = loc.get("lon", KENYA_CENTER["lon"])
        risk = r.get("risk_score", 0)
        level = r.get("risk_level", "INFO")

        lats.append(lat)
        lons.append(lon)

        # Color by risk level
        level_enum = RiskLevel(level) if level in [e.value for e in RiskLevel] else RiskLevel.INFO
        colors.append(RISK_COLORS.get(level_enum, "#64748b"))

        # Size by risk score
        sizes.append(max(8, risk / 5))

        # Hover text
        domain = r.get("domain", "unknown")
        name = r.get("name", domain)
        findings_count = len(r.get("findings", []))
        texts.append(
            f"<b>{domain}</b><br>"
            f"{name}<br>"
            f"Ministry: {r.get('ministry', 'N/A')}<br>"
            f"Risk Score: {risk}/100<br>"
            f"Risk Level: {level}<br>"
            f"Findings: {findings_count}"
        )
        custom_data.append(r)

    # Create the map figure
    fig = go.Figure()

    # Add threat dots
    fig.add_trace(go.Scattergeo(
        lat=lats,
        lon=lons,
        mode="markers",
        marker=dict(
            size=sizes,
            color=colors,
            opacity=0.85,
            sizemode="diameter",
        ),
        text=texts,
        hoverinfo="text",
        hoverlabel=dict(
            bgcolor="#111827",
            bordercolor="#1e293b",
            font=dict(
                family="Inter, sans-serif",
                size=12,
                color="#e2e8f0",
            ),
        ),
        name="Assets",
    ))

    # Add outer glow rings for high-risk assets
    high_risk_lats = []
    high_risk_lons = []
    high_risk_sizes = []
    high_risk_colors = []

    for i, r in enumerate(scan_results):
        if r.get("risk_score", 0) >= 60:
            high_risk_lats.append(lats[i])
            high_risk_lons.append(lons[i])
            high_risk_sizes.append(sizes[i] * 2)
            high_risk_colors.append(colors[i])

    if high_risk_lats:
        fig.add_trace(go.Scattergeo(
            lat=high_risk_lats,
            lon=high_risk_lons,
            mode="markers",
            marker=dict(
                size=high_risk_sizes,
                color=high_risk_colors,
                opacity=0.15,
                sizemode="diameter",
            ),
            hoverinfo="skip",
            showlegend=False,
            name="Risk Glow",
        ))

    fig.update_layout(
        geo=dict(
            bgcolor="#0a0e17",
            showland=True,
            landcolor="#0f1923",
            showocean=True,
            oceancolor="#0a0e17",
            showcountries=True,
            countrycolor="#1e293b",
            center=dict(lat=KENYA_CENTER["lat"], lon=KENYA_CENTER["lon"]),
            projection_scale=20,  # equivalent to zoom
        ),
        showlegend=False,
        margin=dict(l=0, r=0, t=0, b=0),
        paper_bgcolor="#0a0e17",
        plot_bgcolor="#0a0e17",
        height=500,
    )

    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False}, theme=None)

    # Render radar sweep overlay
    _render_radar_overlay()


def _render_radar_overlay() -> None:
    """Render the animated radar sweep overlay."""
    radar_html = """
    <div style="
        position: relative;
        margin-top: -16px;
        height: 4px;
        overflow: hidden;
        border-radius: 0 0 12px 12px;
    ">
        <div style="
            position: absolute;
            top: 0;
            left: -100%;
            width: 50%;
            height: 100%;
            background: linear-gradient(90deg, transparent, #00f0ff, transparent);
            animation: radarLine 3s linear infinite;
        "></div>
    </div>
    <style>
        @keyframes radarLine {
            0% { left: -50%; }
            100% { left: 100%; }
        }
    </style>
    """
    st.markdown(radar_html, unsafe_allow_html=True)


def render_threat_legend() -> None:
    """Render the map legend showing risk level colors."""
    legend_html = """
    <div style="
        display: flex;
        gap: 16px;
        justify-content: center;
        padding: 8px 0;
        font-family: 'Inter', sans-serif;
        font-size: 0.72rem;
        color: #94a3b8;
    ">
        <span style="display: flex; align-items: center; gap: 4px;">
            <span style="width: 8px; height: 8px; border-radius: 50%; background: #ff003c;"></span>
            Critical
        </span>
        <span style="display: flex; align-items: center; gap: 4px;">
            <span style="width: 8px; height: 8px; border-radius: 50%; background: #ff6b35;"></span>
            High
        </span>
        <span style="display: flex; align-items: center; gap: 4px;">
            <span style="width: 8px; height: 8px; border-radius: 50%; background: #ffaa00;"></span>
            Medium
        </span>
        <span style="display: flex; align-items: center; gap: 4px;">
            <span style="width: 8px; height: 8px; border-radius: 50%; background: #00f0ff;"></span>
            Low
        </span>
        <span style="display: flex; align-items: center; gap: 4px;">
            <span style="width: 8px; height: 8px; border-radius: 50%; background: #64748b;"></span>
            Info
        </span>
    </div>
    """
    st.markdown(legend_html, unsafe_allow_html=True)
