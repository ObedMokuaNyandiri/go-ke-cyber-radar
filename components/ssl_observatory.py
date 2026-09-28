"""
.GO.KE Cyber-Surface Radar — SSL Observatory Component
=========================================================
Visualizes SSL certificate status across all scanned domains.
Shows expiry timeline, grade distribution, and certificate details.
"""

import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import streamlit as st
from datetime import datetime, timezone
from typing import Any, Dict, List

from config import COLORS


def render_ssl_observatory(scan_results: List[Dict[str, Any]]) -> None:
    """Render the SSL certificate observatory dashboard."""

    if not scan_results:
        st.info("No scan data available. Run a scan or enable demo mode.")
        return

    # Extract SSL data
    ssl_data = []
    for r in scan_results:
        ssl = r.get("ssl", {})
        ssl_data.append({
            "Domain": r.get("domain", ""),
            "Name": r.get("name", ""),
            "Ministry": r.get("ministry", ""),
            "Status": ssl.get("status", "unknown"),
            "Days Remaining": ssl.get("days_remaining"),
            "Issuer": ssl.get("issuer", "N/A"),
            "Protocol": ssl.get("protocol", "N/A"),
            "Grade": ssl.get("grade", "?"),
            "Self-Signed": ssl.get("self_signed", False),
        })

    df = pd.DataFrame(ssl_data)

    # ── Row 1: SSL Summary Metrics ────────────────────────────────────────
    col1, col2, col3, col4, col5 = st.columns(5)

    valid_count = len(df[df["Status"] == "valid"])
    expiring_count = len(df[df["Status"] == "expiring"])
    expired_count = len(df[df["Status"] == "expired"])
    missing_count = len(df[df["Status"] == "missing"])
    self_signed_count = len(df[df["Self-Signed"] == True])

    with col1:
        st.markdown(f"""
        <div class="metric-card metric-green" style="padding: 14px;">
            <div class="metric-value" style="font-size: 1.8rem;">[v] {valid_count}</div>
            <div class="metric-label">Valid</div>
        </div>
        """, unsafe_allow_html=True)
    with col2:
        st.markdown(f"""
        <div class="metric-card metric-amber" style="padding: 14px;">
            <div class="metric-value" style="font-size: 1.8rem;">[T] {expiring_count}</div>
            <div class="metric-label">Expiring</div>
        </div>
        """, unsafe_allow_html=True)
    with col3:
        st.markdown(f"""
        <div class="metric-card metric-red" style="padding: 14px;">
            <div class="metric-value" style="font-size: 1.8rem;">[U] {expired_count}</div>
            <div class="metric-label">Expired</div>
        </div>
        """, unsafe_allow_html=True)
    with col4:
        st.markdown(f"""
        <div class="metric-card metric-cyan" style="padding: 14px;">
            <div class="metric-value" style="font-size: 1.8rem;">[X] {missing_count}</div>
            <div class="metric-label">No SSL</div>
        </div>
        """, unsafe_allow_html=True)
    with col5:
        st.markdown(f"""
        <div class="metric-card metric-purple" style="padding: 14px;">
            <div class="metric-value" style="font-size: 1.8rem;">[!] {self_signed_count}</div>
            <div class="metric-label">Self-Signed</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Row 2: Charts ─────────────────────────────────────────────────────
    chart_col1, chart_col2 = st.columns([3, 2])

    with chart_col1:
        # Certificate Expiry Timeline
        _render_expiry_timeline(df)

    with chart_col2:
        # Grade distribution
        _render_grade_distribution(df)

    # ── Row 3: Detailed Table ─────────────────────────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("""
    <div class="glass-panel-header">
        DATA: CERTIFICATE DETAILS
    </div>
    """, unsafe_allow_html=True)

    # Styled dataframe
    display_df = df[["Domain", "Status", "Days Remaining", "Grade", "Issuer", "Protocol"]].copy()
    display_df = display_df.sort_values("Days Remaining", ascending=True, na_position="first")

    st.dataframe(
        display_df,
        use_container_width=True,
        height=350,
        column_config={
            "Domain": st.column_config.TextColumn("Domain", width="medium"),
            "Status": st.column_config.TextColumn("Status", width="small"),
            "Days Remaining": st.column_config.NumberColumn("Days Left", format="%d"),
            "Grade": st.column_config.TextColumn("Grade", width="small"),
            "Issuer": st.column_config.TextColumn("Issuer", width="medium"),
            "Protocol": st.column_config.TextColumn("Protocol", width="small"),
        },
    )


def _render_expiry_timeline(df: pd.DataFrame) -> None:
    """Render the certificate expiry timeline chart."""
    st.markdown("""
    <div class="glass-panel-header">
        TIMELINE: CERTIFICATE EXPIRY
    </div>
    """, unsafe_allow_html=True)

    # Filter to domains with known expiry
    timeline_df = df[df["Days Remaining"].notna()].copy()
    timeline_df = timeline_df.sort_values("Days Remaining")

    if timeline_df.empty:
        st.caption("No certificate expiry data available")
        return

    # Color by status
    color_map = {
        "expired": "#ff003c",
        "expiring": "#ffaa00",
        "valid": "#00ff88",
        "missing": "#64748b",
        "unknown": "#64748b",
    }

    colors = [color_map.get(s, "#64748b") for s in timeline_df["Status"]]

    fig = go.Figure()

    fig.add_trace(go.Bar(
        x=timeline_df["Domain"],
        y=timeline_df["Days Remaining"],
        marker_color=colors,
        marker_line=dict(width=0),
        text=timeline_df["Days Remaining"].apply(lambda x: f"{int(x)}d" if x >= 0 else f"{int(x)}d"),
        textposition="outside",
        textfont=dict(size=9, color="#94a3b8", family="JetBrains Mono"),
        hovertemplate="<b>%{x}</b><br>Days: %{y}<extra></extra>",
    ))

    # Add danger zone line at 30 days
    fig.add_hline(
        y=30, line_dash="dash", line_color="#ffaa00",
        annotation_text="30-day warning",
        annotation_font=dict(size=10, color="#ffaa00"),
    )

    fig.add_hline(
        y=0, line_dash="solid", line_color="#ff003c",
        annotation_text="EXPIRED",
        annotation_font=dict(size=10, color="#ff003c"),
    )

    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter", color="#94a3b8"),
        xaxis=dict(
            tickangle=-45,
            tickfont=dict(size=9, family="JetBrains Mono"),
            gridcolor="rgba(30,41,59,0.3)",
        ),
        yaxis=dict(
            title=dict(text="Days Until Expiry", font=dict(size=11)),
            gridcolor="rgba(30,41,59,0.3)",
            zeroline=True,
            zerolinecolor="#ff003c",
        ),
        margin=dict(l=50, r=20, t=10, b=80),
        height=350,
        showlegend=False,
    )

    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False}, theme=None)


def _render_grade_distribution(df: pd.DataFrame) -> None:
    """Render the SSL grade distribution donut chart."""
    st.markdown("""
    <div class="glass-panel-header">
        METRIC: SSL GRADE DISTRIBUTION
    </div>
    """, unsafe_allow_html=True)

    grade_counts = df["Grade"].value_counts().reset_index()
    grade_counts.columns = ["Grade", "Count"]

    grade_colors = {
        "A+": "#00ff88",
        "A": "#00cc6a",
        "B": "#00f0ff",
        "C": "#ffaa00",
        "D": "#ff6b35",
        "F": "#ff003c",
        "?": "#64748b",
    }

    colors = [grade_colors.get(g, "#64748b") for g in grade_counts["Grade"]]

    fig = go.Figure(data=[go.Pie(
        labels=grade_counts["Grade"],
        values=grade_counts["Count"],
        hole=0.55,
        marker=dict(colors=colors, line=dict(color="#0a0e17", width=2)),
        textinfo="label+value",
        textfont=dict(family="Orbitron", size=12, color="#e2e8f0"),
        hovertemplate="Grade %{label}: %{value} domains<extra></extra>",
    )])

    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter", color="#94a3b8"),
        showlegend=True,
        legend=dict(
            font=dict(size=10, family="JetBrains Mono"),
            orientation="h",
            yanchor="bottom",
            y=-0.15,
            xanchor="center",
            x=0.5,
        ),
        margin=dict(l=20, r=20, t=10, b=40),
        height=350,
        annotations=[dict(
            text="SSL",
            x=0.5, y=0.5,
            font=dict(size=18, family="Orbitron", color="#00f0ff"),
            showarrow=False,
        )],
    )

    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False}, theme=None)
