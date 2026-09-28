"""
.GO.KE Cyber-Surface Radar — Threat Feed Component
=====================================================
Renders a real-time scrolling threat feed in terminal style,
showing classified threats as they're detected.
"""

import streamlit as st
from typing import Any, Dict, List

from config import RiskLevel


def render_threat_feed(threats: List[Dict[str, Any]], max_items: int = 50) -> None:
    """
    Render a terminal-style live threat feed.

    Args:
        threats: List of classified threat objects
        max_items: Maximum number of items to display
    """
    # Panel header
    st.markdown("""
    <div class="glass-panel-header">
        <span class="pulse-dot"></span>
        LIVE THREAT FEED
    </div>
    """, unsafe_allow_html=True)

    if not threats:
        st.markdown("""
        <div class="threat-feed">
            <div style="
                text-align: center;
                color: var(--text-muted);
                padding: 40px 20px;
                font-family: 'JetBrains Mono', monospace;
                font-size: 0.8rem;
            ">
                <div style="font-size: 2rem; margin-bottom: 12px;">[•]</div>
                Awaiting scan data...<br>
                <span style="font-size: 0.7rem; opacity: 0.6;">
                    Launch a scan or enable demo mode
                </span>
            </div>
        </div>
        """, unsafe_allow_html=True)
        return

    # Build feed items HTML
    feed_items = []
    display_threats = threats[:max_items]

    for threat in display_threats:
        level = threat.get("level", "INFO").lower()
        timestamp = threat.get("timestamp", "")
        domain = threat.get("domain", "unknown")
        title = threat.get("title", "Unknown Threat")
        detail = threat.get("detail", "")
        icon = threat.get("icon", "[!]")

        # Truncate timestamp for display
        time_short = timestamp.split(" ")[1] if " " in timestamp else timestamp[:8]

        item_html = f"""
        <div class="threat-item {level}">
            <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                <div style="flex: 1;">
                    <span class="threat-timestamp">{time_short}</span>
                    <span class="threat-badge badge-{level}">{threat.get('level', 'INFO')}</span>
                    <span style="margin-left: 2px;">{icon}</span>
                </div>
            </div>
            <div style="margin-top: 4px;">
                <strong style="color: #e2e8f0; font-size: 0.75rem;">{domain}</strong>
                <span style="color: #94a3b8; font-size: 0.72rem;"> — {title}</span>
            </div>
            <div style="color: #64748b; font-size: 0.68rem; margin-top: 2px;">
                {detail}
            </div>
        </div>
        """
        feed_items.append(item_html)

    # Feed summary bar
    critical = sum(1 for t in threats if t.get("level") == "CRITICAL")
    high = sum(1 for t in threats if t.get("level") == "HIGH")
    medium = sum(1 for t in threats if t.get("level") == "MEDIUM")

    summary_html = f"""
    <div style="
        display: flex;
        gap: 12px;
        padding: 8px 12px;
        margin-bottom: 8px;
        background: rgba(10, 14, 23, 0.6);
        border-radius: 6px;
        border: 1px solid #1e293b;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.68rem;
    ">
        <span style="color: #64748b;">TOTAL: <strong style="color: #e2e8f0;">{len(threats)}</strong></span>
        <span style="color: #ff003c;">CRIT: <strong>{critical}</strong></span>
        <span style="color: #ff6b35;">HIGH: <strong>{high}</strong></span>
        <span style="color: #ffaa00;">MED: <strong>{medium}</strong></span>
    </div>
    """

    # Combine into scrollable feed
    all_items_html = "\n".join(feed_items)

    st.markdown(f"""
    {summary_html}
    <div class="threat-feed">
        {all_items_html}
    </div>
    """, unsafe_allow_html=True)


def render_threat_detail(threat: Dict[str, Any]) -> None:
    """Render a detailed view of a single threat with remediation."""
    level = threat.get("level", "INFO")
    color = threat.get("color", "#64748b")

    st.markdown(f"""
    <div style="
        background: #0f1923;
        border: 1px solid {color}33;
        border-left: 4px solid {color};
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 12px;
    ">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <span style="
                font-family: 'Inter', sans-serif;
                font-weight: 600;
                font-size: 0.9rem;
                color: #e2e8f0;
            ">{threat.get('icon', '[!]')} {threat.get('title', 'Unknown')}</span>
            <span class="threat-badge badge-{level.lower()}">{level}</span>
        </div>

        <div style="
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            color: #94a3b8;
            margin-bottom: 8px;
        ">
            <strong style="color: #00f0ff;">{threat.get('domain', 'unknown')}</strong>
            — {threat.get('ministry', 'Unknown Ministry')}
        </div>

        <div style="
            font-family: 'Inter', sans-serif;
            font-size: 0.8rem;
            color: #94a3b8;
            margin-bottom: 12px;
        ">{threat.get('detail', '')}</div>

        <div style="
            background: rgba(0, 240, 255, 0.05);
            border: 1px solid rgba(0, 240, 255, 0.1);
            border-radius: 6px;
            padding: 10px 12px;
            font-family: 'Inter', sans-serif;
            font-size: 0.75rem;
            color: #00f0ff;
        ">
            <strong>[i] Remediation:</strong> {threat.get('remediation', 'Review and remediate.')}
        </div>
    </div>
    """, unsafe_allow_html=True)
