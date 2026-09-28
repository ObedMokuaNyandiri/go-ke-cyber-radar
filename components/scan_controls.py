"""
.GO.KE Cyber-Surface Radar — Scan Controls Component
======================================================
Sidebar scan controls for configuring and launching scans,
with Shodan API key input and demo mode toggle.
"""

import streamlit as st
from typing import Optional

from config import APP_TITLE, APP_ICON, APP_VERSION, SHODAN_API_KEY


def render_sidebar_controls() -> dict:
    """
    Render the sidebar control panel and return user selections.

    Returns:
        Dict with keys: demo_mode, shodan_key, start_scan, selected_domains
    """
    result = {
        "demo_mode": True,
        "shodan_key": "",
        "start_scan": False,
    }

    # ── Logo & Branding ───────────────────────────────────────────────────
    st.sidebar.markdown(f"""
    <div style="text-align: center; padding: 16px 0 8px 0;">
        <div style="font-size: 2.5rem; margin-bottom: 4px;">[•]</div>
        <div style="
            font-family: 'Orbitron', sans-serif;
            font-size: 0.9rem;
            font-weight: 700;
            color: #00f0ff;
            text-shadow: 0 0 20px rgba(0,240,255,0.3);
            letter-spacing: 2px;
        ">.GO.KE RADAR</div>
        <div style="
            font-family: 'Inter', sans-serif;
            font-size: 0.65rem;
            color: #64748b;
            letter-spacing: 2px;
            text-transform: uppercase;
        ">Cyber-Surface Intelligence</div>
        <div style="
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.6rem;
            color: #1e293b;
            margin-top: 4px;
        ">v{APP_VERSION}</div>
    </div>
    """, unsafe_allow_html=True)

    st.sidebar.markdown("---")

    # ── Mode Selection ────────────────────────────────────────────────────
    st.sidebar.markdown("""
    <div style="
        font-family: 'Orbitron', sans-serif;
        font-size: 0.7rem;
        color: #00f0ff;
        text-transform: uppercase;
        letter-spacing: 2px;
        margin-bottom: 8px;
    ">CONFIG: Scan Mode</div>
    """, unsafe_allow_html=True)

    demo_mode = st.sidebar.toggle("Demo Mode", value=True, help="Use simulated scan data for demonstration")
    result["demo_mode"] = demo_mode

    if demo_mode:
        pass
    else:
        # ── Shodan API Key ────────────────────────────────────────────────
        if SHODAN_API_KEY:
            result["shodan_key"] = SHODAN_API_KEY
        else:
            st.sidebar.markdown("<br>", unsafe_allow_html=True)
            st.sidebar.markdown("""
            <div style="
                font-family: 'Orbitron', sans-serif;
                font-size: 0.7rem;
                color: #00f0ff;
                text-transform: uppercase;
                letter-spacing: 2px;
                margin-bottom: 8px;
            ">AUTH: API Configuration</div>
            """, unsafe_allow_html=True)

            shodan_key = st.sidebar.text_input(
                "Shodan API Key",
                value="",
                type="password",
                placeholder="Enter your Shodan API key",
                help="Get a free key at shodan.io",
            )
            result["shodan_key"] = shodan_key

            if not shodan_key:
                st.sidebar.markdown("""
                <div style="
                    font-family: 'Inter', sans-serif;
                    font-size: 0.72rem;
                    color: #ffaa00;
                    background: rgba(255, 170, 0, 0.05);
                    border: 1px solid rgba(255, 170, 0, 0.1);
                    border-radius: 8px;
                    padding: 10px 12px;
                ">
                    [!] Without a Shodan API key, only SSL, DNS, and HTTP header
                    analysis will be performed. Port/service detection requires Shodan.
                </div>
                """, unsafe_allow_html=True)

    st.sidebar.markdown("---")

    # ── Scan Controls ─────────────────────────────────────────────────────
    st.sidebar.markdown("""
    <div style="
        font-family: 'Orbitron', sans-serif;
        font-size: 0.7rem;
        color: #00f0ff;
        text-transform: uppercase;
        letter-spacing: 2px;
        margin-bottom: 8px;
    ">SYS: Controls</div>
    """, unsafe_allow_html=True)

    if demo_mode:
        start = st.sidebar.button("LOAD DEMO DATA", use_container_width=True)
    else:
        start = st.sidebar.button("LAUNCH SCAN", use_container_width=True)

    result["start_scan"] = start

    st.sidebar.markdown("---")

    # ── About Section ─────────────────────────────────────────────────────
    with st.sidebar.expander("System Info"):
        st.markdown("""
        **`.GO.KE Cyber-Surface Radar`** maps the cyber-attack surface
        of Kenya's government infrastructure using passive reconnaissance.

        **Data Sources:**
        - SSL/TLS certificate inspection
        - DNS record enumeration
        - HTTP security header analysis
        - Shodan passive index (optional)

        **Ethical Notice:**
        This tool performs **passive reconnaissance only**.
        No active exploitation, port scanning, or vulnerability
        testing is conducted.

        Built with Python, Streamlit, and Plotly.
        """)

    # ── Disclaimer ────────────────────────────────────────────────────────
    st.sidebar.markdown("""
    <div style="
        font-family: 'Inter', sans-serif;
        font-size: 0.6rem;
        color: #334155;
        text-align: center;
        padding: 8px;
        margin-top: 16px;
    ">
        Passive reconnaissance only.<br>
        For authorized security research.<br>
        © 2026 Cyber-Surface Radar
    </div>
    """, unsafe_allow_html=True)

    return result
