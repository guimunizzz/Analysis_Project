"""
Centralized theme and styles for The Operator application.
This module contains all CSS styles used across the application for consistency.
"""

import base64
from pathlib import Path

def get_common_styles():
    """
    Returns the common CSS styles used across all pages.
    These styles are extracted from the IP Analysis page to maintain consistency.
    """
    return """
    <style>
    .stApp {
        background: radial-gradient(circle at top, #020617 0, #020617 55%);
        color: #f9fafb;  /* texto principal branco */
        font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }

    .main > div {
        padding-top: 1.5rem;
        padding-bottom: 2rem;
    }

    /* Shell principal de cada página */
    .page-shell {
        background: #020617;
        border-radius: 18px;
        border: 1px solid rgba(148, 163, 184, 0.35);
        box-shadow: 0 20px 45px rgba(15, 23, 42, 0.85);
        padding: 1.6rem 1.4rem 1.9rem;
        margin-bottom: 1.5rem;
    }

    .page-shell-header {
        display: flex;
        justify-content: space-between;
        align-items: baseline;
        gap: 0.75rem;
        flex-wrap: wrap;
        margin-bottom: 1rem;
    }

    .page-shell-title {
        font-size: 1.6rem;
        font-weight: 650;
        letter-spacing: -0.03em;
        display: flex;
        align-items: center;
        gap: 0.6rem;
        color: #f9fafb;  /* título branco */
    }

    .page-shell-subtitle {
        color: #e5e7eb;  /* subtítulo quase branco */
        font-size: 0.9rem;
    }

    .page-shell-badge {
        font-size: 0.68rem;
        padding: 0.2rem 0.7rem;
        border-radius: 999px;
        border: 1px solid rgba(148, 163, 184, 0.6);
        background: rgba(15, 23, 42, 0.96);
        color: #e5e7eb;
        text-transform: uppercase;
        letter-spacing: 0.15em;
    }

    /* Cards genéricos */
    .card-row {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
        gap: 0.85rem;
        margin-top: 1.1rem;
    }

    .card {
        background: #020617;
        border-radius: 14px;
        border: 1px solid rgba(148, 163, 184, 0.5);
        box-shadow: 0 12px 30px rgba(15, 23, 42, 0.9);
        padding: 0.9rem 1rem;
    }

    .card-muted {
        background: #020617;
        border-radius: 14px;
        border: 1px dashed rgba(148, 163, 184, 0.45);
        box-shadow: none;
        padding: 0.9rem 1rem;
    }

    .card-label {
        font-size: 0.78rem;
        text-transform: uppercase;
        letter-spacing: 0.16em;
        color: #cbd5f5;  /* label clara */
        margin-bottom: 0.3rem;
    }

    .card-value {
        font-size: 1.35rem;
        font-weight: 650;
        color: #ffffff;  /* valor branco */
    }

    .card-sub {
        font-size: 0.8rem;
        color: #e5e7eb;  /* subtítulo claro */
        margin-top: 0.25rem;
    }

    /* Status e badges */
    .status-ok   { color: #22c55e; }
    .status-warn { color: #facc15; }
    .status-bad  { color: #fca5a5; }

    .badge-soft {
        font-size: 0.72rem;
        padding: 0.15rem 0.6rem;
        border-radius: 999px;
        background: rgba(15,23,42,0.96);
        border: 1px solid rgba(148,163,184,0.5);
        color: #e5e7eb;
        display: inline-flex;
        align-items: center;
        gap: 0.3rem;
        margin-top: 0.35rem;
    }

    /* Sidebar Logo */
    .sidebar-logo-container {
        display: flex;
        justify-content: center;
        align-items: center;
        padding: 1.5rem 1rem 1rem;
        margin-bottom: 1rem;
        border-bottom: 1px solid rgba(148, 163, 184, 0.2);
    }

    .sidebar-logo-container img {
        max-width: 100%;
        height: auto;
        max-height: 60px;
    }

    /* Ajustes para métricas */
    .stMetric {
        background-color: #020617;
        border: 1px solid rgba(148, 163, 184, 0.5);
        border-radius: 14px;
        padding: 1rem;
        box-shadow: 0 12px 30px rgba(15, 23, 42, 0.9);
    }

    /* Botões secundários */
    .stButton>button[kind="secondary"] {
        border-radius: 999px !important;
        background: transparent !important;
        border: 1px solid rgba(148,163,184,0.5) !important;
        color: #e5e7eb !important;
        font-size: 0.85rem !important;
    }

    /* Input fields */
    .stTextInput>div>div>input {
        background-color: #020617;
        border: 1px solid rgba(148, 163, 184, 0.5);
        border-radius: 8px;
        color: #f9fafb;
    }

    .stTextInput>div>div>input:focus {
        border-color: #3b82f6;
        box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2);
    }
    </style>
    """


def get_sidebar_logo_html():
    """
    Returns the HTML for the sidebar logo.
    Supports SVG, PNG, JPG/JPEG and WEBP. Falls back to a built-in SVG if no file is found.
    This should be added at the top of the sidebar in all pages.
    """
    assets_dir = Path(__file__).parent.parent / "assets"

    # Candidate filenames in priority order
    candidates = [
        assets_dir / "NCTECH.png",
        assets_dir / "logo.svg",
        assets_dir / "logo.png",
        assets_dir / "logo.jpg",
        assets_dir / "logo.jpeg",
        assets_dir / "logo.webp",
    ]

    logo_src = None

    # Find first existing candidate and encode with correct mime
    for path in candidates:
        if path.exists():
            ext = path.suffix.lower()
            try:
                if ext == ".svg":
                    # SVG is text-based
                    with open(path, "r", encoding="utf-8") as f:
                        content = f.read()
                    b64 = base64.b64encode(content.encode("utf-8")).decode()
                    logo_src = f"data:image/svg+xml;base64,{b64}"
                else:
                    # Binary formats
                    with open(path, "rb") as f:
                        content = f.read()
                    b64 = base64.b64encode(content).decode()
                    mime = {
                        ".png": "image/png",
                        ".jpg": "image/jpeg",
                        ".jpeg": "image/jpeg",
                        ".webp": "image/webp",
                    }.get(ext, "application/octet-stream")
                    logo_src = f"data:{mime};base64,{b64}"
            except Exception:
                # If any error occurs reading/encoding, continue to next candidate
                logo_src = None
            finally:
                if logo_src:
                    break

    if not logo_src:
        # Fallback: use a simple logo matching the main design if file not found
        fallback_svg = '''<svg width="200" height="60" viewBox="0 0 200 60" xmlns="http://www.w3.org/2000/svg">
            <rect width="200" height="60" fill="none"/>
            <g id="shield">
                <path d="M 30 10 L 40 10 L 45 15 L 45 35 C 45 42 40 47 35 50 C 30 47 25 42 25 35 L 25 15 Z" 
                      fill="#3b82f6" stroke="#1e40af" stroke-width="1.5"/>
                <path d="M 30 18 L 35 24 L 42 16" 
                      stroke="#ffffff" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
            </g>
            <text x="55" y="28" font-family="system-ui, -apple-system, sans-serif" 
                  font-size="18" font-weight="700" fill="#f9fafb">
                The Operator
            </text>
            <text x="55" y="44" font-family="system-ui, -apple-system, sans-serif" 
                  font-size="10" font-weight="400" fill="#94a3b8" letter-spacing="1">
                THREAT INTELLIGENCE
            </text>
        </svg>'''
        b64 = base64.b64encode(fallback_svg.encode("utf-8")).decode()
        logo_src = f"data:image/svg+xml;base64,{b64}"

    return f"""
    <div class="sidebar-logo-container">
        <img src="{logo_src}" alt="The Operator Logo">
    </div>
    """
