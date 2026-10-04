"""
app.py
Streamlit front-end for the AI Phishing Email Analyzer.

Run with:
    streamlit run app.py
"""

import email
from email import policy

import streamlit as st

from detector import analyze_email
from ai_explainer import explain_with_ollama, is_ollama_available, DEFAULT_MODEL

st.set_page_config(page_title="AI Phishing Email Analyzer", page_icon="🎣", layout="wide")

st.title("🎣 AI Phishing Email Analyzer")
st.caption("Paste an email or upload a .eml file. Detection runs locally — no data leaves your machine.")

# ---------------------------------------------------------------------------
# Input
# ---------------------------------------------------------------------------

col_input, col_meta = st.columns([2, 1])

with col_input:
    uploaded = st.file_uploader("Upload a .eml file (optional)", type=["eml", "txt"])

    body_text = ""
    subject = ""
    sender = ""
    display_name = ""

    if uploaded is not None:
        raw = uploaded.read().decode("utf-8", errors="ignore")
        msg = email.message_from_string(raw, policy=policy.default)
        subject = msg.get("Subject", "") or ""
        from_header = msg.get("From", "") or ""
        if "<" in from_header and ">" in from_header:
            display_name = from_header.split("<")[0].strip().strip('"')
            sender = from_header.split("<")[1].split(">")[0].strip()
        else:
            sender = from_header.strip()
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body_text = part.get_content()
                    break
        else:
            body_text = msg.get_content()

    body_text = st.text_area("Email body", value=body_text, height=300,
                              placeholder="Paste the email text here...")

with col_meta:
    subject = st.text_input("Subject (optional)", value=subject)
    display_name = st.text_input("Sender display name (optional)", value=display_name,
                                  placeholder='e.g. "PayPal Support"')
    sender = st.text_input("Sender email address (optional)", value=sender,
                            placeholder="e.g. service@paypa1-secure.com")

    st.divider()
    use_ai = st.toggle("Add AI explanation (local Ollama)", value=False)
    model_name = st.text_input("Ollama model", value=DEFAULT_MODEL, disabled=not use_ai)

run = st.button("Analyze", type="primary", use_container_width=True)

# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

if run:
    if not body_text.strip():
        st.warning("Paste an email body or upload a .eml file first.")
        st.stop()

    result = analyze_email(body_text, sender=sender, display_name=display_name, subject=subject)

    risk_colors = {"Low": "green", "Medium": "orange", "High": "red", "Critical": "red"}
    color = risk_colors.get(result.risk_level, "gray")

    st.subheader("Result")
    c1, c2 = st.columns([1, 2])
    with c1:
        st.metric("Risk score", f"{result.score}/100")
        st.markdown(f"**Risk level:** :{color}[{result.risk_level}]")
    with c2:
        st.progress(result.score / 100)

    st.subheader("Matched indicators")
    matched = result.matched_indicators()
    if not matched:
        st.success("No suspicious indicators detected by the heuristics.")
    else:
        for ind in matched:
            with st.expander(f"⚠️ {ind.name}  (+{ind.weight})"):
                st.write(ind.description)
                if ind.evidence:
                    st.code("\n".join(ind.evidence))

    with st.expander("All checks performed"):
        for ind in result.indicators:
            mark = "✅ matched" if ind.matched else "— no match"
            st.write(f"**{ind.name}** — {mark}")

    if result.links:
        st.subheader("Links found")
        for link in result.links:
            st.code(link)

    if use_ai:
        st.subheader("AI explanation")
        if not is_ollama_available():
            st.info(
                "Ollama doesn't seem to be running on localhost:11434. "
                "Install it from https://ollama.com and run `ollama pull "
                f"{model_name}` to enable this feature."
            )
        else:
            with st.spinner("Asking local model for an explanation..."):
                try:
                    explanation = explain_with_ollama(result, body_text, model=model_name)
                    st.write(explanation)
                except RuntimeError as e:
                    st.error(str(e))
