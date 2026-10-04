"""
app.py
Streamlit dashboard for the AI SOC Analyst Lab.

Run with:
    streamlit run app.py
"""

import json

import streamlit as st

from triage_engine import Alert, triage_batch, correlate_by_host
from ai_analyst import explain_cluster, explain_alert, is_ollama_available, DEFAULT_MODEL

st.set_page_config(page_title="AI SOC Analyst Lab", page_icon="🛡️", layout="wide")

st.title("🛡️ AI SOC Analyst Lab")
st.caption(
    "Paste or upload raw security events (SIEM-style JSON). Rule-based triage maps each "
    "event to MITRE ATT&CK and correlates multi-stage attacks on the same host — all locally."
)

SAMPLES = {
    "Multi-stage attack chain (one host)": "sample_alerts/attack_chain.json",
    "Benign noise (should score low)": "sample_alerts/benign_noise.json",
    "Single ransomware-style spike": "sample_alerts/ransomware_spike.json",
}

severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
severity_color = {"Critical": "red", "High": "orange", "Medium": "blue", "Low": "gray", "Informational": "gray"}

# ---------------------------------------------------------------------------
# Input
# ---------------------------------------------------------------------------

col_a, col_b = st.columns([1, 1])
with col_a:
    sample_choice = st.selectbox("Load a sample alert set", ["— none —"] + list(SAMPLES.keys()))
with col_b:
    uploaded = st.file_uploader("...or upload your own alerts JSON", type=["json"])

raw_text = ""
if uploaded is not None:
    raw_text = uploaded.read().decode("utf-8")
elif sample_choice != "— none —":
    with open(SAMPLES[sample_choice]) as f:
        raw_text = f.read()

raw_text = st.text_area("Alerts JSON (list of events)", value=raw_text, height=220)

col_opt1, col_opt2, col_opt3 = st.columns([1, 1, 1])
with col_opt1:
    window = st.slider("Correlation window (minutes)", 5, 120, 30, step=5)
with col_opt2:
    use_ai = st.toggle("AI incident narrative (local Ollama)", value=False)
with col_opt3:
    model_name = st.text_input("Ollama model", value=DEFAULT_MODEL, disabled=not use_ai)

run = st.button("Run triage", type="primary", use_container_width=True)

# ---------------------------------------------------------------------------
# Triage
# ---------------------------------------------------------------------------

if run:
    if not raw_text.strip():
        st.warning("Paste alert JSON, upload a file, or pick a sample first.")
        st.stop()

    try:
        raw_alerts = json.loads(raw_text)
        alerts = [Alert.from_dict(a) for a in raw_alerts]
    except Exception as e:
        st.error(f"Couldn't parse alerts JSON: {e}")
        st.stop()

    results = triage_batch(alerts)
    results_sorted = sorted(results, key=lambda r: severity_order.get(r.severity, 9))
    clusters = correlate_by_host(results, window_minutes=window)
    multi_stage = [c for c in clusters if c.is_multi_stage]

    # --- summary metrics ---------------------------------------------------
    st.subheader("Summary")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Alerts processed", len(results))
    m2.metric("Matched a detection rule", sum(1 for r in results if r.matched))
    m3.metric("Critical / High", sum(1 for r in results if r.severity in ("Critical", "High")))
    m4.metric("Candidate multi-stage incidents", len(multi_stage))

    # --- multi-stage incident clusters --------------------------------------
    if multi_stage:
        st.subheader("🚨 Candidate incidents (multi-stage activity on one host)")
        for cluster in multi_stage:
            with st.container(border=True):
                st.markdown(f"**Host:** `{cluster.host}`  ·  **Techniques:** {', '.join(sorted(cluster.distinct_techniques))}")
                for r in cluster.triages:
                    for f in r.findings:
                        st.write(f"- `{r.alert.timestamp}` **{f.rule.mitre_id}** ({f.rule.mitre_name}) — {f.rule.name}")
                        st.caption(f"  ↳ Recommended action: {f.rule.recommended_action}")

                if use_ai:
                    if not is_ollama_available():
                        st.info(
                            f"Ollama not reachable on localhost:11434. Install from https://ollama.com "
                            f"and `ollama pull {model_name}` to enable AI narratives."
                        )
                    else:
                        with st.spinner("Drafting analyst narrative..."):
                            try:
                                narrative = explain_cluster(cluster, model=model_name)
                                st.markdown("**AI analyst narrative:**")
                                st.write(narrative)
                            except RuntimeError as e:
                                st.error(str(e))
    else:
        st.info("No multi-stage incident detected at this correlation window — see individual alerts below.")

    # --- per-alert table -----------------------------------------------------
    st.subheader("All alerts")
    for r in results_sorted:
        if not r.matched:
            continue
        color = severity_color.get(r.severity, "gray")
        with st.expander(f":{color}[{r.severity}]  ·  {r.alert.id}  ·  {r.alert.host}  ·  {r.alert.event_type}"):
            st.write(f"**User:** {r.alert.user}  ·  **Time:** {r.alert.timestamp}  ·  **Score:** {r.score}/100")
            for f in r.findings:
                st.write(f"- **{f.rule.mitre_id}** ({f.rule.mitre_name}): {f.rule.name}")
                st.caption(f"  ↳ {f.rule.recommended_action}")
            st.json(r.alert.details)

            if use_ai and is_ollama_available():
                if st.button("Explain this alert", key=f"explain-{r.alert.id}"):
                    with st.spinner("Asking local model..."):
                        try:
                            st.write(explain_alert(r, model=model_name))
                        except RuntimeError as e:
                            st.error(str(e))

    unmatched = [r for r in results if not r.matched]
    if unmatched:
        with st.expander(f"No rule matched ({len(unmatched)} alerts)"):
            for r in unmatched:
                st.write(f"- {r.alert.id} · {r.alert.host} · {r.alert.event_type}")
