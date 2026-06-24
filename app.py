import os
import pandas as pd
import streamlit as st
from dotenv import load_dotenv
from groq import Groq
from sentence_transformers import SentenceTransformer, util

st.set_page_config(page_title="Cyber Risk Prioritiser", page_icon="🛡️", layout="wide")
st.title("🛡️ AI Cyber Risk Prioritisation Engine")
st.caption("Ranks vulnerabilities by real-world risk, then retrieves NIST 800-53 remediation via RAG.")

# ---------- load + cache the heavy stuff ONCE ----------
@st.cache_resource
def load_everything():
    vulns    = pd.read_csv("data/vulnerabilities.csv")
    assets   = pd.read_csv("data/assets.csv")
    threats  = pd.read_csv("data/threat_intelligence.csv")
    services = pd.read_csv("data/business_services.csv")
    controls = pd.read_csv("data/nist_controls.csv")
    model = SentenceTransformer("all-MiniLM-L6-v2")
    control_vectors = model.encode(controls["text"].tolist())
    return vulns, assets, threats, services, controls, model, control_vectors

vulns, assets, threats, services, controls, model, control_vectors = load_everything()

# ---------- scoring ----------
def build_scored_table():
    df = vulns.merge(assets, on="asset_id", how="left")
    df = df.merge(services, on="business_service", how="left")
    threat_cves = threats.rename(columns={"matched_cve_or_control": "cve"})
    df = df.merge(threat_cves[["cve","threat_actor","campaign_name","ransomware_association"]], on="cve", how="left")
    df["is_ransomware"] = (df["ransomware_association"] == "Yes")
    df = df.sort_values("is_ransomware", ascending=False).drop_duplicates("vuln_id")

    def score(row):
        points = row["cvss"] * 2
        if row["internet_exposed"] == "Yes": points += 20
        if row["exploit_available"] == "Yes": points += 20
        if row["is_ransomware"]: points += 15
        points += {"Critical":15,"High":10,"Medium":5,"Low":0}.get(row["criticality"],0)
        if row["edr_installed"] == "No": points += 10
        return round(points, 1)

    df["risk_score"] = df.apply(score, axis=1)
    return df.sort_values("risk_score", ascending=False)

def find_best_control(risk_text):
    risk_vector = model.encode(risk_text)
    similarity = util.cos_sim(risk_vector, control_vectors)[0]
    top3 = similarity.argsort(descending=True)[:3]
    return controls.iloc[[int(i) for i in top3]]

# ---------- the button ----------
load_dotenv()
client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

if st.button("⚡ Analyse Top 5 Risks", type="primary"):
    top5 = build_scored_table().head(5)

    for rank, (_, row) in enumerate(top5.iterrows(), start=1):
        risk_text = (f"Unpatched {row['affected_component']} vulnerability requiring "
                     f"flaw remediation, software patching, and vulnerability monitoring. "
                     f"{row['vulnerability_name']}. Remote exploitation of a known CVE.")
        matches = find_best_control(risk_text)
        top_control = matches.iloc[0]
        options = "; ".join(f"{c['control_id']} {c['title']}" for _, c in matches.iterrows())

        prompt = f"""You are a cybersecurity analyst writing for a non-technical manager.
Using ONLY the information below, write a 3-sentence brief: why this risk is urgent, and what to do based on the NIST guidance. Do not invent facts.

RISK: {row['vulnerability_name']} on {row['asset_name']}, CVSS {row['cvss']}, internet-facing, {'ransomware-linked' if row['is_ransomware'] else 'actively exploited'}, score {row['risk_score']}/100.

NIST GUIDANCE: {top_control['control_id']} - {top_control['title']}. {top_control['text'][:400]}
"""
        brief = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}]
        ).choices[0].message.content

        with st.container(border=True):
            st.subheader(f"#{rank}  {row['vulnerability_name']}")
            c1, c2, c3 = st.columns(3)
            c1.metric("Risk Score", f"{row['risk_score']}/100")
            c2.metric("Asset", row['asset_name'])
            c3.metric("Top NIST Control", top_control['control_id'])
            st.write(brief)
            st.caption(f"RAG candidates: {options}")