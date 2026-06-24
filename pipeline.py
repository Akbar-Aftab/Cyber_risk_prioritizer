import os
import pandas as pd
from dotenv import load_dotenv
from groq import Groq
from sentence_transformers import SentenceTransformer, util

# ===== PART A: SCORING (your score.py) =====
vulns    = pd.read_csv("data/vulnerabilities.csv")
assets   = pd.read_csv("data/assets.csv")
threats  = pd.read_csv("data/threat_intelligence.csv")
services = pd.read_csv("data/business_services.csv")

df = vulns.merge(assets, on="asset_id", how="left")
df = df.merge(services, on="business_service", how="left")
threat_cves = threats.rename(columns={"matched_cve_or_control": "cve"})
df = df.merge(threat_cves[["cve", "threat_actor", "campaign_name", "ransomware_association"]], on="cve", how="left")

df["is_ransomware"] = (df["ransomware_association"] == "Yes")
df = df.sort_values("is_ransomware", ascending=False).drop_duplicates("vuln_id")

def score(row):
    points = 0
    points += row["cvss"] * 2
    if row["internet_exposed"] == "Yes": points += 20
    if row["exploit_available"] == "Yes": points += 20
    if row["is_ransomware"]: points += 15
    points += {"Critical": 15, "High": 10, "Medium": 5, "Low": 0}.get(row["criticality"], 0)
    if row["edr_installed"] == "No": points += 10
    return round(points, 1)

df["risk_score"] = df.apply(score, axis=1)
df = df.sort_values("risk_score", ascending=False)
top5 = df.head(5)

# ===== PART B: RAG SETUP (your rag.py) =====
print("loading model + embedding NIST controls...")
controls = pd.read_csv("data/nist_controls.csv")
model = SentenceTransformer("all-MiniLM-L6-v2")
control_vectors = model.encode(controls["text"].tolist())

def find_best_control(risk_text):
    risk_vector = model.encode(risk_text)
    similarity = util.cos_sim(risk_vector, control_vectors)[0]
    top3=similarity.argsort(descending=True)[:3]

   
    return controls.iloc[[int(i) for i in top3]]

# ===== PART C: LLM SETUP (your explain.py) =====
load_dotenv()
client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

# ===== PART D: THE LOOP =====
print("\n" + "=" * 60)
print("TOP 5 CYBER RISKS — PRIORITISED BRIEF")
print("=" * 60)

rank = 1
for i, row in top5.iterrows():
    edr_note = "no endpoint detection (EDR) installed" if row['edr_installed'] == "No" else "EDR installed"
    risk_text = (f"Unpatched {row['affected_component']} vulnerability requiring "
                 f"flaw remediation, software patching, and vulnerability monitoring. "
                 f"{row['vulnerability_name']}. Remote exploitation of a known CVE.")

    control = find_best_control(risk_text)
   
    matches = find_best_control(risk_text)
    top_control = matches.iloc[0]
    options_text = "; ".join(f"{c['control_id']} {c['title']}" for _, c in matches.iterrows())

    prompt = f"""You are a cybersecurity analyst writing for a non-technical manager.
Using ONLY the information below, write a 3-sentence brief: why this risk is urgent, and what to do based on the NIST guidance. Do not invent facts.

RISK: {row['vulnerability_name']} on {row['asset_name']}, CVSS {row['cvss']}, internet-facing, {'ransomware-linked' if row['is_ransomware'] else 'actively exploited'}, score {row['risk_score']}/100.

NIST GUIDANCE: {top_control['control_id']} - {top_control['title']}. {top_control['text'][:400]}
"""
    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}]
    )

    print(f"\n--- RANK {rank}: {row['vulnerability_name']} (score {row['risk_score']}) ---")
    print(f"Asset: {row['asset_name']}")
    print(f"NIST candidates: {options_text}")
    print(response.choices[0].message.content)
    rank += 1
   