#the PHP flaw, V-2047 - Its CVE is CVE-2024-4577. When we did the third merge (stapling on threat info), we hit a problem: that one CVE appears in the threat feed twice, because two different attacker groups are using it:
##CVE-2024-4577 → AmberFox  / "HR Data Theft"
#CVE-2024-4577 → GrayLotus / "CMS Spray"
#Merge couldn't fit two campaigns onto one row, so it split V-2047 into two rows — one for each campaign:
#Our whole goal is to rank 114 flaws and pick the worst 5. But if one flaw secretly sits in the table twice, two bad things happen:
#It could hog two spots in the top 5. IF V-2047 is dangerous and scores high it could appear at both rank #3 and rank #4, pushing a genuinely different flaw out of the list misleading.
import pandas as pd
vulns    = pd.read_csv("data/vulnerabilities.csv")
assets   = pd.read_csv("data/assets.csv")
threats  = pd.read_csv("data/threat_intelligence.csv")
services = pd.read_csv("data/business_services.csv")

df = vulns.merge(assets, on="asset_id", how="left")
df = df.merge(services, on="business_service", how="left")
threat_cves = threats.rename(columns={"matched_cve_or_control": "cve"})
df = df.merge(threat_cves[["cve", "threat_actor", "campaign_name", "ransomware_association"]],
              on="cve", how="left")



df["is_ransomware"]=(df["ransomware_association"]=="Yes")
df=df.sort_values("is_ransomware",ascending=False).drop_duplicates("vuln_id")

#ranking should be of the order Internet exposure → 2. Active exploitation → 3. Ransomware → 4. Business criticality → 5. Missing controls
#Internet exposure: 20 (rank 1)
#Active exploitation: 20 (rank 2)
#Ransomware: 15 (rank 3)
#Criticality: up to 15 (rank 4)
#Missing EDR: 10 (rank 5)

def score(row):
    points=0
    points+=row["cvss"]*2
    if row["internet_exposed"]=="Yes":
        points+=20
    if row["exploit_available"]=="Yes":
        points+=20
    if row["is_ransomware"]:
        points+=15
    points+={"Critical":15 , "High":10 , "Medium":5 , "Low":0}.get(row["criticality"],0)
    if row["edr_installed"] == "No":
        points += 10
    return round(points, 1)

df["risk_score"] = df.apply(score, axis=1)
df = df.sort_values("risk_score", ascending=False)
top5 = df.head(5)
print(top5[["vuln_id", "vulnerability_name", "asset_name", "risk_score"]].to_string(index=False))
