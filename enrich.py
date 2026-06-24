# A machine with 4 flaws shows up on 4 rows 
# same asset info repeated, but a different flaw each time. 




import pandas as pd
vulns=pd.read_csv("Data/vulnerabilities.csv")
assets=pd.read_csv("Data/assets.csv")
threats=pd.read_csv("Data/threat_intelligence.csv")
service=pd.read_csv("Data/business_services.csv")

df=vulns.merge(assets,on="asset_id" , how="left")#each row should be a flaw so it should be on seperate rows flaws(vulnerabilites)
df=df.merge(service , on="business_service", how="left")#if we used how='inner' , flaw wud have been deleted for not matching and we wud loose the vulnerability 



threat_cves= threats.rename(columns={"matched_cve_or_control":"cve"})
df=df.merge(threat_cves[["cve" , "threat_actor" , "campaign_name" , "ransomware_association"]],on="cve",how="left")

print(df[df["vuln_id"] == "V-2015"].T.to_string(header=False))
print("\nTotal rows:", len(df))