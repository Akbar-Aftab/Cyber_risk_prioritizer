import pandas as pd
assets=pd.read_csv("Data/assets.csv")#this means in the data folder open a file assets.csv , means go open the assets file
vulns=pd.read_csv("Data/vulnerabilities.csv")
threats=pd.read_csv("Data/threat_intelligence.csv")

print(f"assets:                ",len(assets)," rows")
print(f"Vulnerabilities:        ",len(vulns), " rows")
print(f"Threat intel:           ",len(threats), " rows")
