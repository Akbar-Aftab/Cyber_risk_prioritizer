import os
from dotenv import load_dotenv
from groq import Groq

load_dotenv()
client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

risk_facts = "Risk: Fortinet SSL-VPN unpatched remote code execution. Internet-facing, Critical asset, no EDR, tied to an active ransomware campaign (CrimsonJackal). Risk score 99.6/100."

nist_control = "SI-2 Flaw Remediation. Identify, report, and correct system flaws; test software and firmware updates before installing; install security-relevant updates within the organisation-defined time period."
prompt = f"""You are a cybersecurity analyst writing for a non-technical manager.

Using ONLY the information below, write a short 3 sentence brief explaining:
1. why this risk is urgent, and
2. what to do about it, based on the NIST guidance.
please dont invent any facts beyond what is provided.

RISK DETAILS:
{risk_facts}

OFFICIAL NIST GUIDANCE TO BASE THE FIX ON:
{nist_control}
"""
response = client.chat.completions.create(
    model="llama-3.3-70b-versatile",
    messages=[{"role": "user", "content": prompt}]
)

print(response.choices[0].message.content)

