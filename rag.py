import pandas as pd
from sentence_transformers import SentenceTransformer, util
#This reaches into the embedding library you installed and grabs two specific tools out of it:
#SentenceTransformer — the embedding model itself (the thing that turns text into coordinates).
#util — a helper bundle that contains the "measure closeness" function we'll use.
controls = pd.read_csv("data/nist_controls.csv")
print("loading model...")
model = SentenceTransformer("all-MiniLM-L6-v2")

control_vectors=model.encode(controls["text"].tolist())
#model.encode(controls["text"].tolist())
#so the order is , first you take the text column , convert it into a list because .encode wants a simple list , and .encode converts each of these controls into 384 coordinates and control_vector stores the result


def find_best_control(risk_text):
    risk_vector=model.encode(risk_text)
    similarity=util.cos_sim(risk_vector,control_vectors)[0]
    best=similarity.argmax().item()
    return controls.iloc[best]

risk = "Fortinet SSL-VPN unpatched remote code execution, exploit available, needs patching"
match = find_best_control(risk) # now match is the winning control row
print("risk:", risk )
print(f"Best NIST match: " , match["control_id"] , "-" , match["title"])


