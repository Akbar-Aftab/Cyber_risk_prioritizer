from sentence_transformers import SentenceTransformer

model = SentenceTransformer("all-MiniLM-L6-v2")

coordinates = model.encode("Fortinet VPN needs patching")

print("This sentence became a list of", len(coordinates), "numbers")
print("First 5 numbers:", coordinates[:5])