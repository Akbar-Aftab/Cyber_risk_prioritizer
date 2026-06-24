import os
from dotenv import load_dotenv
from groq import Groq

# read the key out of your .env file
load_dotenv()
client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

# send one simple message to the AI
response = client.chat.completions.create(
    model="llama-3.3-70b-versatile",
    messages=[{"role": "user", "content": "Say hello in one short sentence."}]
)

# print what the AI replied
print(response.choices[0].message.content)
