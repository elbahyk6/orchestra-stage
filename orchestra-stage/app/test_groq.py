import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv('../.env')

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

prompt = """
Here are Nmap scan results:
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
443/tcp open https

Analyze these results and give me a security risk summary.
"""

response = client.chat.completions.create(
    model="llama-3.3-70b-versatile",
    messages=[{"role": "user", "content": prompt}]
)

print(response.choices[0].message.content)