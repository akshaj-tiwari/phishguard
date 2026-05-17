from dotenv import load_dotenv
import os
import requests

load_dotenv()

api_key = os.getenv("VT_API_KEY")

url = "https://www.virustotal.com/api/v3/domains/google.com"

headers = {
    "x-apikey": api_key
}

response = requests.get(url, headers=headers)

print(response.status_code)
print(response.json())