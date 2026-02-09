import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()
api_key = os.getenv('OPENAI_API_KEY')

print(f"API Key found: {'Yes' if api_key else 'No'}")
if api_key:
    # Safely print prefix
    print(f"Key prefix: {api_key[:10]}...")

try:
    client = OpenAI(api_key=api_key)
    print("Sending moderation request...")
    response = client.moderations.create(input="I want to kill someone.")
    print(f"Flagged: {response.results[0].flagged}")
    print("Full response results:")
    for result in response.results:
        print(result)
except Exception as e:
    print(f"Error: {e}")
