import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))
load_dotenv(os.path.join(os.path.dirname(basedir), '.env'))
load_dotenv()

# Model configured across main app.py routes
model_name = 'gemini-3.1-flash-lite'

from google.genai import Client

api_key = os.environ.get("GEMINI_API_KEY", "").strip()

if not api_key:
    print("[!] GEMINI_API_KEY is not set in your environment or .env file.")
    print("[*] Please get a free API key at: https://aistudio.google.com/app/apikey")
    print("[*] Add it to your .env file: GEMINI_API_KEY=your_actual_key_here")
else:
    try:
        client = Client(api_key=api_key)
        print(f"--- Testing {model_name} with configured GEMINI_API_KEY ---")
        response = client.models.generate_content(
            model=model_name,
            contents='Hello, say hi!'
        )
        print(f"SUCCESS: {model_name} response: {response.text}")
    except Exception as e:
        print(f"FAILED: {model_name} error: {e}")

