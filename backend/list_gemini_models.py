import google.generativeai as genai
import os
from dotenv import load_dotenv

# Try to load from .env if it exists
load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    # Fallback to check if it's in environment already
    api_key = os.environ.get("GEMINI_API_KEY")

if not api_key:
    print("Error: GEMINI_API_KEY not found in environment or .env file.")
else:
    try:
        genai.configure(api_key=api_key)
        print("Available models supporting generateContent:")
        for m in genai.list_models():
            if 'generateContent' in m.supported_generation_methods:
                print(f"- {m.name}")
    except Exception as e:
        print(f"Error listing models: {e}")
