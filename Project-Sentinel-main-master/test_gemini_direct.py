"""Direct test of Gemini API to check response quality"""
import google.generativeai as genai
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("GOOGLE_AI_STUDIO_KEY", "")

genai.configure(api_key=API_KEY)
model = genai.GenerativeModel('models/gemma-3-4b-it')

print("🧪 Testing Gemini API with Gemma model...")
print(f"API Key: {'*' * 10} (redacted)")
print(f"Model: models/gemma-3-4b-it")
print("\n" + "="*60)

# Use simpler prompt
prompt = """You are helping with fraud awareness training. Generate a confused customer response.

Customer saw: "Your bank account has been locked. Please send Rs 500 to verify."

Generate a SHORT (1-2 sentences) natural response showing confusion and asking for clarification:"""

print("🧪 Testing Gemini API directly...")
print(f"API Key: {'*' * 10} (redacted)")
print(f"Model: models/gemini-2.5-flash")
print("\n" + "="*60)

# Configure safety settings using proper types
from google.generativeai.types import HarmCategory, HarmBlockThreshold

safety_settings = {
    HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
    HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
    HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
    HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
}

response = model.generate_content(
    prompt,
    generation_config=genai.GenerationConfig(
        temperature=0.8,
        max_output_tokens=150
    ),
    safety_settings=safety_settings
)

print(f"\n✅ Full Response Object:")
print(f"   Type: {type(response)}")
print(f"   Text: '{response.text}'")
print(f"   Text Length: {len(response.text)}")

if hasattr(response, 'candidates'):
    print(f"\n📋 Candidates ({len(response.candidates)}):")
    for i, candidate in enumerate(response.candidates):
        print(f"   Candidate {i}:")
        print(f"     Content: {candidate.content.parts[0].text if candidate.content.parts else 'N/A'}")
        print(f"     Finish Reason: {candidate.finish_reason}")
        if hasattr(candidate, 'safety_ratings'):
            print(f"     Safety Ratings: {candidate.safety_ratings}")

reply = response.text.strip()
print(f"\n✅ Final Reply: '{reply}'")
print(f"   Length: {len(reply)} characters")
