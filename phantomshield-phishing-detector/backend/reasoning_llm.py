from langchain_google_genai import ChatGoogleGenerativeAI
from dotenv import load_dotenv
import os

load_dotenv()

api_key = os.getenv("GOOGLE_API_KEY")
if not api_key:
    raise ValueError("GOOGLE_API_KEY not found in environment.")

llm = ChatGoogleGenerativeAI(
    model="gemini-2.5-flash",
    temperature=0.2,
    google_api_key=api_key
)

def generate_ai_reasoning(data):
    prompt = f"""
You are a cybersecurity analyst.

Explain clearly why this URL appears safe or unsafe.

Verdict: {data['verdict']}
Risk Score: {data['risk_score']}
Reasons: {data['reasons']}
Features: {data['features']}
Page Analysis: {data['page_analysis']}
"""

    try:
        response = llm.invoke(prompt)
        return response.content
    except Exception as e:
        return f"AI error: {str(e)}"