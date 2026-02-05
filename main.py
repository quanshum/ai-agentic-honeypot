import os
import json
from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel
from openai import OpenAI

# -------------------------------
# FastAPI App
# -------------------------------
app = FastAPI()

# -------------------------------
# Environment Variables
# -------------------------------
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
API_KEY = os.getenv("API_KEY")

if not OPENAI_API_KEY:
    raise ValueError("OPENAI_API_KEY is missing")
if not API_KEY:
    raise ValueError("API_KEY is missing")

client = OpenAI(api_key=OPENAI_API_KEY)

# -------------------------------
# Request Schema (matches their sample)
# -------------------------------
class Message(BaseModel):
    sender: str
    text: str
    timestamp: int

class ScamRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: list = []
    metadata: dict = {}

# -------------------------------
# Authentication
# -------------------------------
def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

# -------------------------------
# Scam Detection Endpoint
# -------------------------------
@app.post("/detect")
def detect_scam(request: ScamRequest, _: str = Depends(verify_api_key)):
    try:
        user_message = request.message.text

        # -------------------------------
        # Call OpenAI
        # -------------------------------
        prompt = f"""
You are a scam detection engine.

Analyze the following message and respond ONLY with a short reply to simulate a victim's response:

Message:
{user_message}
"""
        response = client.chat.completions.create(
            model="gpt-5-mini",
            messages=[{"role": "user", "content": prompt}],
            max_completion_tokens=100  # Use max_completion_tokens for gpt-5-mini
        )

        ai_reply = response.choices[0].message.content.strip()

        # -------------------------------
        # Return the exact JSON they expect
        # -------------------------------
        return {
            "status": "success",
            "reply": ai_reply
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
