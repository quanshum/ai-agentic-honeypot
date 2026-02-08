import os
import json
import re
from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel
from sqlalchemy.orm import Session
from openai import OpenAI

from database import SessionLocal
# from models import ScamInteraction  # keep commented if DB not ready

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
# Database Dependency
# -------------------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

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
# Intelligence Extraction Helpers
# -------------------------------
def extract_upi_ids(text):
    pattern = r"[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}"
    return list(set(re.findall(pattern, text)))

def extract_bank_accounts(text):
    pattern = r"\b\d{9,18}\b"
    return list(set(re.findall(pattern, text)))

def extract_links(text):
    pattern = r"https?://[^\s]+"
    return list(set(re.findall(pattern, text)))

# -------------------------------
# Scam Detection Endpoint
# -------------------------------
@app.post("/detect")
def detect_scam(
    request: ScamRequest,
    db: Session = Depends(get_db),
    _: str = Depends(verify_api_key)
):
    try:
        user_message = request.message.text

        # -------------------------------
        # Call OpenAI with strict JSON instruction
        # -------------------------------
        prompt = f"""
You are an advanced AI Honeypot designed to detect scammers and safely engage them to extract intelligence.

GOALS:
1. Detect if the sender is likely a scammer.
2. If scam is detected → respond like a believable human victim.
3. Try to extract more scam details such as:
   - Payment requests
   - UPI IDs
   - Bank account details
   - External phishing links
   - Phone numbers
4. Keep the scammer engaged without revealing suspicion.
5. If message is NOT scam → reply politely and normally.

SCAM INDICATORS TO WATCH FOR:
- Urgency or threats (account blocked, immediate action required)
- Payment demands
- Requests for OTP / PIN / passwords
- Fake bank or government impersonation
- Suspicious links
- Requests for verification

RESPONSE STYLE:
- Sound natural and slightly confused
- Ask questions that encourage scammer to reveal details
- Do NOT accuse scammer
- Keep reply short and human-like

Respond ONLY in valid JSON using this format:

{
  "scam_detected": true/false,
  "agent_reply": "human style reply continuing conversation",
  "confidence_score": number between 0 and 1
}

Message:
"""
{user_message}
"""


IMPORTANT: Always return valid JSON with all fields filled. If nothing is detected, fill 'agent_reply' with 'No scam detected'.
"""

        response = client.chat.completions.create(
            model="gpt-5-mini",
            messages=[{"role": "user", "content": prompt}],
            max_completion_tokens=100
        )

        raw_output = response.choices[0].message.content.strip()

        # -------------------------------
        # Parse Model JSON Safely
        # -------------------------------
        try:
            parsed = json.loads(raw_output)
        except json.JSONDecodeError:
            parsed = {
                "scam_detected": False,
                "agent_reply": "No scam detected",
                "confidence_score": 0.0
            }

        agent_reply = parsed.get("agent_reply", "No scam detected")

        # -------------------------------
        # Optional: Intelligence Extraction
        # -------------------------------
        # upi_ids = extract_upi_ids(user_message)
        # bank_accounts = extract_bank_accounts(user_message)
        # links = extract_links(user_message)

        # -------------------------------
        # Optional: Store In DB
        # -------------------------------
        # interaction = ScamInteraction(
        #     session_id=request.sessionId,
        #     message=user_message,
        #     scam_detected=parsed.get("scam_detected", False),
        #     agent_reply=agent_reply,
        #     confidence_score=parsed.get("confidence_score", 0.0),
        #     upi_ids=",".join(upi_ids),
        #     bank_accounts=",".join(bank_accounts),
        #     phishing_links=",".join(links)
        # )
        # db.add(interaction)
        # db.commit()

        # -------------------------------
        # Return in hackathon-required format
        # -------------------------------
        return {
            "status": "success",
            "reply": agent_reply
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
