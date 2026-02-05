import os
import json
import re
from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel
from sqlalchemy.orm import Session
from openai import OpenAI

from database import SessionLocal
# from models import ScamInteraction  # Uncomment when database model is ready

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
# Request Schema
# -------------------------------

class ScamRequest(BaseModel):
    session_id: str
    message: str

# -------------------------------
# Authentication
# -------------------------------

def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

# -------------------------------
# Intelligence Extraction Helpers
# -------------------------------

def extract_upi_ids(text: str):
    pattern = r"[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}"
    return list(set(re.findall(pattern, text)))

def extract_bank_accounts(text: str):
    pattern = r"\b\d{9,18}\b"
    return list(set(re.findall(pattern, text)))

def extract_links(text: str):
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
        user_message = request.message

        # -------------------------------
        # OpenAI GPT-5-mini Prompt
        # -------------------------------

        prompt = f"""
You are a scam detection engine.

Analyze the following message and respond ONLY in JSON:

{{
  "scam_detected": true/false,
  "agent_reply": "reply pretending to be a victim to gather more scam intel",
  "confidence_score": number between 0 and 1
}}

Message:
{user_message}
"""

        # -------------------------------
        # Call GPT-5-mini (compatible)
        # -------------------------------

        response = client.chat.completions.create(
            model="gpt-5-mini",
            messages=[{"role": "user", "content": prompt}],
            max_completion_tokens=100  # ✅ use this instead of max_tokens
            # temperature is removed, GPT-5-mini only supports default
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
                "agent_reply": "",
                "confidence_score": 0.0
            }

        scam_detected = parsed.get("scam_detected", False)
        agent_reply = parsed.get("agent_reply", "")
        confidence_score = parsed.get("confidence_score", 0.0)

        # -------------------------------
        # Extract Intelligence
        # -------------------------------

        upi_ids = extract_upi_ids(user_message)
        bank_accounts = extract_bank_accounts(user_message)
        links = extract_links(user_message)

        # -------------------------------
        # Store In Database (optional)
        # -------------------------------

        # interaction = ScamInteraction(
        #     session_id=request.session_id,
        #     message=user_message,
        #     scam_detected=scam_detected,
        #     agent_reply=agent_reply,
        #     confidence_score=confidence_score,
        #     upi_ids=",".join(upi_ids),
        #     bank_accounts=",".join(bank_accounts),
        #     phishing_links=",".join(links)
        # )
        #
        # db.add(interaction)
        # db.commit()

        # -------------------------------
        # Final API Response
        # -------------------------------

        return {
            "scam_detected": scam_detected,
            "agent_reply": agent_reply,
            "extracted_intelligence": {
                "upi_ids": upi_ids,
                "bank_accounts": bank_accounts,
                "phishing_links": links
            },
            "confidence_score": confidence_score
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
