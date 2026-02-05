import os
from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List
import re
from openai import OpenAI
from sqlalchemy.orm import Session

# DB imports
from database import SessionLocal, engine, Base
from models import Conversation, Message, Intelligence


# -----------------------------
# Load Environment Variables
# -----------------------------
load_dotenv()

API_KEY = os.getenv("HONEYPOT_API_KEY")

if not API_KEY:
    raise ValueError("HONEYPOT_API_KEY not set")

if not os.getenv("OPENAI_API_KEY"):
    raise ValueError("OPENAI_API_KEY not set")

client = OpenAI()

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI()


# -----------------------------
# Global Exception Handler
# Prevents API crashes
# -----------------------------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "details": str(exc)
        }
    )


# -----------------------------
# DB Session Dependency
# -----------------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# -----------------------------
# Request Schema
# -----------------------------
class MessageHistory(BaseModel):
    role: str
    content: str


class HoneypotRequest(BaseModel):
    conversation_id: str
    message: str
    history: List[MessageHistory] = []
    turn_count: int = 0


# -----------------------------
# Intelligence Extraction
# -----------------------------
def extract_intelligence(text):

    upi = re.findall(r"[a-zA-Z0-9.\-_]+@[a-zA-Z]+", text)
    accounts = re.findall(r"\b\d{9,18}\b", text)
    links = re.findall(r"https?://\S+", text)

    return {
        "upi_ids": list(set(upi)),
        "bank_accounts": list(set(accounts)),
        "phishing_links": list(set(links))
    }


# -----------------------------
# Honeypot Endpoint
# -----------------------------
@app.post("/honeypot")
def honeypot_endpoint(
    data: HoneypotRequest,
    x_api_key: str = Header(..., alias="x-api-key"),
    db: Session = Depends(get_db)
):

    # -----------------------------
    # API Authentication
    # -----------------------------
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    # -----------------------------
    # Ensure Conversation Exists
    # -----------------------------
    conversation = db.query(Conversation).filter_by(
        conversation_id=data.conversation_id
    ).first()

    if not conversation:
        conversation = Conversation(conversation_id=data.conversation_id)
        db.add(conversation)
        db.commit()

    # -----------------------------
    # Scam Detection
    # -----------------------------
    detection_prompt = f"""
You are a scam detection classifier.

Rules:
- If message involves urgency, payment request, account suspension,
UPI, links, impersonation → YES
- Otherwise → NO

STRICT OUTPUT:
YES
NO

Message:
{data.message}
"""

    try:
        detection_response = client.chat.completions.create(
            model="gpt-4o-mini",
            temperature=0,
            max_tokens=5,
            messages=[{"role": "user", "content": detection_prompt}]
        )

        scam_reply = detection_response.choices[0].message.content.strip().upper()
        scam_detected = scam_reply == "YES"

    except Exception:
        scam_detected = False

    # -----------------------------
    # Agent Response
    # -----------------------------
    agent_reply = ""

    if scam_detected and data.turn_count < 3:

        agent_prompt = f"""
You are a normal user replying to a scammer.

Goals:
- Sound worried but cooperative
- Ask for payment details naturally
- Never reveal suspicion
- Keep reply short

Conversation History:
{data.history}

Scammer Message:
{data.message}

Reply as user:
"""

        try:
            agent_response = client.chat.completions.create(
                model="gpt-4o-mini",
                temperature=0.7,
                max_tokens=50,
                messages=[{"role": "user", "content": agent_prompt}]
            )

            agent_reply = agent_response.choices[0].message.content.strip()

        except Exception:
            agent_reply = ""

    # -----------------------------
    # Intelligence Extraction
    # -----------------------------
    extracted = extract_intelligence(data.message + " " + agent_reply)

    # -----------------------------
    # Confidence Scoring
    # -----------------------------
    confidence_score = 0.4

    if scam_detected:
        confidence_score += 0.3
    if extracted["upi_ids"]:
        confidence_score += 0.2
    if extracted["phishing_links"]:
        confidence_score += 0.1

    confidence_score = min(confidence_score, 0.95)

    # -----------------------------
    # Store Scammer Message
    # -----------------------------
    db.add(Message(
        conversation_id=data.conversation_id,
        sender="scammer",
        message_text=data.message,
        scam_detected=scam_detected,
        confidence=confidence_score
    ))

    # -----------------------------
    # Store Agent Message
    # -----------------------------
    if agent_reply:
        db.add(Message(
            conversation_id=data.conversation_id,
            sender="agent",
            message_text=agent_reply,
            scam_detected=True,
            confidence=confidence_score
        ))

    # -----------------------------
    # Store Intelligence
    # -----------------------------
    for upi in extracted["upi_ids"]:

        exists = db.query(Intelligence).filter_by(
            conversation_id=data.conversation_id,
            intel_type="upi",
            value=upi
        ).first()

        if not exists:
            db.add(Intelligence(
                conversation_id=data.conversation_id,
                intel_type="upi",
                value=upi
            ))

    for bank in extracted["bank_accounts"]:

        exists = db.query(Intelligence).filter_by(
            conversation_id=data.conversation_id,
            intel_type="bank",
            value=bank
        ).first()

        if not exists:
            db.add(Intelligence(
                conversation_id=data.conversation_id,
                intel_type="bank",
                value=bank
            ))

    for link in extracted["phishing_links"]:

        exists = db.query(Intelligence).filter_by(
            conversation_id=data.conversation_id,
            intel_type="link",
            value=link
        ).first()

        if not exists:
            db.add(Intelligence(
                conversation_id=data.conversation_id,
                intel_type="link",
                value=link
            ))

    db.commit()

    # -----------------------------
    # Final Response
    # -----------------------------
    return {
        "scam_detected": scam_detected,
        "agent_reply": agent_reply,
        "extracted_intelligence": extracted,
        "confidence_score": confidence_score
    }
