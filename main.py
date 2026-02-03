from fastapi import FastAPI, Header, HTTPException

app = FastAPI()

API_KEY = "my_super_secret_key"

@app.post("/honeypot")
def honeypot_endpoint(x_api_key: str = Header(...)):

    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    return {
        "status": "active",
        "message": "Honeypot service operational"
    }
