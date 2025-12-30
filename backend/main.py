from fastapi import FastAPI
from pydantic import BaseModel
import joblib
import pandas as pd
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

model = joblib.load(BASE_DIR / "ids_multiclass_model.pkl")
scaler = joblib.load(BASE_DIR / "scaler.pkl")
label_encoder = joblib.load(BASE_DIR / "label_encoder.pkl")

app = FastAPI(title="Intrusion Detection API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://nsl-kdd.vercel.app"],  # restrict in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class NetworkInput(BaseModel):
    duration: float
    protocol_type: int
    service: int
    flag: int
    src_bytes: float
    dst_bytes: float
    land: float
    wrong_fragment: float
    urgent: float
    hot: float
    num_failed_logins: float
    logged_in: float
    num_compromised: float
    root_shell: float
    su_attempted: float
    num_root: float
    num_file_creations: float
    num_shells: float
    num_access_files: float
    num_outbound_cmds: float
    is_host_login: float
    is_guest_login: float
    count: float
    srv_count: float
    serror_rate: float
    srv_serror_rate: float
    rerror_rate: float
    srv_rerror_rate: float
    same_srv_rate: float
    diff_srv_rate: float
    srv_diff_host_rate: float
    dst_host_count: float
    dst_host_srv_count: float
    dst_host_same_srv_rate: float
    dst_host_diff_srv_rate: float
    dst_host_same_src_port_rate: float
    dst_host_srv_diff_host_rate: float
    dst_host_serror_rate: float
    dst_host_srv_serror_rate: float
    dst_host_rerror_rate: float
    dst_host_srv_rerror_rate: float

@app.get("/")
def health():
    return {"status": "IDS API running"}

@app.post("/predict")
def predict(data: NetworkInput):
    df = pd.DataFrame([data.dict()])
    scaled = scaler.transform(df)

    pred = model.predict(scaled)[0]
    proba = model.predict_proba(scaled).max()

    result = label_encoder.inverse_transform([pred])[0]

    return {
        "prediction": result,
        "confidence": round(float(proba), 3)
    }
