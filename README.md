
---


# 🔐 Network Intrusion Detection System (NSL-KDD) – ML + Full Stack Deployment

A **Machine Learning–based Network Intrusion Detection System (IDS)** built using the **NSL-KDD dataset**, deployed with a **FastAPI backend** and a **React + Vite frontend**, featuring **real-time attack simulation, explainable AI, risk scoring, dashboards, and history tracking**.

---

## 🚀 Live Deployment

### 🌐 Frontend (Vercel)
👉 https://nsl-kdd.vercel.app/

### ⚙️ Backend API (Render)
👉 https://nsl-kdd-0hb1.onrender.com  
👉 Swagger Docs: https://nsl-kdd-0hb1.onrender.com/docs

---

## 🧠 Project Overview

This project detects and classifies network traffic into multiple intrusion categories using a trained ML model:

### Attack Classes
- **Normal**
- **DoS (Denial of Service)**
- **Probe (Scanning / Reconnaissance)**
- **R2L (Remote to Local)**
- **U2R (User to Root)**

---

## ✨ Key Features

### 🔍 Machine Learning
- Random Forest–based IDS model
- Trained on **NSL-KDD dataset**
- Multi-class classification
- StandardScaler preprocessing

### 🧠 Explainable AI
- Rule-based explanation for predictions
- SHAP-style feature impact visualization
- Human-readable detection reasoning

### 📊 Interactive Dashboard
- Auto-fill attack presets (Normal / DoS / Probe)
- Risk score indicator (Low / Medium / High)
- Bar charts & line charts (Recharts)
- Attack history timeline
- CSV export of detection history

### 🌐 Full Stack Deployment
- **FastAPI** backend (Render)
- **React + Vite** frontend (Vercel)
- CORS-enabled secure API communication

---

## 🏗️ Tech Stack

### Backend
- Python 3.10+
- FastAPI
- Scikit-learn
- Pandas
- Joblib
- Uvicorn

### Frontend
- React
- Vite
- Recharts
- CSS (Glassmorphism UI)

### Deployment
- **Vercel** – Frontend hosting
- **Render** – Backend API hosting
- **GitHub** – Version control

---

## 📁 Project Structure


```
NSL_KDD/
│
├── backend/
│   ├── main.py
│   ├── ids_multiclass_model.pkl
│   ├── scaler.pkl
│   ├── label_encoder.pkl
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── App.css
│   │   └── main.jsx
│   ├── index.html
│   └── package.json
│
├── notebooks/
│   └── model_training.ipynb
│
└── README.md

````

---

## 📡 API Endpoint

### `POST /predict`

**Request Body (JSON):**
```json
{
  "duration": 0,
  "protocol_type": 1,
  "service": 20,
  "flag": 9,
  "src_bytes": 200,
  "dst_bytes": 5000,
  "land": 0,
  "wrong_fragment": 0,
  "urgent": 0,
  "hot": 0,
  "num_failed_logins": 0,
  "logged_in": 1,
  "num_compromised": 0,
  "root_shell": 0,
  "su_attempted": 0,
  "num_root": 0,
  "num_file_creations": 0,
  "num_shells": 0,
  "num_access_files": 0,
  "num_outbound_cmds": 0,
  "is_host_login": 0,
  "is_guest_login": 0,
  "count": 8,
  "srv_count": 8,
  "serror_rate": 0,
  "srv_serror_rate": 0,
  "rerror_rate": 0,
  "srv_rerror_rate": 0,
  "same_srv_rate": 1,
  "diff_srv_rate": 0,
  "srv_diff_host_rate": 0,
  "dst_host_count": 255,
  "dst_host_srv_count": 255,
  "dst_host_same_srv_rate": 1,
  "dst_host_diff_srv_rate": 0,
  "dst_host_same_src_port_rate": 0.04,
  "dst_host_srv_diff_host_rate": 0,
  "dst_host_serror_rate": 0,
  "dst_host_srv_serror_rate": 0,
  "dst_host_rerror_rate": 0,
  "dst_host_srv_rerror_rate": 0
}
````

**Response:**

```json
{
  "prediction": "Normal"
}
```

---

## 🧪 Local Setup (Optional)

### Backend

```bash
pip install -r requirements.txt
uvicorn main:app --reload
```

### Frontend

```bash
npm install
npm run dev
```

---

## 📈 Model Performance

* Overall Accuracy: **~99.7%**
* High precision for DoS & Probe attacks
* Robust performance on imbalanced classes

---

## 🔐 Security Notes

* CORS enabled for frontend-backend communication
* Production-ready API structure
* Easy to restrict origins for deployment security

---

## 📌 Future Enhancements

* Real SHAP integration
* Live network traffic capture
* Authentication & role-based access
* Cloud-native monitoring integration
* Docker-based deployment

---

## 👤 Author

**Kuppireddy Bhageeratha Reddy**
B.Tech | Cyber Security & Machine Learning
GitHub: [https://github.com/kuppireddybhageerathareddy1110](https://github.com/kuppireddybhageerathareddy1110)

---

## ⭐ Acknowledgements

* NSL-KDD Dataset
* FastAPI & Scikit-learn communities
* Render & Vercel for free-tier hosting

---

## 📜 License

This project is for **educational and research purposes**.

---
![WhatsApp Image 2025-12-30 at 15 48 49](https://github.com/user-attachments/assets/6541c7a8-fcac-43c2-a6e3-3d959431ebc6)

![WhatsApp Image 2025-12-30 at 15 48 31](https://github.com/user-attachments/assets/75a8a303-aa60-4310-bed1-715141b51b95)
