# 🚀 Complete Deployment Guide: XGBoost Malware Detector with React

## 📊 System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    React Frontend (Port 3000)               │
│  - Single File Prediction                                   │
│  - Batch JSONL Upload                                       │
│  - Results Dashboard                                        │
└──────────────────────┬──────────────────────────────────────┘
                       │ HTTP/CORS
                       ↓
┌─────────────────────────────────────────────────────────────┐
│                 FastAPI Backend (Port 8000)                 │
│  - /predict (single predictions)                            │
│  - /predict-batch (batch predictions)                       │
│  - /scan-jsonl (file upload & scan)                         │
│  - /model-info (model details)                              │
│  - /health (health check)                                   │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ↓
┌─────────────────────────────────────────────────────────────┐
│            XGBoost Model (15 MB, 626 features)              │
│  - Trained on 60,000 samples (EMBER)                        │
│  - 98.78% Accuracy, 99.38% ROC-AUC                          │
└─────────────────────────────────────────────────────────────┘
```

## 🔧 Quick Start (Local Development)

### Option 1: Manual Setup (Recommended for Development)

#### 1. Start Backend API

```bash
cd a:/Documents/m-virus

# Install dependencies
A:.venv/Scripts/pip install -r requirements-api.txt

# Run API
A:.venv/Scripts/python api_backend.py
```

**Expected Output:**
```
INFO:     Started server process
INFO:     Uvicorn running on http://0.0.0.0:8000
```

#### 2. Create React App

```bash
# In a new terminal/directory
npx create-react-app malware-detector-ui
cd malware-detector-ui

# Install dependencies
npm install axios
```

#### 3. Add Frontend Components

```bash
# Copy component files
cp MalwareDetector.jsx src/components/
cp MalwareDetector.css src/components/
```

#### 4. Update App.jsx

```jsx
import React from 'react';
import MalwareDetector from './components/MalwareDetector';
import './App.css';

function App() {
  return <MalwareDetector />;
}

export default App;
```

#### 5. Set Environment Variable

Create `.env` file:
```
REACT_APP_API_URL=http://localhost:8000
```

#### 6. Start Frontend

```bash
npm start
```

**Access Application:**
- Frontend: http://localhost:3000
- API Docs: http://localhost:8000/docs
- API ReDoc: http://localhost:8000/redoc

### Option 2: Docker Deployment (Production Ready)

#### 1. Build & Run with Docker Compose

```bash
cd a:/Documents/m-virus

docker-compose up -d
```

**Services Running:**
- Backend: http://localhost:8000
- Frontend: http://localhost:3000

#### 2. View Logs

```bash
# Backend logs
docker logs xgboost-malware-detector-api -f

# Frontend logs
docker logs xgboost-malware-detector-ui -f
```

#### 3. Stop Services

```bash
docker-compose down
```

## 📋 API Endpoints Reference

### 1. Health Check

```bash
curl http://localhost:8000/health
```

**Response:**
```json
{
  "status": "healthy",
  "model_loaded": true,
  "timestamp": "2026-02-26T00:10:30.890716"
}
```

### 2. Single File Prediction

```bash
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{
    "features": [0.1, 0.2, 0.3, ...626 values],
    "sha256": "abc123def456"
  }'
```

**Response:**
```json
{
  "prediction": "Malware",
  "probability_malware": 0.95,
  "confidence": 0.95,
  "sha256": "abc123def456"
}
```

### 3. Batch Predictions

```bash
curl -X POST http://localhost:8000/predict-batch \
  -H "Content-Type: application/json" \
  -d '{
    "embeddings": [
      [0.1, 0.2, ...626 values],
      [0.3, 0.4, ...626 values]
    ]
  }'
```

**Response:**
```json
{
  "total": 2,
  "malware_count": 1,
  "benign_count": 1,
  "average_confidence": 0.94,
  "predictions": [...]
}
```

### 4. Upload & Scan JSONL File

```bash
curl -X POST http://localhost:8000/scan-jsonl \
  -F "file=@test_features.jsonl"
```

**Response:**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "total_files": 1000,
  "malware_count": 450,
  "benign_count": 550,
  "average_confidence": 0.956,
  "timestamp": "2026-02-26T00:15:23"
}
```

### 5. Get Scan Results

```bash
curl http://localhost:8000/scan-results/550e8400-e29b-41d4-a716-446655440000
```

### 6. Model Information

```bash
curl http://localhost:8000/model-info
```

**Response:**
```json
{
  "model_type": "XGBoost Binary Classifier",
  "input_features": 626,
  "accuracy": 0.9878,
  "roc_auc": 0.9938,
  "precision": 0.97,
  "recall": 0.8659,
  "f1_score": 0.9157
}
```

## 🌐 Frontend Features

### Dashboard Components

1. **Header Section**
   - App title and description
   - Model performance metrics (Accuracy, ROC-AUC, etc.)

2. **Single File Prediction**
   - Feature input (626 comma-separated values)
   - Optional SHA256 hash input
   - Real-time prediction with confidence visualization

3. **Batch Scan**
   - JSONL file upload interface
   - Progress tracking
   - Results table with prediction details

4. **Results Display**
   - Color-coded (Red=Malware, Green=Benign)
   - Confidence scores
   - Probability indicators
   - Detailed statistics

## 🔐 Security Considerations

### For Production Deployment

#### 1. CORS Configuration

**Restrict Origins:**
```python
# api_backend.py
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourdomain.com"],  # Your domain only
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
```

#### 2. Authentication (Optional)

Add JWT tokens:
```python
from fastapi.security import HTTPBearer

security = HTTPBearer()

@app.post("/predict")
async def predict_malware(request: PredictionRequest, credentials = Depends(security)):
    # Validate token
    pass
```

#### 3. Rate Limiting

```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.post("/predict")
@limiter.limit("100/minute")
async def predict_malware(request):
    pass
```

#### 4. HTTPS

```bash
# Use SSL certificates
uvicorn.run(
    app,
    host="0.0.0.0",
    port=443,
    ssl_keyfile="/path/to/key.pem",
    ssl_certfile="/path/to/cert.pem"
)
```

## 📊 Performance Tuning

### Backend Optimization

```python
# Increase worker processes
uvicorn.run(
    app,
    host="0.0.0.0",
    port=8000,
    workers=4,  # Match CPU cores
    loop="uvloop"  # Faster event loop
)
```

### Frontend Optimization

```bash
# Build optimized production bundle
npm run build

# Analyze bundle size
npm install -g webpack-bundle-analyzer
npm run analyze
```

## 🐛 Debugging & Logs

### View API Logs

```bash
# Enable debug logging
export DEBUG=True
python api_backend.py
```

### Frontend Debug

```bash
# Enable React DevTools
npm install react-devtools

# Check network requests
# Open browser DevTools → Network tab
```

### Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| CORS Error | Ensure backend CORS is configured correctly |
| Model Not Loading | Check file path and permissions |
| Slow Predictions | Increase worker processes, use batch predictions |
| Out of Memory | Reduce batch size, enable pagination |
| Port Already in Use | `lsof -i :8000` to find process, kill it |

## 📈 Scaling

### Horizontal Scaling

Use load balancer (NGINX):

```nginx
upstream backend {
    server api1:8000;
    server api2:8000;
    server api3:8000;
}

server {
    listen 80;
    location /api {
        proxy_pass http://backend;
    }
}
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: malware-detector-api
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: api
        image: malware-detector:latest
        ports:
        - containerPort: 8000
        resources:
          requests:
            memory: "2Gi"
            cpu: "1"
```

## 📚 Testing

### API Testing with Curl

```bash
#!/bin/bash

# Test health
curl http://localhost:8000/health

# Test prediction with dummy features
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"features": ['$(python -c "print(','.join(['0.1']*626))")']}'

# Test batch
curl http://localhost:8000/model-info
```

### Frontend Testing

```bash
npm test
npm run build
```

## 🎯 Deployment Checklist

- [ ] Backend API runs successfully
- [ ] Frontend connects to backend
- [ ] Model loads without errors
- [ ] Predictions return correct format
- [ ] Batch uploads work
- [ ] Results display properly
- [ ] Error handling implemented
- [ ] CORS configured for production domain
- [ ] SSL/HTTPS enabled (if needed)
- [ ] Rate limiting in place
- [ ] Logging configured
- [ ] Performance tested
- [ ] Documentation updated

## 📞 Support & Troubleshooting

### API Won't Start

```bash
# Check if port 8000 is in use
netstat -ano | findstr :8000

# Kill process
taskkill /PID <PID> /F

# Verify Python environment
python --version
pip list | grep fastapi
```

### Frontend Can't Connect to API

```bash
# Check if API is running
curl http://localhost:8000/health

# Check CORS headers
curl -i http://localhost:8000/health

# Check environment variable
# In browser console: console.log(process.env.REACT_APP_API_URL)
```

### Model Prediction Errors

```bash
# Check model file exists
dir models\\xgboost_malware_model.json

# Verify features format
# Must be exactly 626 features
# All values must be numeric

# Test with Python
python -c "import xgboost as xgb; m = xgb.Booster(); m.load_model('models/xgboost_malware_model.json')"
```

---

**Version**: 1.0  
**Last Updated**: February 2026  
**Status**: Production Ready ✓

For more information, see:
- [README.md](README.md) - Project overview
- [REACT_SETUP.md](REACT_SETUP.md) - Frontend detailed setup
- [MODEL_REPORT.md](MODEL_REPORT.md) - Model analysis
