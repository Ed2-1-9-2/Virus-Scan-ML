# React Frontend Setup Guide

## 📋 Prerequisites

- Node.js 16+ and npm
- React 18+
- axios for HTTP requests

## 🚀 Setup Steps

### 1. Create React App

```bash
npx create-react-app malware-detector-ui
cd malware-detector-ui
```

### 2. Install Dependencies

```bash
npm install axios
npm install --save-dev tailwindcss postcss autoprefixer
```

### 3. Replace Components

Copy the provided files to your React project:

```bash
# Replace App.jsx or add component
cp MalwareDetector.jsx src/components/

# Copy styles
cp MalwareDetector.css src/components/
```

### 4. Update App.jsx

```jsx
import React from 'react';
import MalwareDetector from './components/MalwareDetector';

function App() {
  return (
    <div className="App">
      <MalwareDetector />
    </div>
  );
}

export default App;
```

### 5. Configure Environment

Create `.env` file:

```
REACT_APP_API_URL=http://localhost:8000
```

### 6. Run Development Server

```bash
npm start
```

App will open at `http://localhost:3000`

## 🌐 API Communication

### Environment Variable

The API URL is configured via environment variable:

```javascript
const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
```

### CORS Configuration

The backend API has CORS enabled for all origins:

```python
allow_origins=["*"]
```

For production, restrict this to your domain.

## 🏗️ Deployment

### Docker Deployment

```bash
docker-compose up -d
```

This starts:
- Backend API on port 8000
- Frontend on port 3000

### Manual Deployment

**Backend:**
```bash
pip install -r requirements-api.txt
python api_backend.py
```

**Frontend:**
```bash
npm run build
npm start
```

## 📚 API Endpoints

### Single Prediction
```
POST /predict
Content-Type: application/json

{
  "features": [0.1, 0.2, ...],
  "sha256": "abc123..."
}
```

### Batch Predictions
```
POST /predict-batch
{
  "embeddings": [[0.1, 0.2, ...], ...]
}
```

### File Upload (JSONL)
```
POST /scan-jsonl
Content-Type: multipart/form-data

file: <EMBER JSONL file>
```

### Model Info
```
GET /model-info
```

### Health Check
```
GET /health
```

## 🔧 Configuration

### Backend Configuration

Edit `api_backend.py`:

```python
# Change port
uvicorn.run(app, host="0.0.0.0", port=8000)

# Change model path
model_path = "path/to/model.json"
```

### Frontend Configuration

### Frontend Configuration

Edit `MalwareDetector.jsx`:

```javascript
// Change API URL
const API_URL = 'http://your-api-server:8000';

// Change number of results shown
const LIMIT = 50;  // Default: 100
```

## 🐛 Troubleshooting

### API Connection Error

```
Error: API Server not running. Start it with: python api_backend.py
```

**Solution:**
1. Start the backend: `python api_backend.py`
2. Verify it's running: `curl http://localhost:8000/health`
3. Check CORS settings if running on different domain

### CORS Issues

If you see CORS errors:

1. **Development**: Backend has CORS enabled by default
2. **Production**: Update CORS in `api_backend.py`:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourdomain.com"],  # Restrict to your domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### Model Not Found

```
RuntimeError: Failed to load model
```

**Solution:**
- Verify model file exists: `models/xgboost_malware_model.json`
- Check file permissions
- Verify file path in `api_backend.py`

## 📊 Example Usage

### 1. Single File Detection

```javascript
const handlePredictSingle = async () => {
  const features = Array(626).fill(0.1); // Example features
  
  const response = await axios.post(
    'http://localhost:8000/predict',
    {
      features: features,
      sha256: 'abc123...'
    }
  );
  
  console.log('Prediction:', response.data);
  // Output: { prediction: "Malware", probability_malware: 0.95, ... }
};
```

### 2. Batch Upload and Scan

```javascript
const handleBatchUpload = async (file) => {
  const formData = new FormData();
  formData.append('file', file);
  
  const response = await axios.post(
    'http://localhost:8000/scan-jsonl',
    formData
  );
  
  console.log('Scan ID:', response.data.scan_id);
  console.log('Malware Count:', response.data.malware_count);
};
```

### 3. Get Scan Results

```javascript
const fetchResults = async (scanId) => {
  const response = await axios.get(
    `http://localhost:8000/scan-results/${scanId}`
  );
  
  console.log('Results:', response.data);
};
```

## 📲 Features

### Frontend
✅ Single file prediction interface
✅ Batch JSONL file upload and processing
✅ Real-time results display
✅ Confidence visualization
✅ Malware/benign statistics
✅ Responsive design (mobile-friendly)
✅ Error handling and loading states

### Backend
✅ RESTful API endpoints
✅ Batch processing support
✅ CORS enabled
✅ Model info endpoint
✅ Health checks
✅ Result caching
✅ Automatic documentation (Swagger)

## 📖 API Documentation

Interactive API documentation available at:

```
http://localhost:8000/docs       (Swagger UI)
http://localhost:8000/redoc      (ReDoc)
```

## 🚀 Performance Tips

### Optimize Backend
- Use connection pooling
- Cache model in memory ✓ (already implemented)
- Batch predictions for better throughput

### Optimize Frontend
- Lazy load components
- Optimize bundle size
- Use React.memo for expensive components

### Deployment
- Use production server (gunicorn, PM2)
- Enable caching headers
- Use CDN for static assets
- Monitor error logs

## 📞 Support

For issues:
1. Check API logs: `tail -f logs/api.log`
2. Check browser console for client errors
3. Verify model file and features format
4. Test endpoints with curl:

```bash
curl http://localhost:8000/health
curl http://localhost:8000/model-info
```

---

**Version**: 1.0  
**Last Updated**: February 2026
