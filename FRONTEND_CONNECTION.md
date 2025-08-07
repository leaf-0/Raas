# FME Sentinel Watch Frontend Connection Guide

This guide explains how to connect the FME Sentinel Watch frontend to the FME-ABT backend.

## 🔗 Connection Overview

The FME Sentinel Watch frontend is a modern React/TypeScript application that connects to the FME-ABT Python backend via REST API calls. The backend has been enhanced with the necessary endpoints to support the frontend.

## 🚀 Quick Start

### Option 1: Automated Startup (Recommended)

1. **Start the Backend:**
   ```bash
   python start_fme_sentinel.py
   ```
   This will:
   - Check and install dependencies
   - Start the Flask backend on `http://127.0.0.1:5000`
   - Provide instructions for the frontend

2. **Start the Frontend:**
   ```bash
   cd fme-sentinel-watch
   npm install  # First time only
   npm run dev
   ```
   The frontend will be available at `http://localhost:5173`

### Option 2: Manual Startup

1. **Install Backend Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Start Backend:**
   ```bash
   python app.py
   ```

3. **Start Frontend:**
   ```bash
   cd fme-sentinel-watch
   npm install
   npm run dev
   ```

## 🔧 API Endpoints

The backend now provides these endpoints for the FME Sentinel Watch frontend:

### Core Endpoints
- `GET /api/alerts` - Get recent alerts
- `GET /api/status` - Get system monitoring status
- `GET /api/memory` - Get memory usage information
- `POST /api/mitigation` - Toggle mitigation on/off

### Dashboard Endpoints (also available)
- `GET /api/events` - Get recent file events
- `GET /api/metrics` - Get system metrics
- `GET /api/config` - Get configuration
- `GET /api/charts/entropy-trend` - Get entropy trend chart
- `GET /api/charts/burst-heatmap` - Get burst activity heatmap

## 📊 Data Flow

```
FME Sentinel Watch (React) ←→ HTTP/REST API ←→ FME-ABT Backend (Flask)
     (Port 5173)                                    (Port 5000)
```

## 🛠️ Technical Details

### CORS Configuration
The backend is configured with CORS to allow connections from:
- `http://localhost:5173` (Vite dev server)
- `http://127.0.0.1:5173`

### API Response Format
The backend automatically detects requests from the frontend and returns appropriate response formats:

**For FME Sentinel Watch (axios requests):**
```json
[
  {
    "id": 1,
    "alert_type": "entropy",
    "message": "High entropy detected",
    "severity": "high",
    "timestamp": "2024-01-01T12:00:00",
    ...
  }
]
```

**For Dashboard (browser requests):**
```json
{
  "success": true,
  "data": [...],
  "count": 5
}
```

### Authentication
Currently, no authentication is required. The backend accepts all requests from allowed origins.

## 🧪 Testing the Connection

Use the provided test script to verify the connection:

```bash
python test_connection.py
```

This will test all endpoints and verify CORS configuration.

## 🔍 Troubleshooting

### Common Issues

1. **Connection Refused**
   - Ensure the backend is running on port 5000
   - Check if another service is using port 5000

2. **CORS Errors**
   - Verify the frontend is running on port 5173
   - Check browser console for CORS error messages

3. **Empty Data**
   - The system needs to run for a while to generate events and alerts
   - You can manually trigger events by creating/modifying files in the `./monitored` directory

4. **Missing Dependencies**
   - Run `pip install -r requirements.txt` for backend
   - Run `npm install` in the `fme-sentinel-watch` directory for frontend

### Debug Steps

1. **Check Backend Status:**
   ```bash
   curl http://127.0.0.1:5000/api/status
   ```

2. **Check Frontend API Calls:**
   - Open browser developer tools
   - Go to Network tab
   - Look for failed API requests

3. **Check Backend Logs:**
   - Backend logs are displayed in the terminal
   - Look for error messages or exceptions

## 📁 File Structure

```
project-root/
├── app.py                    # Flask backend with API endpoints
├── requirements.txt          # Backend dependencies
├── start_fme_sentinel.py     # Automated startup script
├── test_connection.py        # Connection test script
├── fme-sentinel-watch/       # Frontend directory
│   ├── src/
│   │   ├── services/api.ts   # API service layer
│   │   └── components/       # React components
│   ├── package.json          # Frontend dependencies
│   └── vite.config.ts        # Vite configuration
└── static/                   # Dashboard static files
    └── dashboard.js          # Original dashboard JS
```

## 🎯 Next Steps

1. **Start both applications** using the instructions above
2. **Generate some test data** by creating files in the `./monitored` directory
3. **Monitor the connection** using the browser developer tools
4. **Customize the frontend** as needed for your specific requirements

## 📞 Support

If you encounter issues:
1. Run the test script: `python test_connection.py`
2. Check the troubleshooting section above
3. Verify all dependencies are installed
4. Ensure both applications are running on the correct ports

The connection should work seamlessly once both applications are running!
