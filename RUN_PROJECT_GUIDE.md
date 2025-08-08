# 🚀 Complete Guide: How to Run FME-ABT Project and View All Outputs

This guide will walk you through running the entire FME-ABT ransomware detection system and viewing all possible outputs.

## 📋 Prerequisites

1. **Python 3.9+** installed
2. **Node.js 16+** and npm (for modern frontend)
3. **Git** (if cloning from repository)

## 🎯 Option 1: Modern FME Sentinel Watch (Recommended)

### Step 1: Start the Backend

**Windows:**
```cmd
# Navigate to project directory
cd C:\Users\MIT-LAB2\Raas

# Start backend (this will install dependencies automatically)
start_backend.bat
```

**Linux/Mac:**
```bash
# Navigate to project directory
cd /path/to/Raas

# Install dependencies
pip install -r requirements.txt

# Start backend
python start_fme_sentinel.py
```

**Expected Output:**
```
============================================================
Starting FME-ABT Backend...
============================================================
✓ Backend started on http://127.0.0.1:5000
✓ Backend is responding

FME Sentinel Watch Frontend Instructions
============================================================
Frontend directory found!

To start the FME Sentinel Watch frontend:
1. Open a new terminal/command prompt
2. Navigate to the frontend directory:
   cd C:\Users\MIT-LAB2\Raas\fme-sentinel-watch
3. Install dependencies (first time only):
   npm install
4. Start the development server:
   npm run dev

🎉 Backend is running!
📊 Dashboard available at: http://127.0.0.1:5000
🛡️  FME Sentinel Watch will connect automatically when started

Press Ctrl+C to stop the backend...
```

### Step 2: Start the Frontend

**Open a NEW terminal/command prompt:**
```cmd
# Navigate to frontend directory
cd C:\Users\MIT-LAB2\Raas\fme-sentinel-watch

# Install dependencies (first time only)
npm install

# Start development server
npm run dev
```

**Expected Output:**
```
> fme-sentinel-watch@0.1.0 dev
> vite

  VITE v5.0.0  ready in 500 ms

  ➜  Local:   http://localhost:5173/
  ➜  Network: use --host to expose
  ➜  press h + enter to show help
```

### Step 3: Access the Applications

1. **FME Sentinel Watch (Modern UI):** http://localhost:5173
2. **Traditional Dashboard:** http://127.0.0.1:5000

## 🎯 Option 2: Traditional Dashboard Only

### Start Complete System
```cmd
cd C:\Users\MIT-LAB2\Raas
python main.py
```

**Expected Output:**
```
============================================================
FME-ABT Ransomware Detection System
============================================================
Monitor Path: C:\Users\MIT-LAB2\Raas\monitored
Events DB: file_events.db
Alerts DB: alerts.db
Status: RUNNING

Features Active:
  ✓ File System Monitoring (Watchdog)
  ✓ Entropy Analysis (FME)
  ✓ Burst Detection (ABT)
  ✓ Volume Shadow Copy Monitoring
  ✓ Process Identification
  ✓ Alert System

Press Ctrl+C to stop the detector
============================================================
```

## 📊 All Available Outputs and Where to View Them

### 1. **Real-Time Monitoring Outputs**

**FME Sentinel Watch (http://localhost:5173):**
- 🎯 **Live Alert Feed** - Real-time alerts with severity indicators
- 📈 **System Metrics** - Memory usage, detection rates
- 🔍 **Alert Details** - Detailed information about each detection
- ⚙️ **System Status** - Monitoring state, directories watched
- 🛡️ **Mitigation Controls** - Toggle automatic responses

**Traditional Dashboard (http://127.0.0.1:5000):**
- 📊 **Event Timeline** - Chronological file events
- 🚨 **Alert Dashboard** - Alert management interface
- 📈 **Entropy Charts** - Plotly visualizations
- 🔥 **Burst Heatmaps** - Activity pattern analysis
- ⚙️ **Configuration Panel** - Threshold tuning

### 2. **Console/Terminal Outputs**

**Backend Terminal:**
```
2024-01-08 16:30:15 - monitor - INFO - Started recursive monitoring: C:\Users\MIT-LAB2\Raas\monitored
2024-01-08 16:30:15 - alert - INFO - Started Volume Shadow Copy monitoring
2024-01-08 16:30:16 - fme - WARNING - Suspicious file detected: test.txt (confidence: 0.85)
2024-01-08 16:30:16 - alert - INFO - Alert logged: entropy - High entropy file: test.txt
```

**Frontend Terminal:**
```
[16:30:20] 200 GET /api/alerts 15ms
[16:30:25] 200 GET /api/status 8ms
[16:30:30] 200 GET /api/memory 12ms
```

### 3. **Database Outputs**

**File Events Database (file_events.db):**
```sql
-- View recent events
SELECT * FROM file_events ORDER BY timestamp DESC LIMIT 10;
```

**Alerts Database (alerts.db):**
```sql
-- View recent alerts
SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 10;
```

### 4. **Log Files**

**Error Log (errors.log):**
```
2024-01-08 16:30:15,123 - monitor - INFO - Database initialized: file_events.db
2024-01-08 16:30:15,456 - alert - INFO - Alerts database initialized: alerts.db
```

### 5. **Pop-up Alerts**

When suspicious activity is detected, you'll see:
- 🚨 **Windows Pop-up Notifications** (tkinter messageboxes)
- 🔔 **Browser Notifications** (in FME Sentinel Watch)

## 🧪 Testing the System

### Generate Test Data

1. **Create the monitored directory:**
   ```cmd
   mkdir C:\Users\MIT-LAB2\Raas\monitored
   ```

2. **Generate file activity:**
   ```cmd
   cd C:\Users\MIT-LAB2\Raas\monitored
   
   # Create files to trigger events
   echo "test content" > test1.txt
   echo "more content" > test2.txt
   copy test1.txt test3.txt
   del test2.txt
   ```

3. **Generate high-entropy files (simulates encryption):**
   ```python
   # Run this in Python to create suspicious files
   import os
   import random
   
   os.chdir(r"C:\Users\MIT-LAB2\Raas\monitored")
   
   # Create high-entropy file
   with open("suspicious.dat", "wb") as f:
       f.write(bytes([random.randint(0, 255) for _ in range(10000)]))
   ```

### View Test Results

**Expected Outputs:**
1. **Console:** Entropy analysis warnings
2. **FME Sentinel Watch:** New alerts appear in real-time
3. **Dashboard:** Events show up in tables and charts
4. **Pop-ups:** Alert notifications for suspicious files

## 🔍 Troubleshooting & Verification

### Test Backend Connection
```cmd
# Windows
check_connection.bat

# Linux/Mac
python test_connection.py
```

**Expected Output:**
```
============================================================
FME-ABT Backend Connection Test
============================================================

1. Testing FME Sentinel Watch Endpoints:
----------------------------------------
✓ GET /api/alerts: 200
✓ GET /api/status: 200
✓ GET /api/memory: 200
✓ POST /api/mitigation: 200

FME Sentinel Watch Endpoints: 4/4 working

🎉 All endpoints working! Backend is ready for FME Sentinel Watch
============================================================
```

### Check System Status
```cmd
# View running processes
tasklist | findstr python

# Check ports
netstat -an | findstr :5000
netstat -an | findstr :5173
```

## 📱 Mobile/Remote Access

**Access from other devices on the network:**
1. Find your IP address: `ipconfig` (Windows) or `ifconfig` (Linux/Mac)
2. Update CORS settings in `app.py` to include your IP
3. Access via: `http://YOUR_IP:5000` or `http://YOUR_IP:5173`

## 🎯 Summary of All Outputs

| Output Type | Location | What You'll See |
|-------------|----------|-----------------|
| **Modern UI** | http://localhost:5173 | Real-time alerts, metrics, controls |
| **Dashboard** | http://127.0.0.1:5000 | Charts, tables, configuration |
| **Console** | Terminal windows | Logs, status messages, errors |
| **Pop-ups** | Desktop notifications | Critical alerts |
| **Database** | SQLite files | Raw event and alert data |
| **Log Files** | errors.log | Detailed system logs |
| **API Data** | JSON responses | Raw API data for integration |

## 🚀 Next Steps

1. **Start both applications** using the instructions above
2. **Generate test data** to see the system in action
3. **Monitor all output channels** to understand the system behavior
4. **Customize settings** through the web interfaces
5. **Set up real monitoring** on important directories

The system is now ready to detect ransomware activity in real-time! 🛡️
