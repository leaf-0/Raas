# FME-ABT Detector

A lightweight, zero-cost, open-source Python tool for passive Ransomware-as-a-Service (RaaS) detection.

## Features

- **File Monitoring Enhancement (FME)**: Multi-segment entropy analysis with Chi-square tests
- **Adaptive Burst Threshold (ABT)**: Dynamic burst detection with granular baselines
- **FME Sentinel Watch**: Modern React frontend for real-time monitoring
- **Web Dashboard**: Flask-based dashboard with real-time updates
- **Lightweight Detection**: Targets ~88% accuracy with <5% false positives
- **Low Resource Usage**: Runs on 4GB RAM, any CPU
- **Offline Operation**: Works offline after initial setup

## Requirements

- Python 3.9+
- 4GB RAM minimum
- 500MB storage
- Windows 10/11 or Linux (Ubuntu 20.04+)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/FME-ABT-Detector.git
cd FME-ABT-Detector
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Option 1: FME Sentinel Watch (Modern Frontend)

1. **Start Backend:**
   ```bash
   # Windows
   start_backend.bat

   # Linux/Mac
   python start_fme_sentinel.py
   ```

2. **Start Frontend:**
   ```bash
   cd fme-sentinel-watch
   npm install
   npm run dev
   ```

3. **Access FME Sentinel Watch:**
   ```
   http://localhost:5173
   ```

### Option 2: Traditional Dashboard

1. Start the complete system:
   ```bash
   python main.py
   ```

2. Access the dashboard at `http://localhost:5000`

### Option 3: Individual Components

1. Start the file monitor:
   ```bash
   python monitor.py
   ```

2. Launch the web UI:
   ```bash
   python app.py
   ```

### Connection Test

To verify the backend is working:
```bash
# Windows
check_connection.bat

# Linux/Mac
python test_connection.py
```

## Project Structure

```
FME-ABT-Detector/
├── monitor.py              # File and process monitoring
├── fme.py                 # Entropy and statistical tests
├── abt.py                 # Adaptive burst thresholds
├── alert.py               # Alerts and mitigation
├── app.py                 # Flask backend with API
├── main.py                # Main entry point
├── utils.py               # Utility functions
├── start_fme_sentinel.py  # Automated startup script
├── test_connection.py     # Connection test script
├── start_backend.bat      # Windows startup script
├── check_connection.bat   # Windows connection test
├── FRONTEND_CONNECTION.md # Frontend connection guide
├── fme-sentinel-watch/    # Modern React frontend
│   ├── src/
│   │   ├── components/    # React components
│   │   ├── services/      # API service layer
│   │   └── types/         # TypeScript types
│   ├── package.json       # Frontend dependencies
│   └── vite.config.ts     # Vite configuration
├── templates/             # HTML templates for dashboard
├── static/                # Static files for dashboard
├── file_events.db         # SQLite event logs
├── alerts.db              # SQLite alert logs
├── dataset.csv            # Dataset
├── errors.log             # Error logs
├── requirements.txt       # Backend dependencies
└── tests/                 # Test scripts
```

## Testing

For safety, all ransomware testing should be conducted in an isolated virtual machine with network disabled.

## License

Open Source - MIT License
