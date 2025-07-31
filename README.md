# FME-ABT Detector

A lightweight, zero-cost, open-source Python tool for passive Ransomware-as-a-Service (RaaS) detection.

## Features

- **File Monitoring Enhancement (FME)**: Multi-segment entropy analysis with Chi-square tests
- **Adaptive Burst Threshold (ABT)**: Dynamic burst detection with granular baselines
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

1. Start the file monitor:
```bash
python monitor.py
```

2. Launch the web UI:
```bash
python app.py
```

3. Access the dashboard at `http://localhost:5000`

## Project Structure

```
FME-ABT-Detector/
├── monitor.py        # File and process monitoring
├── fme.py           # Entropy and statistical tests
├── abt.py           # Adaptive burst thresholds
├── alert.py         # Alerts and mitigation
├── app.py           # Flask UI
├── templates/       # HTML templates for UI
├── file_events.db   # SQLite event logs
├── alerts.db        # SQLite alert logs
├── dataset.csv      # Dataset
├── errors.log       # Error logs
├── requirements.txt # Dependencies
└── tests/           # Test scripts
```

## Testing

For safety, all ransomware testing should be conducted in an isolated virtual machine with network disabled.

## License

Open Source - MIT License
