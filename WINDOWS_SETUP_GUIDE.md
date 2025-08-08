# 🪟 Windows Setup Guide for FME-ABT

This guide helps you set up and run the FME-ABT project on Windows when you encounter Python/pip issues.

## 🚨 Common Issue: "pip is not recognized"

This happens when Python is not properly added to your Windows PATH. Here are several solutions:

## 🎯 Solution 1: Use the Automated Setup (Recommended)

```cmd
# Run the automated Windows setup script
setup_windows.bat
```

This script will:
- ✅ Detect your Python installation
- ✅ Install all dependencies
- ✅ Start the backend automatically

## 🎯 Solution 2: Use Python Launcher

If you have Python installed but pip doesn't work:

```cmd
# Use the Python Launcher script
run_with_py.bat
```

Or manually:
```cmd
py --version
py -m pip install -r requirements.txt
py app.py
```

## 🎯 Solution 3: Manual Python Installation

### Step 1: Install Python Properly

1. **Download Python** from https://python.org
2. **Choose Python 3.9 or later**
3. **IMPORTANT:** Check "Add Python to PATH" during installation
4. **Restart your command prompt** after installation

### Step 2: Verify Installation

```cmd
python --version
pip --version
```

If these don't work, try:
```cmd
py --version
py -m pip --version
```

### Step 3: Install Dependencies

```cmd
# Method 1: Standard pip
pip install -r requirements.txt

# Method 2: Python module
python -m pip install -r requirements.txt

# Method 3: Python Launcher
py -m pip install -r requirements.txt
```

## 🎯 Solution 4: Alternative Python Commands

Try these different commands to find what works on your system:

```cmd
# Test different Python commands
python --version
python3 --version
py --version

# Test different pip commands
pip --version
pip3 --version
python -m pip --version
py -m pip --version
```

## 🎯 Solution 5: Install from Microsoft Store

If nothing else works:

1. Open **Microsoft Store**
2. Search for **"Python"**
3. Install **Python 3.11** or later
4. Restart command prompt
5. Try: `python -m pip install -r requirements.txt`

## 🔧 Manual Package Installation

If requirements.txt fails, install packages individually:

```cmd
# Using pip
pip install watchdog psutil scipy flask flask-socketio flask-cors plotly requests

# Using Python module
python -m pip install watchdog psutil scipy flask flask-socketio flask-cors plotly requests

# Using Python Launcher
py -m pip install watchdog psutil scipy flask flask-socketio flask-cors plotly requests
```

## 🚀 Running the Project

Once dependencies are installed, you can run the project:

### Option 1: Backend Only
```cmd
python app.py
# or
py app.py
```

### Option 2: Complete System
```cmd
python main.py
# or
py main.py
```

### Option 3: Test Everything
```cmd
python test_connection.py
# or
py test_connection.py
```

## 🌐 Frontend Setup (FME Sentinel Watch)

### Step 1: Install Node.js
1. Download from https://nodejs.org
2. Install with default settings
3. Restart command prompt

### Step 2: Setup Frontend
```cmd
cd fme-sentinel-watch
npm install
npm run dev
```

## 🧪 Generate Test Data

```cmd
python generate_test_data.py
# or
py generate_test_data.py
```

## 📊 Monitor Outputs

```cmd
python monitor_outputs.py
# or
py monitor_outputs.py
```

## 🔍 Troubleshooting

### Issue: "Python was not found"
**Solution:** Install Python from python.org and check "Add to PATH"

### Issue: "pip is not recognized"
**Solutions:**
- Use `python -m pip` instead of `pip`
- Use `py -m pip` instead of `pip`
- Reinstall Python with "Add to PATH" checked

### Issue: "No module named 'flask'"
**Solution:** Dependencies not installed properly
```cmd
py -m pip install flask flask-socketio flask-cors
```

### Issue: "Permission denied"
**Solution:** Run as administrator or use `--user` flag
```cmd
py -m pip install --user -r requirements.txt
```

### Issue: "Microsoft Visual C++ required"
**Solution:** Install Visual C++ Build Tools or use pre-compiled packages
```cmd
py -m pip install --only-binary=all -r requirements.txt
```

## 🎯 Quick Commands Summary

```cmd
# 1. Automated setup (easiest)
setup_windows.bat

# 2. Python Launcher method
run_with_py.bat

# 3. Manual method
py -m pip install -r requirements.txt
py app.py

# 4. Test connection
py test_connection.py

# 5. Generate test data
py generate_test_data.py

# 6. Monitor outputs
py monitor_outputs.py
```

## 📱 Access URLs

Once running:
- **FME Sentinel Watch:** http://localhost:5173
- **Traditional Dashboard:** http://127.0.0.1:5000

## 🆘 Still Having Issues?

1. **Check Python installation:**
   ```cmd
   where python
   where py
   ```

2. **Check environment variables:**
   - Open System Properties → Environment Variables
   - Look for Python in PATH

3. **Try different terminals:**
   - Command Prompt (cmd)
   - PowerShell
   - Windows Terminal

4. **Restart your computer** after installing Python

5. **Use the Python Launcher** (`py` command) which is more reliable on Windows

The key is to find which Python command works on your system and use the corresponding pip method! 🎯
