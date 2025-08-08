#!/usr/bin/env python3
"""
Test Data Generator for FME-ABT Detector
Generates various types of file activities to test the detection system
"""

import os
import time
import random
import string
import shutil
from pathlib import Path

def create_monitored_directory():
    """Create the monitored directory if it doesn't exist"""
    monitor_dir = Path("./monitored")
    monitor_dir.mkdir(exist_ok=True)
    print(f"✓ Created/verified monitored directory: {monitor_dir.absolute()}")
    return monitor_dir

def generate_normal_files(monitor_dir, count=5):
    """Generate normal text files"""
    print(f"\n📝 Generating {count} normal files...")
    
    for i in range(count):
        filename = f"normal_file_{i+1}.txt"
        filepath = monitor_dir / filename
        
        # Create normal text content
        content = f"""This is a normal text file #{i+1}
Created at: {time.strftime('%Y-%m-%d %H:%M:%S')}
Content: {''.join(random.choices(string.ascii_letters + ' ', k=100))}
This file should not trigger any alerts.
"""
        
        with open(filepath, 'w') as f:
            f.write(content)
        
        print(f"  ✓ Created: {filename}")
        time.sleep(0.5)  # Small delay to spread out events

def generate_high_entropy_files(monitor_dir, count=3):
    """Generate high-entropy files that should trigger alerts"""
    print(f"\n🚨 Generating {count} high-entropy files (should trigger alerts)...")
    
    for i in range(count):
        filename = f"suspicious_encrypted_{i+1}.dat"
        filepath = monitor_dir / filename
        
        # Create high-entropy binary data (simulates encryption)
        size = random.randint(5000, 15000)
        random_data = bytes([random.randint(0, 255) for _ in range(size)])
        
        with open(filepath, 'wb') as f:
            f.write(random_data)
        
        print(f"  🔥 Created: {filename} ({size} bytes of random data)")
        time.sleep(1)  # Longer delay for entropy analysis

def generate_burst_activity(monitor_dir, count=10):
    """Generate burst of file activity"""
    print(f"\n⚡ Generating burst activity ({count} files in quick succession)...")
    
    for i in range(count):
        filename = f"burst_file_{i+1}.tmp"
        filepath = monitor_dir / filename
        
        content = f"Burst file {i+1} created at {time.time()}"
        
        with open(filepath, 'w') as f:
            f.write(content)
        
        print(f"  ⚡ Created: {filename}")
        time.sleep(0.1)  # Very quick succession to trigger burst detection

def simulate_file_modifications(monitor_dir):
    """Simulate file modifications and deletions"""
    print(f"\n✏️ Simulating file modifications and deletions...")
    
    # Find existing files
    existing_files = list(monitor_dir.glob("*.txt"))
    
    if existing_files:
        # Modify some files
        for i, filepath in enumerate(existing_files[:3]):
            print(f"  ✏️ Modifying: {filepath.name}")
            with open(filepath, 'a') as f:
                f.write(f"\nModified at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
            time.sleep(0.5)
        
        # Delete some files
        for filepath in existing_files[3:5]:
            print(f"  🗑️ Deleting: {filepath.name}")
            filepath.unlink()
            time.sleep(0.5)

def create_suspicious_patterns(monitor_dir):
    """Create files with suspicious naming patterns"""
    print(f"\n🔍 Creating files with suspicious patterns...")
    
    suspicious_names = [
        "DECRYPT_INSTRUCTIONS.txt",
        "HOW_TO_RECOVER_FILES.html",
        "RANSOM_NOTE.txt",
        "encrypted_data.locked",
        "backup.encrypted"
    ]
    
    for filename in suspicious_names:
        filepath = monitor_dir / filename
        
        if "DECRYPT" in filename or "RANSOM" in filename:
            content = """
YOUR FILES HAVE BEEN ENCRYPTED!
To recover your files, you need to pay...
Contact us at: evil@hacker.com
"""
        else:
            # Create high-entropy content for "encrypted" files
            content = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=500))
        
        with open(filepath, 'w') as f:
            f.write(content)
        
        print(f"  🚨 Created suspicious file: {filename}")
        time.sleep(1)

def simulate_vss_deletion():
    """Simulate Volume Shadow Copy deletion commands (WARNING: This is just simulation)"""
    print(f"\n⚠️ Simulating VSS deletion detection...")
    print("  Note: This will NOT actually delete shadow copies, just trigger detection")
    
    # Create a harmless script that contains VSS deletion commands in comments
    script_content = """
REM This is a test script - it does NOT actually run these commands
REM The following are examples of commands that would trigger VSS alerts:
REM vssadmin delete shadows /all /quiet
REM wbadmin delete backup
REM wmic shadowcopy delete
REM powershell "Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete()}"

echo "This is just a test script to trigger VSS monitoring alerts"
echo "No actual shadow copies are being deleted"
"""
    
    script_path = Path("./monitored/test_vss_script.bat")
    with open(script_path, 'w') as f:
        f.write(script_content)
    
    print(f"  ✓ Created test script: {script_path}")
    print("  📝 Note: Real VSS deletion would require running actual commands")

def main():
    """Main function to generate all test data"""
    print("🧪 FME-ABT Test Data Generator")
    print("=" * 50)
    print("This script will generate various file activities to test the detection system.")
    print("Make sure the FME-ABT backend is running to see the alerts!")
    print()
    
    # Create monitored directory
    monitor_dir = create_monitored_directory()
    
    # Generate different types of test data
    generate_normal_files(monitor_dir, 5)
    generate_high_entropy_files(monitor_dir, 3)
    generate_burst_activity(monitor_dir, 8)
    simulate_file_modifications(monitor_dir)
    create_suspicious_patterns(monitor_dir)
    simulate_vss_deletion()
    
    print("\n" + "=" * 50)
    print("🎉 Test data generation complete!")
    print()
    print("📊 Check the following for outputs:")
    print("  • FME Sentinel Watch: http://localhost:5173")
    print("  • Traditional Dashboard: http://127.0.0.1:5000")
    print("  • Backend console: Look for entropy and burst alerts")
    print("  • Pop-up notifications: Should appear for suspicious files")
    print("  • Database: file_events.db and alerts.db")
    print()
    print("🔍 Expected alerts:")
    print("  • High entropy alerts for .dat files")
    print("  • Burst activity alerts")
    print("  • Suspicious file pattern alerts")
    print("  • VSS monitoring alerts (if script is executed)")
    print()
    print("⏱️ Wait a few seconds for all analysis to complete...")

if __name__ == "__main__":
    main()
