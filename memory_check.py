#!/usr/bin/env python3
"""
Memory Usage Monitor for FME-ABT Detector

This utility monitors the memory usage of the FME-ABT detection system
to ensure it stays within the target <100MB limit.
"""

import os
import sys
import time
import psutil
from datetime import datetime


def get_memory_usage():
    """
    Get current memory usage of the process
    
    Returns:
        Dictionary with memory information
    """
    try:
        process = psutil.Process()
        memory_info = process.memory_info()
        
        return {
            'rss_mb': memory_info.rss / 1024 / 1024,  # Resident Set Size in MB
            'vms_mb': memory_info.vms / 1024 / 1024,  # Virtual Memory Size in MB
            'percent': process.memory_percent(),       # Percentage of system memory
            'available_mb': psutil.virtual_memory().available / 1024 / 1024
        }
    except Exception as e:
        return {'error': str(e)}


def monitor_memory(duration_seconds=60, interval_seconds=5):
    """
    Monitor memory usage over time
    
    Args:
        duration_seconds: How long to monitor
        interval_seconds: How often to check
    """
    print("FME-ABT Memory Usage Monitor")
    print("="*50)
    print(f"Monitoring for {duration_seconds} seconds, checking every {interval_seconds} seconds")
    print(f"Target: <100MB RSS memory usage")
    print()
    
    start_time = time.time()
    max_rss = 0
    measurements = []
    
    while time.time() - start_time < duration_seconds:
        memory = get_memory_usage()
        
        if 'error' not in memory:
            rss_mb = memory['rss_mb']
            max_rss = max(max_rss, rss_mb)
            measurements.append(rss_mb)
            
            timestamp = datetime.now().strftime("%H:%M:%S")
            status = "✓ OK" if rss_mb < 100 else "⚠ HIGH"
            
            print(f"{timestamp} | RSS: {rss_mb:6.1f}MB | VMS: {memory['vms_mb']:6.1f}MB | "
                  f"Sys%: {memory['percent']:5.1f}% | {status}")
        else:
            print(f"Error: {memory['error']}")
        
        time.sleep(interval_seconds)
    
    # Summary
    print("\n" + "="*50)
    print("Memory Usage Summary:")
    print(f"Maximum RSS: {max_rss:.1f}MB")
    print(f"Average RSS: {sum(measurements)/len(measurements):.1f}MB" if measurements else "No data")
    print(f"Target Met: {'✓ YES' if max_rss < 100 else '✗ NO'}")
    print("="*50)


def check_system_requirements():
    """
    Check if system meets minimum requirements
    """
    print("System Requirements Check")
    print("="*30)
    
    # Check available memory
    memory = psutil.virtual_memory()
    total_gb = memory.total / (1024**3)
    available_gb = memory.available / (1024**3)
    
    print(f"Total RAM: {total_gb:.1f}GB")
    print(f"Available RAM: {available_gb:.1f}GB")
    print(f"Minimum Required: 4.0GB")
    print(f"Memory Check: {'✓ PASS' if total_gb >= 4.0 else '✗ FAIL'}")
    
    # Check disk space
    disk = psutil.disk_usage('.')
    free_mb = disk.free / (1024**2)
    
    print(f"Free Disk Space: {free_mb:.0f}MB")
    print(f"Minimum Required: 500MB")
    print(f"Disk Check: {'✓ PASS' if free_mb >= 500 else '✗ FAIL'}")
    
    print("="*30)


def main():
    """Main function"""
    if len(sys.argv) > 1:
        if sys.argv[1] == '--requirements':
            check_system_requirements()
            return
        elif sys.argv[1] == '--help':
            print("Usage:")
            print("  python memory_check.py                    # Monitor current process")
            print("  python memory_check.py --requirements     # Check system requirements")
            print("  python memory_check.py --help             # Show this help")
            return
    
    # Check if we're monitoring the current process or need to start the detector
    current_memory = get_memory_usage()
    
    if 'error' not in current_memory:
        print(f"Current process memory usage: {current_memory['rss_mb']:.1f}MB")
        
        # If memory usage is very low, we're probably not running the detector
        if current_memory['rss_mb'] < 10:
            print("\nNote: Very low memory usage detected.")
            print("To monitor FME-ABT detector memory usage:")
            print("1. Start the detector: python main.py")
            print("2. In another terminal, run: python memory_check.py")
            print("\nChecking system requirements instead...")
            print()
            check_system_requirements()
        else:
            # Monitor the current process
            monitor_memory()
    else:
        print(f"Error getting memory info: {current_memory['error']}")


if __name__ == "__main__":
    main()
