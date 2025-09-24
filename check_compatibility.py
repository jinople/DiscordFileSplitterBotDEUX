#!/usr/bin/env python3
"""
Discord File Splitter Bot - Environment Compatibility Checker

This script checks if your Python environment is compatible with the Discord bot.
Run this before starting the bot to ensure everything is properly configured.
"""

import sys
import subprocess
import importlib.util

def check_python_version():
    """Check Python version compatibility"""
    print(f"🐍 Python Version: {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    
    if sys.version_info < (3, 10):
        print("❌ ERROR: Python 3.10+ is required")
        return False
    elif sys.version_info >= (3, 14):
        print("⚠️  WARNING: Python 3.14+ is not fully tested")
        return True
    else:
        print("✅ Python version is compatible")
        return True

def check_package(package_name, min_version=None):
    """Check if a package is installed with optional version check"""
    try:
        module = importlib.import_module(package_name)
        version = getattr(module, '__version__', 'unknown')
        
        if min_version and hasattr(module, '__version__'):
            installed_version = tuple(map(int, version.split('.')[:2]))
            required_version = tuple(map(int, min_version.split('.')[:2]))
            
            if installed_version < required_version:
                print(f"❌ {package_name} {version} is too old (requires {min_version}+)")
                return False
        
        print(f"✅ {package_name} {version}")
        return True
        
    except ImportError:
        print(f"❌ {package_name} is not installed")
        return False

def check_requirements():
    """Check all required packages"""
    print("\n📦 Checking Required Packages:")
    
    packages = [
        ('discord', '2.6'),
        ('aiohttp', '3.10'),
        ('aiofiles', '24.0'),
        ('dotenv', '1.0'),  # python-dotenv imports as dotenv
        ('github', '2.0'),   # PyGithub imports as github
        ('cryptography', '41.0'),
    ]
    
    all_good = True
    for package, min_version in packages:
        if not check_package(package, min_version):
            all_good = False
    
    return all_good

def main():
    """Main compatibility check"""
    print("🔍 Discord File Splitter Bot - Compatibility Check")
    print("=" * 55)
    
    python_ok = check_python_version()
    packages_ok = check_requirements()
    
    print("\n" + "=" * 55)
    
    if python_ok and packages_ok:
        print("🎉 Environment is compatible! You can run the bot safely.")
        return 0
    else:
        print("💥 Compatibility issues found. Please fix the errors above.")
        print("\nTo install/upgrade packages, run:")
        print("   pip install -r requirements.txt")
        return 1

if __name__ == "__main__":
    exit(main())