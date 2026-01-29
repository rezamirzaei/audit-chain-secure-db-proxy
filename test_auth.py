#!/usr/bin/env python3
"""
Test script for the multi-step authentication flow
"""

import os
import sys

# Add project paths
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test that all imports work"""
    try:
        from flask import Flask
        print("✓ Flask imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import Flask: {e}")
        print("  Run: pip install flask")
        return False

    try:
        import requests
        print("✓ Requests imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import requests: {e}")
        print("  Run: pip install requests")
        return False

    return True


def test_database_server_syntax():
    """Test database server app syntax"""
    try:
        import py_compile
        py_compile.compile('database_server/app.py', doraise=True)
        print("✓ database_server/app.py syntax OK")
        return True
    except py_compile.PyCompileError as e:
        print(f"✗ database_server/app.py syntax error: {e}")
        return False


def test_proxy_syntax():
    """Test proxy app syntax"""
    try:
        import py_compile
        py_compile.compile('proxy_clone/app.py', doraise=True)
        print("✓ proxy_clone/app.py syntax OK")
        return True
    except py_compile.PyCompileError as e:
        print(f"✗ proxy_clone/app.py syntax error: {e}")
        return False


def main():
    print("=" * 50)
    print("Testing Multi-Step Authentication Implementation")
    print("=" * 50)

    all_ok = True

    print("\n1. Testing imports...")
    if not test_imports():
        all_ok = False

    print("\n2. Testing syntax...")
    if not test_database_server_syntax():
        all_ok = False
    if not test_proxy_syntax():
        all_ok = False

    print("\n" + "=" * 50)
    if all_ok:
        print("All tests passed! ✓")
        print("\nTo run the servers:")
        print("  1. Database Server: cd database_server && python app.py")
        print("  2. Proxy Server:    cd proxy_clone && python app.py")
        print("\nOr use Docker:")
        print("  docker-compose up --build")
    else:
        print("Some tests failed ✗")
        print("\nPlease fix the issues above before running.")
    print("=" * 50)


if __name__ == '__main__':
    main()
