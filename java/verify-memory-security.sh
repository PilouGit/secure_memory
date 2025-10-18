#!/bin/bash

# Script to verify that SecureMemory properly zeros sensitive data
# This script runs a Java program and checks if secrets leak into memory

set -e

SECRET="MyTopSecretPassword@2025!"
DURATION=10

echo "=== SecureMemory Security Verification ==="
echo ""
echo "This script will:"
echo "1. Start a Java program that uses SecureMemory"
echo "2. Create a heap dump"
echo "3. Search for the secret in the heap dump"
echo "4. Report if the secret was found (FAIL) or not found (PASS)"
echo ""
echo "Secret to search: $SECRET"
echo ""

# Compile the Java code if needed
if [ ! -d "target/classes" ]; then
    echo "Compiling Java code..."
    mvn compile
fi

# Start the MemoryLeakDemo in the background
echo "Starting MemoryLeakDemo..."
java -cp target/classes:$(mvn dependency:build-classpath -q -DincludeScope=runtime -Dmdep.outputFile=/dev/stdout) \
    com.securememory.MemoryLeakDemo &

JAVA_PID=$!
echo "Java process PID: $JAVA_PID"

# Wait for the program to initialize
sleep 5

# Check if process is still running
if ! ps -p $JAVA_PID > /dev/null; then
    echo "ERROR: Java process died unexpectedly"
    exit 1
fi

echo ""
echo "--- Creating heap dump ---"
HEAP_DUMP="heap_dump_$JAVA_PID.hprof"

if command -v jmap &> /dev/null; then
    jmap -dump:format=b,file=$HEAP_DUMP $JAVA_PID
    echo "Heap dump created: $HEAP_DUMP"
else
    echo "WARNING: jmap not found. Install JDK to use this tool."
    echo "Trying alternative: jcmd"
    if command -v jcmd &> /dev/null; then
        jcmd $JAVA_PID GC.heap_dump $HEAP_DUMP
        echo "Heap dump created: $HEAP_DUMP"
    else
        echo "ERROR: Neither jmap nor jcmd found. Cannot create heap dump."
        kill $JAVA_PID 2>/dev/null || true
        exit 1
    fi
fi

echo ""
echo "--- Searching for secret in heap dump ---"

if command -v strings &> /dev/null; then
    if strings $HEAP_DUMP | grep -q "$SECRET"; then
        echo "RESULT: FOUND - Secret is present in heap dump"
        echo "STATUS: FAIL - Memory leak detected!"
        FOUND_IN_HEAP=1
    else
        echo "RESULT: NOT FOUND - Secret is not in heap dump"
        echo "STATUS: PASS - No leak in heap"
        FOUND_IN_HEAP=0
    fi
else
    echo "WARNING: 'strings' command not found. Cannot search heap dump."
    FOUND_IN_HEAP=-1
fi

# Try to search in process memory (requires root)
echo ""
echo "--- Attempting to search process memory (may require root) ---"

if [ -r "/proc/$JAVA_PID/maps" ]; then
    echo "Process memory maps accessible"

    # Try to read heap memory regions
    HEAP_REGIONS=$(grep heap /proc/$JAVA_PID/maps | awk '{print $1}')

    if [ -r "/proc/$JAVA_PID/mem" ]; then
        echo "Searching process memory..."

        # Note: This requires root permissions
        if sudo -n true 2>/dev/null; then
            if sudo grep -a "$SECRET" /proc/$JAVA_PID/mem 2>/dev/null; then
                echo "RESULT: FOUND - Secret is in process memory"
                echo "STATUS: FAIL - Memory not properly zeroed!"
            else
                echo "RESULT: NOT FOUND - Secret is not in process memory"
                echo "STATUS: PASS - Memory properly zeroed"
            fi
        else
            echo "INFO: Root access required to search /proc/$JAVA_PID/mem"
            echo "Run with sudo to perform full memory search"
        fi
    else
        echo "INFO: Cannot read /proc/$JAVA_PID/mem (not Linux or insufficient permissions)"
    fi
else
    echo "INFO: Cannot access /proc/$JAVA_PID/maps (not Linux)"
fi

# Cleanup
echo ""
echo "--- Cleanup ---"
kill $JAVA_PID 2>/dev/null || true
rm -f $HEAP_DUMP

echo ""
echo "=== Verification Complete ==="
echo ""

if [ $FOUND_IN_HEAP -eq 0 ]; then
    echo "✓ SUCCESS: No secrets found in heap dump"
    echo "  SecureMemory appears to be working correctly"
    exit 0
elif [ $FOUND_IN_HEAP -eq 1 ]; then
    echo "✗ FAILURE: Secrets found in heap dump"
    echo "  This may be due to:"
    echo "  - Normal String copies not yet garbage collected"
    echo "  - JVM string interning"
    echo "  - Debug/print statements creating copies"
    exit 1
else
    echo "? UNKNOWN: Could not verify (missing tools)"
    exit 2
fi
