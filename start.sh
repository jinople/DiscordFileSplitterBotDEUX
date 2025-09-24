#!/bin/bash

echo "Starting FileSplitterBot with Web Interface..."
echo

echo "Activating virtual environment..."
source venv/bin/activate

echo
echo "Starting Node.js progress server..."
node server.js &
SERVER_PID=$!

echo "Progress server started (PID: $SERVER_PID)"
echo

echo "Waiting 3 seconds for server to start..."
sleep 3

echo
echo "Launching Discord bot (main.py)..."
echo "Web interface available at: http://localhost:8000"
echo

# Function to clean up server on exit
cleanup() {
    echo
    echo "Shutting down progress server..."
    kill $SERVER_PID 2>/dev/null
    echo "Cleanup complete."
}

# Register cleanup function to run on script exit
trap cleanup EXIT

# Start the Python bot
python main.py