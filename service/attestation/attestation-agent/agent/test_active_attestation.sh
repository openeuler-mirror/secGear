#!/bin/bash

# Test script for active attestation functionality

echo "Testing active attestation functionality..."

# Start the agent with active attestation enabled (10 second interval)
echo "Starting attestation agent with 10 second active attestation interval..."
../target/release/attestation-agent -s 10 &
AGENT_PID=$!

# Wait for agent to start
sleep 3

echo "Agent started with PID: $AGENT_PID"

# Test the current_token endpoint
echo "Testing /current_token endpoint..."
for i in {1..5}; do
    echo "Attempt $i:"
    curl -s http://127.0.0.1:8081/current_token
    echo ""
    sleep 5
done

# Clean up
echo "Stopping agent..."
kill $AGENT_PID

echo "Test completed."
