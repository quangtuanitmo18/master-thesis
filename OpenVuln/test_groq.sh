#!/bin/bash

# Script để test Groq integration với OpenVuln

echo "🔧 Testing Groq Integration for OpenVuln"
echo "========================================"
echo ""

# Check if GROQ_API_KEY is set
if [ -z "$GROQ_API_KEY" ]; then
    echo "❌ GROQ_API_KEY not set!"
    echo ""
    echo "Please set it first:"
    echo "  export GROQ_API_KEY='gsk_your_key_here'"
    echo ""
    echo "Get your API key from: https://console.groq.com/keys"
    exit 1
fi

echo "✅ GROQ_API_KEY found"
echo ""

# Test connection
echo "📡 Testing Groq API connection..."
python3 groq_helper.py

if [ $? -ne 0 ]; then
    echo ""
    echo "❌ Connection test failed!"
    exit 1
fi

echo ""
echo "✅ Connection successful!"
echo ""

# Ask user which model to test
echo "🤖 Select model to test:"
echo "  1. llama-3.1-8b-instant (Fast, cheap)"
echo "  2. llama-3.3-70b-versatile (Powerful)"
echo "  3. mixtral-8x7b-32768 (Long context)"
echo ""
read -p "Enter choice (1-3): " choice

case $choice in
    1)
        MODEL="groq:llama-3.1-8b-instant"
        DELAY=1.0
        ;;
    2)
        MODEL="groq:llama-3.3-70b-versatile"
        DELAY=2.0
        ;;
    3)
        MODEL="groq:mixtral-8x7b-32768"
        DELAY=1.5
        ;;
    *)
        echo "Invalid choice, using default: llama-3.1-8b-instant"
        MODEL="groq:llama-3.1-8b-instant"
        DELAY=1.0
        ;;
esac

echo ""
echo "📊 Running analysis with: $MODEL"
echo "⏱️  Delay: ${DELAY}s"
echo ""

# Run analysis
python3 analyze_specific_projects.py \
    --model "$MODEL" \
    --delay "$DELAY" \
    --prompt-type baseline

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Analysis completed successfully!"
    echo ""
    echo "📁 Results saved to:"
    MODEL_DIR=$(echo "$MODEL" | tr '/:' '_')
    echo "  results/baseline/$MODEL_DIR/"
else
    echo ""
    echo "❌ Analysis failed!"
    exit 1
fi
