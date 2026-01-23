#!/usr/bin/env python3
"""
LLM API Handler Module
Handles all interactions with OpenAI API and OpenRouter for security analysis.
Supports model-specific parameters and configurations.
"""

import json
import os
import re
import sys
import time

import tiktoken
from openai import OpenAI

# Model pricing information
# Dictionary mapping model names to their pricing per 1K tokens
# Used for cost estimation when token counting is enabled
# Pricing is in USD per 1K tokens (input and output separately)
MODEL_PRICING = {
    # OpenAI Models
    "gpt-5": {
        "input": 0.00125,  # $1.25 per 1M tokens = $0.00125 per 1K tokens for input
        "output": 0.01     # $10 per 1M tokens = $0.01 per 1K tokens for output
    },
    "gpt-4": {
        "input": 0.03,  # $0.03 per 1K tokens for input
        "output": 0.06  # $0.06 per 1K tokens for output
    },
    "gpt-4-turbo": {
        "input": 0.01,  # $0.01 per 1K tokens for input
        "output": 0.03  # $0.03 per 1K tokens for output
    },
    "gpt-4o": {
        "input": 0.005,  # $0.005 per 1K tokens for input
        "output": 0.015  # $0.015 per 1K tokens for output
    },
    "gpt-4-turbo-preview": {
        "input": 0.01,  # $0.01 per 1K tokens for input
        "output": 0.03  # $0.03 per 1K tokens for output
    },
    "gpt-3.5-turbo": {
        "input": 0.001,  # $0.001 per 1K tokens for input
        "output": 0.002  # $0.002 per 1K tokens for output
    },
    "gpt-3.5-turbo-instruct": {
        "input": 0.0015,  # $0.0015 per 1K tokens for input
        "output": 0.002  # $0.002 per 1K tokens for output
    },
    # GPT-5 (via OpenRouter)
    "openai/gpt-5": {
        "input": 0.00125,  # $1.25 per 1M tokens = $0.00125 per 1K tokens for input
        "output": 0.01     # $10 per 1M tokens = $0.01 per 1K tokens for output
    },
    # Anthropic Models (via OpenRouter)
    "o3": {
        "input": 0.015,  # $0.015 per 1K tokens for input
        "output": 0.06   # $0.06 per 1K tokens for output
    },
    "o3-mini": {
        "input": 0.003,  # $0.003 per 1K tokens for input
        "output": 0.015  # $0.015 per 1K tokens for output
    },
    "o3-pro": {
        "input": 0.015,  # $0.015 per 1K tokens for input
        "output": 0.06   # $0.06 per 1K tokens for output
    },
    "o1": {
        "input": 0.015,  # $0.015 per 1K tokens for input
        "output": 0.06   # $0.06 per 1K tokens for output
    },
    "o1-pro": {
        "input": 0.015,  # $0.015 per 1K tokens for input
        "output": 0.06   # $0.06 per 1K tokens for output
    },
    "o1-mini": {
        "input": 0.003,  # $0.003 per 1K tokens for input
        "output": 0.015  # $0.015 per 1K tokens for output
    },
    "o4-mini": {
        "input": 0.003,  # $0.003 per 1K tokens for input
        "output": 0.015  # $0.015 per 1K tokens for output
    },
    # DeepSeek Models (via OpenRouter)
    "deepseek/deepseek-coder": {
        "input": 0.00014,  # $0.00014 per 1K tokens for input
        "output": 0.00028  # $0.00028 per 1K tokens for output
    },
    "deepseek/deepseek-coder-33b-instruct": {
        "input": 0.00014,  # $0.00014 per 1K tokens for input
        "output": 0.00028  # $0.00028 per 1K tokens for output
    },
    "deepseek/deepseek-coder-6.7b-instruct": {
        "input": 0.00014,  # $0.00014 per 1K tokens for input
        "output": 0.00028  # $0.00028 per 1K tokens for output
    },
    "deepseek/deepseek-llm-67b-chat": {
        "input": 0.00014,  # $0.00014 per 1K tokens for input
        "output": 0.00028  # $0.00028 per 1K tokens for output
    },
    "deepseek/deepseek-llm-7b-chat": {
        "input": 0.00014,  # $0.00014 per 1K tokens for input
        "output": 0.00028  # $0.00028 per 1K tokens for output
    },
    "deepseek/deepseek-math-7b-instruct": {
        "input": 0.00014,  # $0.00014 per 1K tokens for input
        "output": 0.00028  # $0.00028 per 1K tokens for output
    },
    "deepseek/deepseek-reasoner-7b-instruct": {
        "input": 0.00014,  # $0.00014 per 1K tokens for input
        "output": 0.00028  # $0.00028 per 1K tokens for output
    },
    "deepseek/deepseek-reasoner-34b-instruct": {
        "input": 0.00014,  # $0.00014 per 1K tokens for input
        "output": 0.00028  # $0.00028 per 1K tokens for output
    },
    "deepseek/deepseek-r1": {
        "input": 0.00014,  # $0.00014 per 1K tokens for input
        "output": 0.00028  # $0.00028 per 1K tokens for output
    },
    # Google Models (via OpenRouter)
    "google/gemini-1.5-flash": {
        "input": 0.000075,  # $0.000075 per 1K tokens for input
        "output": 0.0003    # $0.0003 per 1K tokens for output
    },
    "google/gemini-1.5-pro": {
        "input": 0.00375,   # $0.00375 per 1K tokens for input
        "output": 0.015     # $0.015 per 1K tokens for output
    },
    "google/gemini-2.0-flash-exp": {
        "input": 0.000075,  # $0.000075 per 1K tokens for input
        "output": 0.0003    # $0.0003 per 1K tokens for output
    },
    "google/gemini-2.0-pro-exp": {
        "input": 0.00375,   # $0.00375 per 1K tokens for input
        "output": 0.015     # $0.015 per 1K tokens for output
    },
    # Meta Llama Models (via OpenRouter)
    "meta-llama/llama-4-maverick": {
        "input": 0.00015,   # $0.15 per 1M tokens = $0.00015 per 1K tokens
        "output": 0.0006    # $0.60 per 1M tokens = $0.0006 per 1K tokens
    },
    # Qwen Models (via OpenRouter)
    "qwen/qwen3-235b-a22b": {
        "input": 0.00013,   # $0.13 per 1M tokens = $0.00013 per 1K tokens
        "output": 0.0006    # $0.60 per 1M tokens = $0.0006 per 1K tokens
    },
    # Mistral Models (via OpenRouter)
    "mistralai/mistral-small-3.2-24b-instruct:free": {
        "input": 0.0,       # Free tier - no cost for input
        "output": 0.0       # Free tier - no cost for output
    },
    # Meta Llama Guard Models (via OpenRouter)
    "meta-llama/llama-guard-4-12b": {
        "input": 0.0001,    # $0.0001 per 1K tokens for input
        "output": 0.0002    # $0.0002 per 1K tokens for output
    },
    # Anthropic Claude Models (via OpenRouter)
    "anthropic/claude-sonnet-4": {
        "input": 0.003,     # $0.003 per 1K tokens for input
        "output": 0.015     # $0.015 per 1K tokens for output
    },
    "anthropic/claude-opus-4": {
        "input": 0.015,     # $0.015 per 1K tokens for input
        "output": 0.075     # $0.075 per 1K tokens for output
    },
    # Meta Llama Scout Models (via OpenRouter)
    "meta-llama/llama-4-scout:free": {
        "input": 0.0,       # Free tier - no cost for input
        "output": 0.0       # Free tier - no cost for output
    },
    # Google Gemini Models (via OpenRouter)
    "google/gemini-2.5-pro": {
        "input": 0.00375,   # $0.00375 per 1K tokens for input
        "output": 0.015     # $0.015 per 1K tokens for output
    },
    "google/gemini-2.0-flash-001": {
        "input": 0.0001,    # $0.10 per 1M tokens = $0.0001 per 1K tokens
        "output": 0.0004    # $0.40 per 1M tokens = $0.0004 per 1K tokens
    },
    "google/gemini-2.5-flash": {
        "input": 0.0001,    # $0.10 per 1M tokens = $0.0001 per 1K tokens
        "output": 0.0004    # $0.40 per 1M tokens = $0.0004 per 1K tokens
    },
    # X.AI Models (via OpenRouter)
    "x-ai/grok-4": {
        "input": 0.0001,    # $0.10 per 1M tokens = $0.0001 per 1K tokens for input
        "output": 0.0004    # $0.40 per 1M tokens = $0.0004 per 1K tokens for output
    },
    # Mistral Models (via OpenRouter)
    "mistralai/codestral-2508": {
        "input": 0.0003,    # $0.30 per 1M tokens = $0.0003 per 1K tokens for input
        "output": 0.0009    # $0.90 per 1M tokens = $0.0009 per 1K tokens for output
    },
    "mistralai/mixtral-8x22b-instruct": {
        "input": 0.0009,    # $0.90 per 1M tokens = $0.0009 per 1K tokens for input
        "output": 0.0009    # $0.90 per 1M tokens = $0.0009 per 1K tokens for output
    },
    "mistralai/mixtral-8x7b-instruct": {
        "input": 0.0009,    # $0.90 per 1M tokens = $0.0009 per 1K tokens for input
        "output": 0.0009    # $0.90 per 1M tokens = $0.0009 per 1K tokens for output
    },
    # Qwen Models (via OpenRouter)
    "qwen/qwen3-235b-a22b": {
        "input": 0.00013,   # $0.13 per 1M tokens = $0.00013 per 1K tokens for input
        "output": 0.0006    # $0.60 per 1M tokens = $0.0006 per 1K tokens for output
    },
    "qwen/qwen3-coder": {
        "input": 0.0002,    # $0.20 per 1M tokens = $0.0002 per 1K tokens for input
        "output": 0.0008    # $0.80 per 1M tokens = $0.0008 per 1K tokens for output
    },
    "qwen/qwen-2.5-coder-32b-instruct": {
        "input": 0.00005,   # $0.05 per 1M tokens = $0.00005 per 1K tokens for input
        "output": 0.0002    # $0.20 per 1M tokens = $0.0002 per 1K tokens for output
    },
    # Meta Llama Models (via OpenRouter)
    "meta-llama/llama-3.1-70b-instruct": {
        "input": 0.0001,    # $0.10 per 1M tokens = $0.0001 per 1K tokens for input
        "output": 0.00028   # $0.28 per 1M tokens = $0.00028 per 1K tokens for output
    },
    "meta-llama/llama-4-scout": {
        "input": 0.0001,    # Assumed pricing per 1K tokens for input
        "output": 0.00028   # Assumed pricing per 1K tokens for output
    },
    # OpenAI OSS Models (via OpenRouter)
    "openai/gpt-oss-120b": {
        "input": 0.0005,    # Assumed pricing per 1K tokens for input
        "output": 0.0015    # Assumed pricing per 1K tokens for output
    },
    "openai/gpt-oss-20b": {
        "input": 0.0002,    # Assumed pricing per 1K tokens for input
        "output": 0.0006    # Assumed pricing per 1K tokens for output
    },
    # DeepSeek Models (via OpenRouter)
    "deepseek/deepseek-r1-distill-llama-70b": {
        "input": 0.000026,  # $0.026 per 1M tokens = $0.000026 per 1K tokens for input
        "output": 0.000104  # $0.104 per 1M tokens = $0.000104 per 1K tokens for output
    },
    "deepseek/deepseek-chat-v3.1": {
        "input": 0.00014,   # $0.14 per 1M tokens = $0.00014 per 1K tokens for input
        "output": 0.00028   # $0.28 per 1M tokens = $0.00028 per 1K tokens for output
    },
    # BigCode Models (via OpenRouter)
    "bigcode/starcoder2-15b-instruct": {
        "input": 0.00014,   # $0.14 per 1M tokens = $0.00014 per 1K tokens for input
        "output": 0.00028   # $0.28 per 1M tokens = $0.00028 per 1K tokens for output
    }
}

# Model-specific configurations
# Dictionary containing model-specific settings including:
# - max_temperature: Maximum temperature value allowed (some models have limits)
# - default_temperature: Default temperature if not specified
# - supported_parameters: List of API parameters this model supports
# - tokenizer: Which tokenizer to use for token counting (usually "gpt-4" as approximation)
# - description: Human-readable description of the model
# - provider: API provider ("openai" or "openrouter")
MODEL_CONFIGS = {
    # OpenAI Models
    "gpt-5": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "GPT-5 model with full parameter support",
        "provider": "openai"
    },
    "gpt-4": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "GPT-4 model with full parameter support",
        "provider": "openai"
    },
    "gpt-4-turbo": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "GPT-4 Turbo model with full parameter support",
        "provider": "openai"
    },
    "gpt-4o": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4o",
        "description": "GPT-4o model with full parameter support",
        "provider": "openai"
    },
    "gpt-4-turbo-preview": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "GPT-4 Turbo Preview model with full parameter support",
        "provider": "openai"
    },
    "gpt-3.5-turbo": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-3.5-turbo",
        "description": "GPT-3.5 Turbo model with full parameter support",
        "provider": "openai"
    },
    "gpt-3.5-turbo-instruct": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-3.5-turbo",
        "description": "GPT-3.5 Turbo Instruct model with full parameter support",
        "provider": "openai"
    },
    # GPT-5 (via OpenRouter)
    "openai/gpt-5": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "GPT-5 model with full parameter support via OpenRouter",
        "provider": "openrouter"
    },
    # Anthropic Models (via OpenRouter)
    "o3": {
        "max_temperature": 1.0,
        "default_temperature": 0.0,
        "supported_parameters": ["max_completion_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "o3 model with temperature range 0-1, uses max_completion_tokens, does NOT support temperature",
        "provider": "openrouter"
    },
    "o3-mini": {
        "max_temperature": 1.0,
        "default_temperature": 0.0,
        "supported_parameters": ["max_completion_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "o3-mini model with temperature range 0-1, uses max_completion_tokens, does NOT support temperature",
        "provider": "openrouter"
    },
    "o3-pro": {
        "max_temperature": 1.0,
        "default_temperature": 0.0,
        "supported_parameters": ["max_completion_tokens", "top_p", "frequency_penalty", "presence_penalty", "reasoning"],
        "tokenizer": "gpt-4",
        "description": "o3-pro model with temperature range 0-1, uses max_completion_tokens, does NOT support temperature, uses OpenAI response API",
        "provider": "openai"
    },
    "o1": {
        "max_temperature": 1.0,
        "default_temperature": 0.0,
        "supported_parameters": ["max_completion_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "o1 model with temperature range 0-1, uses max_completion_tokens, does NOT support temperature",
        "provider": "openrouter"
    },
    "o1-pro": {
        "max_temperature": 1.0,
        "default_temperature": 0.0,
        "supported_parameters": ["max_completion_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "o1-pro model with temperature range 0-1, uses max_completion_tokens, does NOT support temperature",
        "provider": "openrouter"
    },
    "o1-mini": {
        "max_temperature": 1.0,
        "default_temperature": 0.0,
        "supported_parameters": ["max_completion_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "o1-mini model with temperature range 0-1, uses max_completion_tokens, does NOT support temperature",
        "provider": "openrouter"
    },
    "o4-mini": {
        "max_temperature": 1.0,
        "default_temperature": 0.0,
        "supported_parameters": ["max_completion_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "o4-mini model with temperature range 0-1, uses max_completion_tokens, does NOT support temperature",
        "provider": "openrouter"
    },
    # DeepSeek Models (via OpenRouter)
    "deepseek/deepseek-coder": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "DeepSeek Coder model with full parameter support",
        "provider": "openrouter"
    },
    "deepseek/deepseek-coder-33b-instruct": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "DeepSeek Coder 33B Instruct model with full parameter support",
        "provider": "openrouter"
    },
    "deepseek/deepseek-coder-6.7b-instruct": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "DeepSeek Coder 6.7B Instruct model with full parameter support",
        "provider": "openrouter"
    },
    "deepseek/deepseek-llm-67b-chat": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "DeepSeek LLM 67B Chat model with full parameter support",
        "provider": "openrouter"
    },
    "deepseek/deepseek-llm-7b-chat": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "DeepSeek LLM 7B Chat model with full parameter support",
        "provider": "openrouter"
    },
    "deepseek/deepseek-math-7b-instruct": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "DeepSeek Math 7B Instruct model with full parameter support",
        "provider": "openrouter"
    },
    "deepseek/deepseek-reasoner-7b-instruct": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "DeepSeek Reasoner 7B Instruct model with full parameter support",
        "provider": "openrouter"
    },
    "deepseek/deepseek-reasoner-34b-instruct": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "DeepSeek Reasoner 34B Instruct model with full parameter support",
        "provider": "openrouter"
    },
    "deepseek/deepseek-r1": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "DeepSeek R1 model with full parameter support",
        "provider": "openrouter"
    },
    # Google Models (via OpenRouter)
    "google/gemini-1.5-flash": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Google Gemini 1.5 Flash model with full parameter support",
        "provider": "openrouter"
    },
    "google/gemini-1.5-pro": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Google Gemini 1.5 Pro model with full parameter support",
        "provider": "openrouter"
    },
    "google/gemini-2.0-flash-exp": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Google Gemini 2.0 Flash Experimental model with full parameter support",
        "provider": "openrouter"
    },
    "google/gemini-2.0-pro-exp": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Google Gemini 2.0 Pro Experimental model with full parameter support",
        "provider": "openrouter"
    },
    # Meta Llama Models (via OpenRouter)
    "meta-llama/llama-4-maverick": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Meta Llama 4 Maverick model (free tier) with full parameter support",
        "provider": "openrouter"
    },
    # Qwen Models (via OpenRouter)
    "qwen/qwen3-235b-a22b": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Qwen 3.3B model (free tier) with full parameter support",
        "provider": "openrouter"
    },
    # Mistral Models (via OpenRouter)
    "mistralai/mistral-small-3.2-24b-instruct:free": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Mistral Small 3.2B Instruct model (free tier) with full parameter support",
        "provider": "openrouter"
    },
    # Meta Llama Guard Models (via OpenRouter)
    "meta-llama/llama-guard-4-12b": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Meta Llama Guard 4 12B model with full parameter support",
        "provider": "openrouter"
    },
    # Anthropic Claude Models (via OpenRouter)
    "anthropic/claude-sonnet-4": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Anthropic Claude Sonnet 4 model with full parameter support",
        "provider": "openrouter"
    },
    "anthropic/claude-opus-4": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Anthropic Claude Opus 4 model with full parameter support",
        "provider": "openrouter"
    },
    # Meta Llama Scout Models (via OpenRouter)
    "meta-llama/llama-4-scout:free": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Meta Llama Scout 4 model (free tier) with full parameter support",
        "provider": "openrouter"
    },
    # Google Gemini Models (via OpenRouter)
    "google/gemini-2.5-pro": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Google Gemini 2.5 Pro model with full parameter support",
        "provider": "openrouter"
    },
    "google/gemini-2.0-flash-001": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Google Gemini 2.0 Flash model with full parameter support",
        "provider": "openrouter"
    },
    "google/gemini-2.5-flash": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Google Gemini 2.5 Flash model with full parameter support",
        "provider": "openrouter"
    },
    # X.AI Models (via OpenRouter)
    "x-ai/grok-4": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "X.AI Grok-4 model with full parameter support",
        "provider": "openrouter"
    },
    # Mistral Models (via OpenRouter)
    "mistralai/codestral-2508": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Mistral Codestral 2508 model specialized for coding tasks with full parameter support",
        "provider": "openrouter"
    },
    "mistralai/mixtral-8x22b-instruct": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Mistral Mixtral 8x22B Instruct model with full parameter support",
        "provider": "openrouter"
    },
    "mistralai/mixtral-8x7b-instruct": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Mistral Mixtral 8x7B Instruct model with full parameter support",
        "provider": "openrouter"
    },
    # Qwen Models (via OpenRouter)
    "qwen/qwen3-235b-a22b": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Qwen3 235B A22B MoE model with full parameter support",
        "provider": "openrouter"
    },
    "qwen/qwen3-coder": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Qwen3 Coder 480B MoE model specialized for coding tasks with full parameter support",
        "provider": "openrouter"
    },
    "qwen/qwen-2.5-coder-32b-instruct": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Qwen2.5 Coder 32B Instruct model specialized for coding tasks with full parameter support",
        "provider": "openrouter"
    },
    # Meta Llama Models (via OpenRouter)
    "meta-llama/llama-3.1-70b-instruct": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Meta Llama 3.1 70B Instruct model with full parameter support",
        "provider": "openrouter"
    },
    "meta-llama/llama-4-scout": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Meta Llama Scout 4 model (free tier) with full parameter support",
        "provider": "openrouter"
    },
    # DeepSeek Models (via OpenRouter)
    "deepseek/deepseek-r1-distill-llama-70b": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "DeepSeek R1 Distill Llama 70B model with full parameter support",
        "provider": "openrouter"
    },
    "deepseek/deepseek-chat-v3.1": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "DeepSeek Chat v3.1 model with full parameter support",
        "provider": "openrouter"
    },
    # BigCode Models (via OpenRouter)
    "bigcode/starcoder2-15b-instruct": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "BigCode StarCoder2 15B Instruct model specialized for coding tasks with full parameter support",
        "provider": "openrouter"
    },
    "openai/gpt-oss-120b": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "OpenAI GPT-OSS 120B model with full parameter support",
        "provider": "openrouter"
    },
    "openai/gpt-oss-20b": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "OpenAI GPT-OSS 20B model with full parameter support",
        "provider": "openrouter"
    },
    # CLIProxyAPI Models (local proxy)
    "gemini-2.5-pro": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Google Gemini 2.5 Pro via CLIProxyAPI",
        "provider": "cliproxyapi"
    },
    "gemini-2.5-flash": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Google Gemini 2.5 Flash via CLIProxyAPI",
        "provider": "cliproxyapi"
    },
    "gemini-2.5-flash-lite": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Google Gemini 2.5 Flash Lite via CLIProxyAPI",
        "provider": "cliproxyapi"
    },
    "gemini-3-pro-preview": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Google Gemini 3 Pro Preview via CLIProxyAPI",
        "provider": "cliproxyapi"
    },
    "gemini-3-flash-preview": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Google Gemini 3 Flash Preview via CLIProxyAPI",
        "provider": "cliproxyapi"
    }
}

def is_openai_model(model: str) -> bool:
    """
    Check if a model is an OpenAI model (vs OpenRouter).
    
    This determines which API endpoint to use. OpenAI models use the standard
    OpenAI API, while other models (DeepSeek, Gemini, etc.) go through OpenRouter.
    
    Args:
        model (str): Model name (e.g., "gpt-4o", "deepseek/deepseek-r1")
        
    Returns:
        bool: True if it's an OpenAI model, False if it uses OpenRouter
    """
    # Special case: o3-pro uses OpenAI API but requires special handling (response API)
    if model == "o3-pro":
        return True
    
    # Check provider field in model configuration
    config = get_model_config(model)
    return config.get("provider", "openai") == "openai"

def is_cliproxyapi_model(model: str) -> bool:
    """
    Check if a model should use CLIProxyAPI (local proxy server).
    
    Models with prefix "cliproxy:" will use CLIProxyAPI.
    This allows easy routing to local CLIProxyAPI instance.
    
    Args:
        model (str): Model name
        
    Returns:
        bool: True if model should use CLIProxyAPI, False otherwise
    """
    # Use prefix "cliproxy:" to indicate CLIProxyAPI models
    if model.startswith("cliproxy:"):
        return True
    
    return False

def get_model_config(model: str) -> dict:
    """
    Get configuration dictionary for a specific model.
    
    Retrieves model-specific settings like temperature limits, supported parameters,
    tokenizer type, and API provider. Used throughout the module for parameter validation
    and API routing.
    
    Args:
        model (str): Model name (must be a key in MODEL_CONFIGS)
        
    Returns:
        dict: Model configuration containing:
            - max_temperature: Maximum allowed temperature
            - default_temperature: Default temperature value
            - supported_parameters: List of supported API parameters
            - tokenizer: Tokenizer name for token counting
            - description: Model description
            - provider: API provider ("openai" or "openrouter")
        
    Raises:
        ValueError: If model is not found in MODEL_CONFIGS
    """
    if model not in MODEL_CONFIGS:
        raise ValueError(f"Model '{model}' is not supported. Supported models: {list(MODEL_CONFIGS.keys())}")
    
    return MODEL_CONFIGS[model]

def validate_model_parameters(model: str, **kwargs) -> dict:
    """
    Validate and normalize API parameters for a specific model.
    
    Different models support different parameters and have different limits.
    This function:
    1. Validates temperature is within model's allowed range
    2. Maps max_tokens to max_completion_tokens for models that require it (o1, o3 series)
    3. Filters out unsupported parameters
    4. Applies default values where appropriate
    
    Args:
        model (str): Model name
        **kwargs: Parameters to validate (temperature, max_tokens, top_p, etc.)
        
    Returns:
        dict: Validated and normalized parameters ready for API call
        
    Raises:
        ValueError: If temperature is out of allowed range
    """
    config = get_model_config(model)
    validated_params = {}
    
    # Only add temperature if supported by the model
    # Some models (o1, o3 series) don't support temperature parameter
    if 'temperature' in config['supported_parameters']:
        if 'temperature' in kwargs:
            temp = kwargs['temperature']
            max_temp = config['max_temperature']
            # Validate temperature is within allowed range
            if not (0 <= temp <= max_temp):
                raise ValueError(f"Temperature must be between 0 and {max_temp} for model {model}. Got: {temp}")
            validated_params['temperature'] = temp
        else:
            # Use default temperature if not specified
            validated_params['temperature'] = config['default_temperature']
    
    # Map max_tokens to max_completion_tokens for models that require it
    # OpenAI o1/o3 series use max_completion_tokens instead of max_tokens
    if 'max_tokens' in kwargs and 'max_completion_tokens' in config['supported_parameters']:
        validated_params['max_completion_tokens'] = kwargs['max_tokens']
    elif 'max_tokens' in kwargs:
        validated_params['max_tokens'] = kwargs['max_tokens']
    
    # Validate other parameters against model's supported list
    supported_params = config['supported_parameters']
    for param, value in kwargs.items():
        if param == 'max_tokens' and 'max_completion_tokens' in supported_params:
            continue  # already mapped above
        if param in supported_params:
            validated_params[param] = value
        else:
            # Warn but don't fail - allows graceful degradation
            print(f"Warning: Parameter '{param}' is not supported for model {model}. Supported: {supported_params}")
    
    return validated_params

def count_tokens(text: str, model: str) -> int:
    """
    Count the number of tokens in a text string using the model's tokenizer.
    
    Token counting is important for:
    - Cost estimation (pricing is per token)
    - Staying within model context limits
    - Monitoring API usage
    
    Uses tiktoken library which provides accurate token counting for OpenAI models.
    For non-OpenAI models, uses GPT-4 tokenizer as approximation (most models use
    similar tokenization schemes).
    
    Args:
        text (str): Text to count tokens for
        model (str): Model name (determines which tokenizer to use)
        
    Returns:
        int: Number of tokens in the text
    """
    try:
        # Get the tokenizer name from model config
        config = get_model_config(model)
        tokenizer_name = config['tokenizer']
        # Create encoding and count tokens
        encoding = tiktoken.encoding_for_model(tokenizer_name)
        return len(encoding.encode(text))
    except Exception as e:
        # Fallback to GPT-4 tokenizer if model-specific tokenizer fails
        print(f"Warning: Could not get tokenizer for model {model}, using GPT-4 tokenizer as fallback: {e}")
        try:
            # GPT-4 tokenizer is a good approximation for most models
            encoding = tiktoken.encoding_for_model("gpt-4")
            return len(encoding.encode(text))
        except Exception as fallback_error:
            # Final fallback: rough character-based estimation
            print(f"Error: Could not use GPT-4 tokenizer as fallback: {fallback_error}")
            # Rough estimation: 1 token ≈ 4 characters for English text
            # This is less accurate but better than failing completely
            estimated_tokens = len(text) // 4
            print(f"Using rough estimation: {estimated_tokens} tokens (based on character count)")
            return estimated_tokens

def calculate_cost(input_tokens: int, output_tokens: int, model: str) -> float:
    """
    Calculate the estimated cost of an API call based on token counts.
    
    Pricing is typically different for input and output tokens, with output
    tokens usually being more expensive. Costs are calculated per 1K tokens.
    
    Args:
        input_tokens (int): Number of input tokens (prompt)
        output_tokens (int): Number of output tokens (response)
        model (str): Model name (must be in MODEL_PRICING)
        
    Returns:
        float: Estimated cost in USD
    """
    if model not in MODEL_PRICING:
        # Fallback to GPT-4 pricing if model pricing not available
        print(f"Warning: No pricing information available for model {model}. Using GPT-4 pricing as fallback.")
        model = "gpt-4"
    
    # Calculate costs separately for input and output
    # Pricing is per 1K tokens, so divide by 1000
    input_cost = (input_tokens / 1000) * MODEL_PRICING[model]["input"]
    output_cost = (output_tokens / 1000) * MODEL_PRICING[model]["output"]
    return input_cost + output_cost

def send_to_llm(prompt, model, temperature=None, enable_token_counting=True, **kwargs):
    """
    Main entry point for sending prompts to LLM APIs.
    
    This function routes requests to the appropriate API provider:
    - OpenAI (for OpenAI models)
    - OpenRouter (for models via OpenRouter)
    - CLIProxyAPI (for local proxy, models with "cliproxy:" prefix)
    
    Args:
        prompt (str): The prompt text to send to the LLM
        model (str): Model name (e.g., "gpt-4o", "deepseek/deepseek-r1", "o3-pro", "cliproxy:gpt-4o")
        temperature (float, optional): Temperature for response generation (0.0-2.0)
                                       Lower = more deterministic, Higher = more creative
        enable_token_counting (bool): Whether to count tokens and calculate cost
                                     Disable for faster execution if cost tracking not needed
        **kwargs: Additional model-specific parameters:
            - max_tokens: Maximum tokens in response
            - top_p: Nucleus sampling parameter
            - frequency_penalty: Penalize frequent tokens
            - presence_penalty: Penalize new tokens
    
    Returns:
        str: The LLM's response text
        
    Note:
        - OpenAI models: Uses standard OpenAI API
        - OpenRouter models: Routes through OpenRouter API (supports many providers)
        - CLIProxyAPI models: Routes through local CLIProxyAPI (models with "cliproxy:" prefix)
        - o3-pro: Uses special OpenAI response API (not chat completion)
    """
    # Special handling for o3-pro model (uses response API instead of chat completion)
    if model == "o3-pro":
        return send_to_o3_pro(prompt, model, temperature, enable_token_counting, **kwargs)
    
    # Check if model should use CLIProxyAPI (local proxy) - check this before OpenAI/OpenRouter
    if is_cliproxyapi_model(model):
        # Remove "cliproxy:" prefix if present
        actual_model = model.replace("cliproxy:", "")
        return send_to_cliproxyapi(prompt, actual_model, temperature, enable_token_counting, **kwargs)
    
    # Route to appropriate provider based on model configuration
    if is_openai_model(model):
        return send_to_openai(prompt, model, temperature, enable_token_counting, **kwargs)
    else:
        return send_to_openrouter(prompt, model, temperature, enable_token_counting, **kwargs)

def send_to_openai(prompt, model, temperature=None, enable_token_counting=True, **kwargs):
    """
    Send a prompt to OpenAI API and return the response.
    
    Args:
        prompt (str): The prompt to send
        model (str): The model to use
        temperature (float, optional): Temperature for response generation
        enable_token_counting (bool): Whether to count tokens and calculate cost
        **kwargs: Additional model-specific parameters (max_tokens, top_p, etc.)
    
    Returns:
        str: The response from the model
    """
    try:
        # Create OpenAI client with timeout settings
        # Uses OPENAI_API_KEY from environment variable automatically
        client = OpenAI(
            timeout=30.0,  # 30 second timeout to prevent hanging
            max_retries=2  # Retry up to 2 times on transient failures
        )
    except Exception as e:
        print(f"Error creating OpenAI client: {e}")
        print("This might be due to network/SSL issues. Please check your internet connection.")
        raise
    
    # Validate and normalize parameters for the specific model
    # This ensures parameters are compatible with the model's capabilities
    try:
        params = {'temperature': temperature} if temperature is not None else {}
        params.update(kwargs)
        validated_params = validate_model_parameters(model, **params)
    except ValueError as e:
        print(f"Parameter validation error: {e}")
        raise
    
    # Initialize token counts for cost tracking
    input_tokens = None
    output_tokens = None
    cost = None
    
    # Count input tokens if enabled (for cost estimation)
    if enable_token_counting:
        try:
            input_tokens = count_tokens(prompt, model)
        except Exception as e:
            print(f"Warning: Could not count input tokens: {e}")
            input_tokens = None
    
    # Prepare API call parameters in OpenAI chat completion format
    api_params = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a security assistant."},
            {"role": "user", "content": prompt}
        ],
        **validated_params  # Include validated parameters (temperature, max_tokens, etc.)
    }
    
    # Make the API call to OpenAI chat completions endpoint
    try:
        response = client.chat.completions.create(**api_params)
    except Exception as e:
        print(f"Error making API call: {e}")
        print("This might be due to network issues, API key problems, or rate limiting.")
        raise
    
    # Count output tokens if enabled (for cost estimation)
    if enable_token_counting:
        try:
            output_tokens = count_tokens(response.choices[0].message.content, model)
        except Exception as e:
            print(f"Warning: Could not count output tokens: {e}")
            output_tokens = None
    
    # Calculate cost if we have token counts
    if input_tokens is not None and output_tokens is not None:
        try:
            cost = calculate_cost(input_tokens, output_tokens, model)
        except Exception as e:
            print(f"Warning: Could not calculate cost: {e}")
            cost = None
    
    # Print token usage and cost information in a formatted way
    print("\n" + "="*50)
    print(f"OpenAI API Call Summary (Model: {model})")
    print("-"*50)
    if input_tokens is not None:
        print(f"Input tokens:  {input_tokens:>8}")
    else:
        print(f"Input tokens:  {'N/A':>8} (counting disabled/failed)")
    
    if output_tokens is not None:
        print(f"Output tokens: {output_tokens:>8}")
    else:
        print(f"Output tokens: {'N/A':>8} (counting disabled/failed)")
    
    if input_tokens is not None and output_tokens is not None:
        print(f"Total tokens:  {input_tokens + output_tokens:>8}")
    else:
        print(f"Total tokens:  {'N/A':>8} (counting disabled/failed)")
    
    print("-"*50)
    if cost is not None:
        print(f"Estimated cost: ${cost:.4f}")
    else:
        print(f"Estimated cost: N/A (counting disabled/failed)")
    
    # Print model-specific information
    config = get_model_config(model)
    print(f"Model config: {config['description']}")
    print(f"Parameters used: {validated_params}")
    print("="*50 + "\n")
    
    return response.choices[0].message.content

def send_to_openrouter(prompt, model, temperature=None, enable_token_counting=True, **kwargs):
    """
    Send a prompt to OpenRouter API and return the response.
    
    Args:
        prompt (str): The prompt to send
        model (str): The model to use
        temperature (float, optional): Temperature for response generation
        enable_token_counting (bool): Whether to count tokens and calculate cost
        **kwargs: Additional model-specific parameters (max_tokens, top_p, etc.)
    
    Returns:
        str: The response from the model
    """
    try:
        # Create OpenRouter client with timeout settings
        # OpenRouter provides unified API access to multiple LLM providers
        # Uses OPENROUTER_API_KEY from environment variable
        client = OpenAI(
            base_url="https://openrouter.ai/api/v1",  # OpenRouter API endpoint
            api_key=os.getenv('OPENROUTER_API_KEY'),
            timeout=30.0,  # 30 second timeout
            max_retries=2  # Retry up to 2 times on transient failures
        )
    except Exception as e:
        print(f"Error creating OpenRouter client: {e}")
        print("This might be due to network/SSL issues. Please check your internet connection.")
        raise
    
    # Validate and normalize parameters for the specific model
    # OpenRouter models may have different parameter requirements than OpenAI
    try:
        params = {'temperature': temperature} if temperature is not None else {}
        params.update(kwargs)
        validated_params = validate_model_parameters(model, **params)
    except ValueError as e:
        print(f"Parameter validation error: {e}")
        raise
    
    # Initialize token counts for cost tracking
    input_tokens = None
    output_tokens = None
    cost = None
    
    # Count input tokens if enabled (for cost estimation)
    if enable_token_counting:
        try:
            input_tokens = count_tokens(prompt, model)
        except Exception as e:
            print(f"Warning: Could not count input tokens: {e}")
            input_tokens = None
    
    # Prepare API call parameters in OpenAI-compatible format
    # OpenRouter uses the same API format as OpenAI for compatibility
    api_params = {
        "model": model,  # Model name includes provider prefix (e.g., "deepseek/deepseek-r1")
        "messages": [
            {"role": "system", "content": "You are a security assistant."},
            {"role": "user", "content": prompt}
        ],
        **validated_params  # Include validated parameters
    }
    
    # Make the API call to OpenRouter
    try:
        response = client.chat.completions.create(**api_params)
    except Exception as e:
        print(f"Error making OpenRouter API call: {e}")
        print("This might be due to network issues, API key problems, or rate limiting.")
        raise
    
    # Count output tokens if enabled (for cost estimation)
    if enable_token_counting:
        try:
            output_tokens = count_tokens(response.choices[0].message.content, model)
        except Exception as e:
            print(f"Warning: Could not count output tokens: {e}")
            output_tokens = None
    
    # Calculate cost if we have token counts
    if input_tokens is not None and output_tokens is not None:
        try:
            cost = calculate_cost(input_tokens, output_tokens, model)
        except Exception as e:
            print(f"Warning: Could not calculate cost: {e}")
            cost = None
    
    # Print token usage and cost information in a formatted way
    print("\n" + "="*50)
    print(f"OpenRouter API Call Summary (Model: {model})")
    print("-"*50)
    if input_tokens is not None:
        print(f"Input tokens:  {input_tokens:>8}")
    else:
        print(f"Input tokens:  {'N/A':>8} (counting disabled/failed)")
    
    if output_tokens is not None:
        print(f"Output tokens: {output_tokens:>8}")
    else:
        print(f"Output tokens: {'N/A':>8} (counting disabled/failed)")
    
    if input_tokens is not None and output_tokens is not None:
        print(f"Total tokens:  {input_tokens + output_tokens:>8}")
    else:
        print(f"Total tokens:  {'N/A':>8} (counting disabled/failed)")
    
    print("-"*50)
    if cost is not None:
        print(f"Estimated cost: ${cost:.4f}")
    else:
        print(f"Estimated cost: N/A (counting disabled/failed)")
    
    # Print model-specific information
    config = get_model_config(model)
    print(f"Model config: {config['description']}")
    print(f"Parameters used: {validated_params}")
    print("="*50 + "\n")
    
    return response.choices[0].message.content

def send_to_o3_pro(prompt, model, temperature=None, enable_token_counting=True, **kwargs):
    """
    Send a prompt to o3-pro model using OpenAI's response API (not chat completion).
    
    Args:
        prompt (str): The prompt to send
        model (str): The model to use (should be "o3-pro")
        temperature (float, optional): Temperature for response generation
        enable_token_counting (bool): Whether to count tokens and calculate cost
        **kwargs: Additional model-specific parameters (max_tokens, top_p, etc.)
    
    Returns:
        str: The response from the model
    """
    try:
        # Create OpenAI client with longer timeout settings
        # o3-pro uses reasoning which can take longer than standard chat completions
        client = OpenAI(
            timeout=60.0,  # Longer timeout (60s) for o3-pro as reasoning takes more time
            max_retries=2
        )
    except Exception as e:
        print(f"Error creating OpenAI client: {e}")
        print("This might be due to network/SSL issues. Please check your internet connection.")
        raise
    
    # Validate and normalize parameters for o3-pro
    # Note: o3-pro doesn't support temperature parameter
    try:
        params = {'temperature': temperature} if temperature is not None else {}
        params.update(kwargs)
        validated_params = validate_model_parameters(model, **params)
    except ValueError as e:
        print(f"Parameter validation error: {e}")
        raise
    
    # Initialize token counts for cost tracking
    input_tokens = None
    output_tokens = None
    cost = None
    
    # Count input tokens if enabled (for cost estimation)
    if enable_token_counting:
        try:
            input_tokens = count_tokens(prompt, model)
        except Exception as e:
            print(f"Warning: Could not count input tokens: {e}")
            input_tokens = None
    
    # Prepare API call parameters for o3-pro response API
    # o3-pro uses a different API endpoint (responses.create) than standard chat completions
    api_params = {
        "model": model,
        "input": [  # Uses "input" instead of "messages" for response API
            {"role": "system", "content": "You are a security assistant specialized in vulnerability analysis."},
            {"role": "user", "content": prompt}
        ],
        "reasoning": {"effort": "high"},  # Enable high reasoning effort for best performance
        **validated_params
    }
    
    # Make the API call using responses API (not chat completion)
    # This is a special API endpoint for reasoning models like o3-pro
    try:
        response = client.responses.create(**api_params)
    except Exception as e:
        print(f"Error making o3-pro API call: {e}")
        print("This might be due to network issues, API key problems, or rate limiting.")
        raise
    
    # Count output tokens if enabled (for cost estimation)
    if enable_token_counting:
        try:
            # o3-pro response API returns output_text instead of choices[0].message.content
            output_tokens = count_tokens(response.output_text, model)
        except Exception as e:
            print(f"Warning: Could not count output tokens: {e}")
            output_tokens = None
    
    # Calculate cost if we have token counts
    if input_tokens is not None and output_tokens is not None:
        try:
            cost = calculate_cost(input_tokens, output_tokens, model)
        except Exception as e:
            print(f"Warning: Could not calculate cost: {e}")
            cost = None
    
    # Print token usage and cost information in a formatted way
    print("\n" + "="*50)
    print(f"o3-pro Response API Call Summary (Model: {model})")
    print("-"*50)
    if input_tokens is not None:
        print(f"Input tokens:  {input_tokens:>8}")
    else:
        print(f"Input tokens:  {'N/A':>8} (counting disabled/failed)")
    
    if output_tokens is not None:
        print(f"Output tokens: {output_tokens:>8}")
    else:
        print(f"Output tokens: {'N/A':>8} (counting disabled/failed)")
    
    if input_tokens is not None and output_tokens is not None:
        print(f"Total tokens:  {input_tokens + output_tokens:>8}")
    else:
        print(f"Total tokens:  {'N/A':>8} (counting disabled/failed)")
    
    print("-"*50)
    if cost is not None:
        print(f"Estimated cost: ${cost:.4f}")
    else:
        print(f"Estimated cost: N/A (counting disabled/failed)")
    
    # Print model-specific information
    config = get_model_config(model)
    print(f"Model config: {config['description']}")
    print(f"Parameters used: {validated_params}")
    print(f"Reasoning effort: High")
    print("="*50 + "\n")
    
    return response.output_text

def send_to_cliproxyapi(prompt, model, temperature=None, enable_token_counting=True, **kwargs):
    """
    Send a prompt to CLIProxyAPI (local proxy server).
    
    CLIProxyAPI is a local proxy service that provides unified access to multiple LLM providers.
    This function connects to a local instance running on http://127.0.0.1:8317/v1
    
    Includes automatic retry logic with exponential backoff for rate limit errors (429).
    
    Args:
        prompt (str): The prompt to send
        model (str): The model to use (model name as understood by CLIProxyAPI)
        temperature (float, optional): Temperature for response generation
        enable_token_counting (bool): Whether to count tokens and calculate cost
        **kwargs: Additional model-specific parameters (max_tokens, top_p, etc.)
    
    Returns:
        str: The response from the model
    """
    try:
        # Create CLIProxyAPI client pointing to local server
        # Hard-coded for local development
        client = OpenAI(
            base_url="http://127.0.0.1:8317/v1",  # Local CLIProxyAPI endpoint
            api_key="your-api-key-1",  # Hard-coded API key for local use
            timeout=30.0,  # 30 second timeout
            max_retries=2  # Retry up to 2 times on transient failures
        )
    except Exception as e:
        print(f"Error creating CLIProxyAPI client: {e}")
        print("This might be due to network issues or the local server not running.")
        print("Make sure CLIProxyAPI is running on http://127.0.0.1:8317")
        raise
    
    # Validate and normalize parameters for the specific model
    # CLIProxyAPI models may not be in MODEL_CONFIGS, so use default parameters if validation fails
    validated_params = {}
    try:
        params = {'temperature': temperature} if temperature is not None else {}
        params.update(kwargs)
        validated_params = validate_model_parameters(model, **params)
    except ValueError as e:
        # If model not in config, use default parameters (CLIProxyAPI will handle validation)
        print(f"Warning: Model '{model}' not in config, using default parameters: {e}")
        # Use default parameters that work with most models
        if temperature is not None:
            validated_params['temperature'] = temperature
        if 'max_tokens' in kwargs:
            validated_params['max_tokens'] = kwargs['max_tokens']
        # Add other common parameters
        for param in ['top_p', 'frequency_penalty', 'presence_penalty']:
            if param in kwargs:
                validated_params[param] = kwargs[param]
    
    # Initialize token counts for cost tracking
    input_tokens = None
    output_tokens = None
    cost = None
    
    # Count input tokens if enabled (for cost estimation)
    if enable_token_counting:
        try:
            input_tokens = count_tokens(prompt, model)
        except Exception as e:
            print(f"Warning: Could not count input tokens: {e}")
            input_tokens = None
    
    # Prepare API call parameters in OpenAI-compatible format
    # CLIProxyAPI uses the same API format as OpenAI for compatibility
    # Ensure stream is always False (non-streaming mode)
    api_params = {
        "model": model,  # Model name as understood by CLIProxyAPI
        "messages": [
            {"role": "system", "content": "You are a security assistant."},
            {"role": "user", "content": prompt}
        ],
        # **validated_params,  # Include validated parameters first
        "stream": False  # Explicitly disable streaming (CLIProxyAPI requires non-streaming for this use case)
        # Put stream last to ensure it's always False, even if validated_params has stream
    }
    
    # Retry logic with exponential backoff for rate limit errors (429) and server errors (500)
    max_retries = 5
    base_delay = 5  # Base delay in seconds (increased from 2)
    max_delay = 120  # Maximum delay in seconds (increased from 60)
    response = None
    
    for attempt in range(max_retries):
        try:
            # Make the API call to CLIProxyAPI
            response = client.chat.completions.create(**api_params)
            
            # Success - break out of retry loop
            break
            
        except Exception as e:
            # Check if it's a rate limit error (429) or server error (500)
            is_rate_limit = False
            is_server_error = False
            retry_after = None
            error_detail = None
            status_code = None
            
            # Try to extract error details
            if hasattr(e, 'response'):
                try:
                    if hasattr(e.response, 'status_code'):
                        status_code = e.response.status_code
                    if hasattr(e.response, 'json'):
                        error_detail = e.response.json()
                    elif hasattr(e.response, 'text'):
                        try:
                            # Try to parse as JSON first
                            error_detail = json.loads(e.response.text) if e.response.text else None
                        except (json.JSONDecodeError, ValueError):
                            # If not JSON, keep as string
                            error_detail = e.response.text
                except:
                    pass
            
            # Check error message/code for rate limit or server errors
            error_msg = str(e)
            if '429' in error_msg or 'rate limit' in error_msg.lower() or 'RATE_LIMIT' in error_msg:
                is_rate_limit = True
            elif '500' in error_msg or 'internal_server_error' in error_msg.lower() or 'server_error' in error_msg.lower():
                is_server_error = True
            elif status_code:
                if status_code == 429:
                    is_rate_limit = True
                elif status_code == 500 or status_code >= 502:  # 500, 502, 503, 504
                    is_server_error = True
            elif error_detail:
                # Check error_detail dict for error indicators
                if isinstance(error_detail, dict):
                    error_obj = error_detail.get('error', {})
                    error_code = error_obj.get('code')
                    if error_code == 429 or 'RATE_LIMIT' in str(error_obj) or 'RESOURCE_EXHAUSTED' in str(error_obj):
                        is_rate_limit = True
                        # Try to extract retry-after time from message
                        message = error_obj.get('message', '')
                        if 'reset after' in message.lower() or 'quota will reset' in message.lower():
                            # Extract time like "reset after 2s" or "quota will reset after 2s"
                            match = re.search(r'reset after (\d+)s?', message.lower())
                            if match:
                                retry_after = int(match.group(1))
                    elif error_code == 500 or 'internal_server_error' in str(error_obj).lower() or 'server_error' in str(error_obj).lower():
                        is_server_error = True
                elif isinstance(error_detail, str):
                    if '429' in error_detail or 'rate limit' in error_detail.lower():
                        is_rate_limit = True
                    elif '500' in error_detail or 'internal_server_error' in error_detail.lower():
                        is_server_error = True
            
            # If retryable error (rate limit or server error) and not last attempt, retry with backoff
            if (is_rate_limit or is_server_error) and attempt < max_retries - 1:
                # Calculate delay: use retry_after if available, otherwise exponential backoff
                if retry_after:
                    delay = min(retry_after + 1, max_delay)  # Add 1 second buffer
                else:
                    delay = min(base_delay * (2 ** attempt), max_delay)  # Exponential backoff
                
                error_type = "Rate limit" if is_rate_limit else "Server error"
                print(f"⚠️ {error_type} hit (attempt {attempt + 1}/{max_retries}). Waiting {delay}s before retry...")
                if retry_after:
                    print(f"   Server indicates quota resets after {retry_after}s")
                time.sleep(delay)
                continue
            else:
                # Not a retryable error, or last attempt - raise the error
                # Better error handling to show full error details
                error_msg = str(e)
                if error_detail:
                    print(f"Error making CLIProxyAPI call: {error_detail}")
                else:
                    print(f"Error making CLIProxyAPI call: {error_msg}")
                print("This might be due to network issues, API key problems, or the server not running.")
                print("Make sure CLIProxyAPI is running on http://127.0.0.1:8317")
                print(f"Endpoint: http://127.0.0.1:8317/v1/chat/completions")
                print(f"API Key: your-api-key-1")
                raise
    
    # If we exhausted all retries without success, raise an error
    if response is None:
        raise Exception("Failed to get response from CLIProxyAPI after all retry attempts")
    
    # Count output tokens if enabled (for cost estimation)
    if enable_token_counting:
        try:
            output_tokens = count_tokens(response.choices[0].message.content, model)
        except Exception as e:
            print(f"Warning: Could not count output tokens: {e}")
            output_tokens = None
    
    # Calculate cost if we have token counts
    if input_tokens is not None and output_tokens is not None:
        try:
            cost = calculate_cost(input_tokens, output_tokens, model)
        except Exception as e:
            print(f"Warning: Could not calculate cost: {e}")
            cost = None
    
    # Print token usage and cost information in a formatted way
    print("\n" + "="*50)
    print(f"CLIProxyAPI Call Summary (Model: {model})")
    print("-"*50)
    if input_tokens is not None:
        print(f"Input tokens:  {input_tokens:>8}")
    else:
        print(f"Input tokens:  {'N/A':>8} (counting disabled/failed)")
    
    if output_tokens is not None:
        print(f"Output tokens: {output_tokens:>8}")
    else:
        print(f"Output tokens: {'N/A':>8} (counting disabled/failed)")
    
    if input_tokens is not None and output_tokens is not None:
        print(f"Total tokens:  {input_tokens + output_tokens:>8}")
    else:
        print(f"Total tokens:  {'N/A':>8} (counting disabled/failed)")
    
    print("-"*50)
    if cost is not None:
        print(f"Estimated cost: ${cost:.4f}")
    else:
        print(f"Estimated cost: N/A (counting disabled/failed)")
    
    # Print model-specific information
    try:
        config = get_model_config(model)
        print(f"Model config: {config['description']}")
    except:
        print(f"Model config: Using CLIProxyAPI local proxy")
    print(f"Parameters used: {validated_params}")
    print("="*50 + "\n")
    
    return response.choices[0].message.content

def list_supported_models():
    """
    List all supported models with their configurations.
    
    Returns:
        dict: Dictionary of model configurations
    """
    return MODEL_CONFIGS

def get_model_info(model: str) -> dict:
    """
    Get detailed information about a specific model.
    
    Args:
        model (str): Model name
        
    Returns:
        dict: Model information including pricing and configuration
    """
    if model not in MODEL_CONFIGS:
        raise ValueError(f"Model '{model}' is not supported")
    
    config = MODEL_CONFIGS[model]
    pricing = MODEL_PRICING.get(model, {})
    
    return {
        "model": model,
        "config": config,
        "pricing": pricing,
        "supported_parameters": config["supported_parameters"],
        "max_temperature": config["max_temperature"],
        "default_temperature": config["default_temperature"],
        "provider": config["provider"]
    }

def test_model_connectivity(model_name="gpt-4o"):
    """
    Test if a model is accessible with the current API key.
    
    Args:
        model_name (str): The model to test
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Check CLIProxyAPI models first (skip config validation)
        if is_cliproxyapi_model(model_name):
            client = OpenAI(
                base_url="http://127.0.0.1:8317/v1",
                api_key="your-api-key-1",
                timeout=10.0
            )
            print("✓ CLIProxyAPI client created successfully")
            return True
        
        # Check OpenAI models
        if is_openai_model(model_name):
            client = OpenAI(timeout=10.0)
            print("✓ OpenAI client created successfully")
        else:
            # OpenRouter models
            client = OpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=os.getenv('OPENROUTER_API_KEY'),
                timeout=10.0
            )
            print("✓ OpenRouter client created successfully")
        return True
    except Exception as e:
        print(f"✗ Error creating client: {e}")
        print("Please check your internet connection and API key configuration.")
        return False

def test_openrouter_connectivity():
    """
    Test OpenRouter connectivity specifically.
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=os.getenv('OPENROUTER_API_KEY'),
            timeout=10.0
        )
        print("✓ OpenRouter client created successfully")
        return True
    except Exception as e:
        print(f"✗ Error creating OpenRouter client: {e}")
        print("Please check your internet connection and OpenRouter API key configuration.")
        return False

def validate_api_key():
    """
    Validate that required API keys are set in environment variables.
    
    This function checks for both OpenAI and OpenRouter API keys since the system
    supports models from both providers. OpenAI key is required for OpenAI models,
    OpenRouter key is required for models accessed through OpenRouter.
    
    Returns:
        bool: True if all required API keys are set, False otherwise
    """
    # Check for OpenAI API key (required for OpenAI models)
    if not os.getenv('OPENAI_API_KEY'):
        print("Error: OPENAI_API_KEY environment variable is not set.")
        print("Please set your OpenAI API key:")
        print("export OPENAI_API_KEY='your-api-key-here'")
        return False
    
    # Check for OpenRouter API key (required for non-OpenAI models)
    # OpenRouter provides access to models from multiple providers (DeepSeek, Gemini, etc.)
    if not os.getenv('OPENROUTER_API_KEY'):
        print("Warning: OPENROUTER_API_KEY environment variable is not set.")
        print("This is required for non-OpenAI models (DeepSeek, Google Gemini, etc.).")
        print("Please set your OpenRouter API key:")
        print("export OPENROUTER_API_KEY='your-openrouter-api-key-here'")
        print("You can get one from: https://openrouter.ai/")
        return False
    
    return True

def validate_openai_api_key():
    """
    Validate that the OpenAI API key is set.
    
    Returns:
        bool: True if API key is set, False otherwise
    """
    if not os.getenv('OPENAI_API_KEY'):
        print("Error: OPENAI_API_KEY environment variable is not set.")
        print("Please set your OpenAI API key:")
        print("export OPENAI_API_KEY='your-api-key-here'")
        return False
    return True

def validate_openrouter_api_key():
    """
    Validate that the OpenRouter API key is set.
    
    Returns:
        bool: True if API key is set, False otherwise
    """
    if not os.getenv('OPENROUTER_API_KEY'):
        print("Error: OPENROUTER_API_KEY environment variable is not set.")
        print("Please set your OpenRouter API key:")
        print("export OPENROUTER_API_KEY='your-openrouter-api-key-here'")
        print("You can get one from: https://openrouter.ai/")
        return False
    return True 