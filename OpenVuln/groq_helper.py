#!/usr/bin/env python3
"""
Groq API Helper for OpenVuln
Provides a simple interface to call Groq API
"""

import os
import json
import logging
from typing import Dict, Any, Optional
import requests

logger = logging.getLogger(__name__)

class GroqAPIHelper:
    """Helper class for Groq API calls"""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Groq API helper
        
        Args:
            api_key: Groq API key (if None, reads from GROQ_API_KEY env var)
        """
        self.api_key = api_key or os.getenv("GROQ_API_KEY")
        self.base_url = "https://api.groq.com/openai/v1"
        
        if not self.api_key:
            logger.warning("GROQ_API_KEY not found in environment")
    
    def chat_completion(
        self,
        model: str,
        prompt: str,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        timeout: int = 60
    ) -> Dict[str, Any]:
        """
        Send chat completion request to Groq
        
        Args:
            model: Model name (e.g., "llama-3.3-70b-versatile")
            prompt: User prompt text
            temperature: Temperature (0.0-2.0)
            max_tokens: Max tokens in response
            timeout: Request timeout in seconds
        
        Returns:
            Response dict with model output
        """
        if not self.api_key:
            raise ValueError("Groq API key not provided")
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": model,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "temperature": temperature,
            "max_tokens": max_tokens
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=data,
                timeout=timeout
            )
            
            # Check for errors
            if not response.ok:
                error_msg = f"Groq API error: HTTP {response.status_code}"
                try:
                    error_data = response.json()
                    if 'error' in error_data:
                        error_msg += f" - {error_data['error']}"
                except:
                    error_msg += f" - {response.text[:200]}"
                
                logger.error(error_msg)
                raise Exception(error_msg)
            
            result = response.json()
            
            # Extract content
            content = result["choices"][0]["message"]["content"]
            
            # Log usage
            usage = result.get("usage", {})
            logger.info(f"Groq API usage - Prompt: {usage.get('prompt_tokens', 0)}, "
                       f"Completion: {usage.get('completion_tokens', 0)}, "
                       f"Total: {usage.get('total_tokens', 0)}")
            
            return {
                "content": content,
                "usage": usage,
                "model": result.get("model", model)
            }
            
        except requests.exceptions.Timeout:
            logger.error(f"Groq API timeout after {timeout}s")
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Groq API request failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error calling Groq API: {e}")
            raise


# Supported Groq models
GROQ_MODELS = {
    "llama-3.3-70b-versatile": "Meta Llama 3.3 70B Versatile",
    "llama-3.3-70b-specdec": "Meta Llama 3.3 70B Speculative Decoding",
    "llama-3.1-70b-versatile": "Meta Llama 3.1 70B Versatile",
    "llama-3.1-8b-instant": "Meta Llama 3.1 8B Instant (Fast)",
    "llama-3.2-1b-preview": "Meta Llama 3.2 1B Preview",
    "llama-3.2-3b-preview": "Meta Llama 3.2 3B Preview",
    "mixtral-8x7b-32768": "Mixtral 8x7B (32k context)",
    "gemma2-9b-it": "Google Gemma 2 9B",
    "gemma-7b-it": "Google Gemma 7B",
}


def test_groq_connection(model: str = "llama-3.1-8b-instant") -> bool:
    """
    Test Groq API connection
    
    Args:
        model: Model to test with
    
    Returns:
        True if successful, False otherwise
    """
    try:
        helper = GroqAPIHelper()
        response = helper.chat_completion(
            model=model,
            prompt="Say 'Hello from Groq!' in one sentence.",
            max_tokens=50
        )
        print(f"✅ Groq API connection successful!")
        print(f"Response: {response['content']}")
        return True
    except Exception as e:
        print(f"❌ Groq API connection failed: {e}")
        return False


if __name__ == "__main__":
    # Test connection
    print("Testing Groq API connection...")
    test_groq_connection()
