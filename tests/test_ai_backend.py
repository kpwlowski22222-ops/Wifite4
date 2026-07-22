import os
import pytest
from unittest.mock import MagicMock, patch
from core.ai_backend import AIBackend

def test_ai_backend_initialization():
    with patch.dict(os.environ, {
        "NVIDIA_API_KEY": "test-nvapi",
        "NVIDIA_BASE_URL": "http://127.0.0.1:8000/v1",
        "NVIDIA_MODEL": "zai-org/GLM-5.2"
    }):
        backend = AIBackend()
        assert backend.nvidia_api_key == "test-nvapi"
        assert backend.nvidia_base_url == "http://127.0.0.1:8000/v1"
        assert backend.nvidia_model == "zai-org/GLM-5.2"

def test_ai_backend_status():
    with patch.dict(os.environ, {
        "NVIDIA_API_KEY": "test-nvapi",
        "NVIDIA_BASE_URL": "http://127.0.0.1:8000/v1",
        "NVIDIA_MODEL": "zai-org/GLM-5.2"
    }):
        backend = AIBackend()
        # Mock Ollama status to be unreachable
        backend.ollama.reachable = MagicMock(return_value=False)
        st = backend.status()
        assert st["active"] == "nvidia"
        assert st["nvidia"] is True
        assert st["nvidia_endpoint"] == "http://127.0.0.1:8000/v1"
        assert st["nvidia_model"] == "zai-org/GLM-5.2"

@patch("requests.post")
def test_ai_backend_query_nvidia_success(mock_post):
    # Set up mock response
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "choices": [
            {
                "message": {
                    "content": "Test NVIDIA GLM response"
                }
            }
        ]
    }
    mock_post.return_value = mock_resp

    with patch.dict(os.environ, {
        "NVIDIA_API_KEY": "test-nvapi",
        "NVIDIA_BASE_URL": "http://127.0.0.1:8000/v1",
        "NVIDIA_MODEL": "zai-org/GLM-5.2"
    }):
        backend = AIBackend()
        # Make Ollama unreachable
        backend.ollama.reachable = MagicMock(return_value=False)
        
        reply = backend.query("wifi", "test prompt")
        assert reply == "Test NVIDIA GLM response"
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert args[0] == "http://127.0.0.1:8000/v1/chat/completions"
        assert kwargs["json"]["model"] == "zai-org/GLM-5.2"
