#!/bin/bash

# Require an operator-supplied NGC API key; never fall back to a placeholder.
API_KEY=${NGC_API_KEY:-}
if [ -z "$API_KEY" ]; then
    echo "[!] NGC_API_KEY is required to pull/run the NVIDIA NIM container." >&2
    exit 1
fi

echo "Logging in to nvcr.io..."
echo "$API_KEY" | docker login nvcr.io -u '$oauthtoken' --password-stdin

export NGC_API_KEY="$API_KEY"
export LOCAL_NIM_CACHE=~/.cache/nim

echo "Setting up cache directory at $LOCAL_NIM_CACHE"
mkdir -p "$LOCAL_NIM_CACHE"
chmod -R a+w "$LOCAL_NIM_CACHE"

echo "Pulling and running the NVIDIA NIM Docker container..."
docker run -it --rm \
    --gpus all \
    --shm-size=16GB \
    -e NGC_API_KEY \
    -v "$LOCAL_NIM_CACHE:/opt/nim/.cache" \
    -p 8000:8000 \
    nvcr.io/nim/zai-org/glm-5.2:latest
