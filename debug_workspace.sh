#!/bin/bash

WORKSPACE="./workspace"
echo "WORKSPACE is set to: $WORKSPACE"
echo "Absolute path of WORKSPACE: $(cd "$WORKSPACE" && pwd)"
echo "Contents of WORKSPACE:"
ls -la "$WORKSPACE"