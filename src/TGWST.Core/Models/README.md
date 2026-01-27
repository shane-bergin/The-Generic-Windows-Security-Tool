# AI Model for Script Analysis

To enable the AI-powered script analysis feature, you need to download a compatible LLM model and place it in this directory.

## Required Model

The application is configured to use the `phi-3-mini-4k-instruct` model in GGUF format.

- **File Name:** `phi-3-mini-4k-instruct.Q4_K_M.gguf`
- **Download Link:** [https://huggingface.co/microsoft/Phi-3-mini-4k-instruct-gguf/resolve/main/Phi-3-mini-4k-instruct-Q4_K_M.gguf](https://huggingface.co/microsoft/Phi-3-mini-4k-instruct-gguf/resolve/main/Phi-3-mini-4k-instruct-Q4_K_M.gguf)
- **Size:** Approximately 2.17 GB

## Instructions

1.  Download the model file from the link above.
2.  Ensure the downloaded file is named exactly `phi-3-mini-4k-instruct.Q4_K_M.gguf`.
3.  Place the file into this directory (`src/TGWST.Core/Models/`).
4.  Rebuild the solution.

After following these steps, the "LLM Analysis" feature in the Scan tab will be enabled. If the model is not found, the feature will be disabled.
