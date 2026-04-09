# SLM Service — llama.cpp Server
# ADR Б0.6, Б10: Content Factory, Reranking, Log Compression
FROM ghcr.io/ggerganov/llama.cpp:server AS base

COPY config.yaml /etc/slm/config.yaml
COPY grammars/ /etc/slm/grammars/

EXPOSE 8080

CMD ["--host", "0.0.0.0", "--port", "8080", "--model", "/models/model.gguf"]
