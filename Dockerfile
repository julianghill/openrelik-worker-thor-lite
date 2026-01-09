# Use the official Docker Hub Ubuntu base image
FROM ubuntu:24.04

LABEL org.opencontainers.image.version="2025.01.24"
LABEL org.opencontainers.image.title="OpenRelik Worker for THOR Lite"
LABEL org.opencontainers.image.source="https://github.com/NextronSystems/openrelik-worker-thor-lite"

# Prevent needing to configure debian packages, stopping the setup of
# the docker container.
RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections

# Install poetry and any other dependency that your worker needs.
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-poetry \
    curl \
    unzip \
    # Add your dependencies here
    && rm -rf /var/lib/apt/lists/*

# ----------------------------------------------------------------------
# Install THOR Lite
# ----------------------------------------------------------------------
WORKDIR /thor-lite
RUN curl -o thorlite-linux.zip "https://update1.nextron-systems.com/getupdate.php?product=thor10lite-linux&dev=1" \
    && unzip thorlite-linux.zip \
    && rm thorlite-linux.zip \
    && chmod +x thor-lite-linux-64
# ----------------------------------------------------------------------
# Install YARA Forge rules (default snapshot)
# ----------------------------------------------------------------------
RUN mkdir -p /thor-lite/signatures/custom/yara-forge \
    && curl -L -o /tmp/yara-forge.zip "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip" \
    && unzip /tmp/yara-forge.zip -d /thor-lite/signatures/custom/yara-forge \
    && rm /tmp/yara-forge.zip \
    && python3 - <<'PY'
import hashlib
import os
import shutil

custom_dirs = ["/thor-lite/signatures/custom/yara", "/thor-lite/custom-signatures/yara"]
clean_dirs = ["/thor-lite/signatures/custom", "/thor-lite/custom-signatures"] + custom_dirs
forge_dir = "/thor-lite/signatures/custom/yara-forge"
prefix = "yara_forge_"

for custom_dir in clean_dirs:
    os.makedirs(custom_dir, exist_ok=True)
    for name in os.listdir(custom_dir):
        if name.startswith(prefix) and name.lower().endswith((".yar", ".yara")):
            os.remove(os.path.join(custom_dir, name))

count = 0
for root, _, files in os.walk(forge_dir):
    for filename in files:
        if not filename.lower().endswith((".yar", ".yara")):
            continue
        source_path = os.path.join(root, filename)
        rel_path = os.path.relpath(source_path, forge_dir)
        digest = hashlib.sha1(rel_path.encode("utf-8")).hexdigest()[:12]
        dest_name = f"{prefix}{digest}_{filename}"
        for custom_dir in custom_dirs:
            shutil.copy2(source_path, os.path.join(custom_dir, dest_name))
        count += 1

print(f"Flattened {count} YARA Forge rules into {', '.join(custom_dirs)}")
PY
# ----------------------------------------------------------------------

# Configure poetry
ENV POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=1 \
    POETRY_VIRTUALENVS_CREATE=1 \
    POETRY_CACHE_DIR=/tmp/poetry_cache

# Set working directory
WORKDIR /openrelik

# Copy files needed to build
COPY . ./

# Install the worker and set environment to use the correct python interpreter.
RUN poetry install && rm -rf $POETRY_CACHE_DIR
ENV VIRTUAL_ENV=/app/.venv PATH="/openrelik/.venv/bin:$PATH"

# Default command if not run from docker-compose (and command being overidden)
CMD ["celery", "--app=src.tasks", "worker", "--task-events", "--concurrency=1", "--loglevel=INFO"]
