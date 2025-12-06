#!/bin/bash
set -euo pipefail

# --- CONFIGURATION ---
# The target Tailscale IP is used for documentation purposes.
# The UI will listen on all interfaces (0.0.0.0) but is accessed via Tailscale.
TAILSCALE_IP=$(tailscale ip -4)
WEBUI_PORT="8080" # The UI runs inside the host network on this port
OLLAMA_PORT="11434"

# Models to download and install
MODELS=(
    "deepseek-r1:8b"
    "nomic-embed-text"
)
# ---------------------

echo "Starting AI Server Setup..."

install_docker() {
    if command -v docker &> /dev/null; then
        echo "Docker is already installed."
        sudo usermod -aG docker "$USER" || true
        return 0
    fi

    echo "Installing Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    rm get-docker.sh

    sudo usermod -aG docker "$USER" || true

    echo "Docker installation complete. You must log out and log back in for the 'docker' command to work without 'sudo'."
}

configure_systemd() {
    echo "Creating systemd overrides for dependencies and network settings..."

    SSH_DROPIN_DIR="/etc/systemd/system/ssh.service.d"
    sudo mkdir -p "$SSH_DROPIN_DIR"
    sudo cat <<EOF > "$SSH_DROPIN_DIR/override.conf"
[Unit]
After=tailscaled.service
Wants=tailscaled.service
EOF
    echo "SSH systemd override created."

    OLLAMA_DROPIN_DIR="/etc/systemd/system/ollama.service.d"
    sudo mkdir -p "$OLLAMA_DROPIN_DIR"
    sudo cat <<EOF > "$OLLAMA_DROPIN_DIR/override.conf"
[Service]
Environment="OLLAMA_HOST=0.0.0.0"
EOF
    echo "Ollama systemd override created."
}

setup_webui() {
    echo "Setting up Open WebUI container and systemd service..."

    sudo docker stop open-webui 2>/dev/null || true
    sudo docker rm open-webui 2>/dev/null || true

    sudo docker run -d \
      --network=host \
      -e OLLAMA_BASE_URL=http://127.0.0.1:$OLLAMA_PORT \
      -v open-webui:/app/backend/data \
      --name open-webui \
      --restart always \
      ghcr.io/open-webui/open-webui:main

    WEBUI_SERVICE_PATH="/etc/systemd/system/docker.open-webui.service"
    sudo cat <<EOF > "$WEBUI_SERVICE_PATH"
[Unit]
Description=Open WebUI Docker Container
Requires=docker.service
After=docker.service

[Service]
Restart=always
ExecStart=/usr/bin/docker start -a open-webui
ExecStop=/usr/bin/docker stop open-webui

[Install]
WantedBy=multi-user.target
EOF

    echo "Open WebUI container started and service unit created."
}

install_models() {
    echo "Downloading Ollama models..."

    sudo systemctl restart ollama

    for MODEL in "${MODELS[@]}"; do
        echo "Pulling model $MODEL..."
        sudo ollama pull "$MODEL"
        if [ $? -eq 0 ]; then
            echo "Model $MODEL installed."
        else
            echo "ERROR: Failed to install model $MODEL."
        fi
    done
}

# --- Main Execution Flow ---

install_docker
configure_systemd

echo "Reloading systemd daemon and starting services..."
sudo systemctl daemon-reload
sudo systemctl restart ollama
sudo systemctl enable docker.open-webui.service
sudo systemctl start docker.open-webui.service
sudo systemctl restart ssh

setup_webui
install_models

echo "--- SETUP COMPLETE ---"
echo " "
echo "Ollama and Open WebUI are installed and configured to start automatically."
echo " "
echo "1. Access the Web UI:"
echo "   http://$TAILSCALE_IP:$WEBUI_PORT"
echo " "
echo "2. IMPORTANT: If you just installed Docker, you must log out and log back in for your user to run Docker commands without 'sudo'."
echo "3. The first user to sign up on the UI will be the administrator."
