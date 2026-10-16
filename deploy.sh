#!/usr/bin/env bash
# ==============================================================================
# Adversum 1-Click Production Deployment Script (Linux / macOS / Cloud)
# ==============================================================================
set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "\n${CYAN}=== [ADVERSUM INSTITUTIONAL STACK DEPLOYER] ===${NC}\n"

if [ "$1" == "--down" ]; then
    echo -e "${YELLOW}Shutting down Adversum stack...${NC}"
    docker compose down
    echo -e "${GREEN}[OK] Stack stopped.${NC}"
    exit 0
fi

if [ "$1" == "--logs" ]; then
    docker compose logs -f
    exit 0
fi

# Verify Docker engine
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}[ERROR] Docker daemon is not running.${NC}"
    exit 1
fi

if [ "$1" == "--build" ]; then
    echo -e "${YELLOW}Building fresh containers...${NC}"
    docker compose build
fi

echo -e "${CYAN}Starting multi-container orchestration...${NC}"
docker compose up -d

echo -e "\nWaiting for backend readiness probe..."
RETRIES=20
READY=false

for i in $(seq 1 $RETRIES); do
    sleep 2
    if curl -s -f http://localhost:8000/health/ready | grep '"ready":true' > /dev/null 2>&1; then
        READY=true
        break
    fi
    echo "  Probe attempt $i/$RETRIES waiting..."
done

if [ "$READY" = true ]; then
    echo -e "\n${GREEN}[SUCCESS] Adversum Stack is 100% OPERATIONAL!${NC}"
    echo -e "  • Frontend Web UI     : http://localhost"
    echo -e "  • Live SOC Dashboard   : http://localhost/soc"
    echo -e "  • Adversum War Room    : http://localhost/war-room"
    echo -e "  • API & Swagger Docs   : http://localhost:8000/docs"
    echo -e "  • WebSocket Stream     : ws://localhost:8000/ws/threat-stream"
    echo -e "  • Anvil EVM Node       : http://localhost:8545"
    echo -e "\nTo view logs: ./deploy.sh --logs"
    echo -e "To shut down: ./deploy.sh --down\n"
else
    echo -e "\n${YELLOW}[WARNING] Stack started but readiness probe timed out.${NC}"
    echo -e "Check container logs with: docker compose logs"
fi
