#!/bin/bash

# ============================================
# AI-NMS Attack Simulator for DEPLOYED SITE
# Use this to test your live Vercel deployment
# ============================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# ============================================
# CHANGE THIS TO YOUR DEPLOYED URL
# ============================================
TARGET_URL="https://ai-nms-security.vercel.app"
# Or use your actual deployed URL

BASE_URL="$TARGET_URL"

echo -e "${RED}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                                                              ║"
echo "║     🤖 AI-NMS Attack Simulator - LIVE DEPLOYMENT TEST       ║"
echo "║                                                              ║"
echo "║     Testing your Vercel deployed security system            ║"
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""

echo -e "${CYAN}Target: ${BASE_URL}${NC}"
echo -e "${CYAN}Time: $(date)${NC}"
echo ""

# Function to send traffic
send_traffic() {
    local ip=$1
    local port=$2
    local protocol=$3
    local count=$4
    
    curl -s -X POST "$BASE_URL/api/traffic" \
        -H "Content-Type: application/json" \
        -d "{\"ip\":\"$ip\",\"port\":$port,\"protocol\":\"$protocol\",\"requestCount\":$count}" > /dev/null
    echo -e "   📤 Sent: $ip:$port - $count requests"
}

# Attack 1: DDoS Simulation
ddos_attack() {
    echo -e "${RED}[1/5] 🌊 Launching DDoS Attack Simulation...${NC}"
    for i in {1..30}; do
        RANDOM_IP="$((RANDOM%256)).$((RANDOM%256)).$((RANDOM%256)).$((RANDOM%256))"
        send_traffic "$RANDOM_IP" 80 "HTTP" $((RANDOM%150 + 100))
    done
    echo -e "${GREEN}   ✓ 30 DDoS requests sent from multiple IPs${NC}"
    sleep 1
}

# Attack 2: Brute Force Simulation
bruteforce_attack() {
    echo -e "${RED}[2/5] 🔐 Launching Brute Force Attack Simulation...${NC}"
    ATTACKER_IP="192.168.1.100"
    for i in {1..20}; do
        send_traffic "$ATTACKER_IP" 443 "HTTPS" 50
    done
    echo -e "${GREEN}   ✓ 20 brute force attempts from $ATTACKER_IP${NC}"
    sleep 1
}

# Attack 3: Port Scan Simulation
portscan_attack() {
    echo -e "${RED}[3/5] 🔍 Launching Port Scan Attack Simulation...${NC}"
    SCANNER_IP="10.0.0.25"
    PORTS=(22 23 80 443 445 3389 3306 5900 8080)
    for port in "${PORTS[@]}"; do
        send_traffic "$SCANNER_IP" "$port" "TCP" 5
    done
    echo -e "${GREEN}   ✓ Port scan on ${#PORTS[@]} ports from $SCANNER_IP${NC}"
    sleep 1
}

# Attack 4: Malicious IP Attack
malicious_ip_attack() {
    echo -e "${RED}[4/5] 🚫 Launching Malicious IP Attack...${NC}"
    MALICIOUS_IPS=("45.33.22.11" "185.130.5.253")
    for ip in "${MALICIOUS_IPS[@]}"; do
        send_traffic "$ip" 9999 "TCP" 100
    done
    sleep 1
}

# Attack 5: Bot Traffic Simulation
bot_attack() {
    echo -e "${RED}[5/5] 🤖 Launching Bot Traffic Attack Simulation...${NC}"
    BOT_IP="172.16.0.50"
    for i in {1..30}; do
        send_traffic "$BOT_IP" 8080 "HTTP" 30
    done
    echo -e "${GREEN}   ✓ 30 rapid bot requests from $BOT_IP${NC}"
    sleep 1
}

# Check dashboard status
check_dashboard() {
    echo ""
    echo -e "${PURPLE}📊 Checking dashboard status...${NC}"
    TRAFFIC_COUNT=$(curl -s "$BASE_URL/api/traffic" | grep -o '"count":[0-9]*' | cut -d':' -f2)
    echo -e "${GREEN}   Total traffic logs on deployed site: $TRAFFIC_COUNT${NC}"
    echo ""
}

# Main execution
main() {
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}         Starting Attack Simulation on DEPLOYED SITE           ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    # Check if deployed site is reachable
    echo -e "${YELLOW}🔍 Checking if deployed site is reachable...${NC}"
    if curl -s "$BASE_URL" > /dev/null 2>&1; then
        echo -e "${GREEN}   ✅ Deployed site is reachable at $BASE_URL${NC}"
    else
        echo -e "${RED}   ❌ Cannot reach deployed site!${NC}"
        exit 1
    fi
    echo ""
    
    # Execute attacks
    ddos_attack
    bruteforce_attack
    portscan_attack
    malicious_ip_attack
    bot_attack
    
    check_dashboard
    
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}              ✅ Attack Simulation Complete!                    ${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}📋 Next Steps:${NC}"
    echo -e "   1. Go to your dashboard: ${CYAN}$BASE_URL${NC}"
    echo -e "   2. Click ${GREEN}'Run AI Detection'${NC} to analyze the attacks"
    echo -e "   3. Watch the AI detect and classify each attack type"
    echo -e "   4. Check the Alerts tab for security alerts"
    echo -e "   5. Click ${RED}'Respond'${NC} to block malicious IPs"
    echo ""
}

# Run main function
main