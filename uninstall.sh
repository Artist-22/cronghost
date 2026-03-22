#!/bin/bash

RED='\033[91m'
GREEN='\033[92m'
GRAY='\033[90m'
WHITE='\033[97m'
RESET='\033[0m'

echo ""
echo -e "${WHITE}  CronGhost Uninstaller${RESET}"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}  Error: Run as root.${RESET}"
    exit 1
fi

echo -e "${GRAY}  Removing CronGhost...${RESET}"
rm -f  /usr/local/bin/cronghost
rm -f  /usr/share/applications/cronghost.desktop
rm -f  /usr/share/icons/hicolor/256x256/apps/cronghost.png
rm -f  /usr/share/pixmaps/cronghost.png
rm -f  /usr/local/man/man1/cronghost.1.gz

echo -e "${GRAY}  Removing data and quarantine...${RESET}"
rm -rf /var/lib/cronghost

update-desktop-database /usr/share/applications/ 2>/dev/null || true
gtk-update-icon-cache /usr/share/icons/hicolor/ 2>/dev/null || true

echo ""
echo -e "${GREEN}  CronGhost removed completely.${RESET}"
echo -e "${GRAY}  Baseline, quarantine, and history also removed.${RESET}"
echo ""
