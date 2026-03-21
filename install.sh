#!/bin/bash

RED='\033[91m'
GREEN='\033[92m'
GRAY='\033[90m'
WHITE='\033[97m'
RESET='\033[0m'

echo ""
echo -e "${WHITE}  CronGhost Installer${RESET}"
echo -e "${GRAY}  Installing as a system tool...${RESET}"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}  Error: Run installer as root.${RESET}"
    echo -e "${GRAY}  Use: sudo bash install.sh${RESET}"
    exit 1
fi

# Copy main script
echo -e "${GRAY}  Copying cronghost to /usr/local/bin...${RESET}"
cp cronghost.py /usr/local/bin/cronghost
chmod 755 /usr/local/bin/cronghost

# Create data directory
echo -e "${GRAY}  Creating data directory...${RESET}"
mkdir -p /var/lib/cronghost
chmod 700 /var/lib/cronghost

# Install icon
echo -e "${GRAY}  Installing custom icon...${RESET}"
mkdir -p /usr/share/icons/hicolor/256x256/apps
mkdir -p /usr/share/pixmaps

python3 << 'PYEOF'
from PIL import Image, ImageDraw
SIZE = 256
img  = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
draw = ImageDraw.Draw(img)
draw.ellipse([4,4,252,252], fill=(15,15,20,255), outline=(0,200,80,255), width=4)
skull = (220,220,220,255)
draw.ellipse([68,48,188,148], fill=skull)
draw.ellipse([52,80,110,150], fill=skull)
draw.ellipse([146,80,204,150], fill=skull)
draw.rectangle([78,120,178,158], fill=skull)
horn = (200,200,200,255)
draw.polygon([(80,72),(58,28),(96,60)], fill=horn)
draw.polygon([(176,72),(198,28),(160,60)], fill=horn)
dark = (10,10,15,255)
draw.ellipse([82,82,112,112], fill=dark)
draw.ellipse([144,82,174,112], fill=dark)
glow = (0,220,80,255)
draw.ellipse([88,88,106,106], fill=glow)
draw.ellipse([150,88,168,106], fill=glow)
draw.rectangle([88,138,168,158], fill=dark)
for x in [90,104,118,132,146]:
    draw.rectangle([x,138,x+10,154], fill=(240,240,240,255))
draw.polygon([(134,62),(120,100),(130,100),(116,138),(140,96),(128,96),(142,62)], fill=(255,220,0,255))
body = (180,180,180,255)
draw.polygon([(78,148),(178,148),(190,210),(66,210)], fill=body)
for x in range(66,192,16):
    draw.ellipse([x,198,x+18,218], fill=dark)
claw = (160,160,160,255)
draw.polygon([(78,158),(50,175),(44,195),(66,182),(72,200),(80,178),(88,158)], fill=claw)
for cx,cy in [(44,195),(56,204),(68,205)]:
    draw.polygon([(cx,cy),(cx-8,cy+16),(cx+4,cy+14),(cx+10,cy+18),(cx+12,cy+10)], fill=claw)
draw.polygon([(168,158),(206,175),(212,195),(190,182),(184,200),(176,178),(168,158)], fill=claw)
for cx,cy in [(188,205),(200,204),(212,195)]:
    draw.polygon([(cx,cy),(cx+8,cy+16),(cx-4,cy+14),(cx-10,cy+18),(cx-12,cy+10)], fill=claw)
draw.ellipse([2,2,254,254], outline=(0,180,60,200), width=3)
img.save("/usr/share/icons/hicolor/256x256/apps/cronghost.png")
img.save("/usr/share/pixmaps/cronghost.png")
print("  Icon saved.")
PYEOF

gtk-update-icon-cache /usr/share/icons/hicolor/ 2>/dev/null || true

# Desktop entry
echo -e "${GRAY}  Creating application menu entry...${RESET}"
cat > /usr/share/applications/cronghost.desktop << 'DESKTOP'
[Desktop Entry]
Name=CronGhost
GenericName=Persistence Scanner
Comment=Scheduled Task Shadow Scanner — Tier 3
Exec=bash -c "sudo cronghost; read -p 'Press enter to close...'"
Icon=cronghost
Terminal=true
Type=Application
Categories=Security;System;
Keywords=security;persistence;cron;audit;
DESKTOP

chmod 644 /usr/share/applications/cronghost.desktop
update-desktop-database /usr/share/applications/ 2>/dev/null || true

echo ""
echo -e "${GREEN}  CronGhost installed successfully.${RESET}"
echo ""
echo -e "${WHITE}  How to run:${RESET}"
echo -e "${GRAY}  From terminal:     ${WHITE}sudo cronghost${RESET}"
echo -e "${GRAY}  From app menu:     ${WHITE}Search 'CronGhost' — your icon will show${RESET}"
echo ""
