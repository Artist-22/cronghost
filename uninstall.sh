#!/bin/bash
echo ""
echo "  Removing CronGhost..."
rm -f  /usr/local/bin/cronghost
rm -f  /usr/share/applications/cronghost.desktop
rm -f  /usr/share/icons/hicolor/256x256/apps/cronghost.png
rm -f  /usr/share/pixmaps/cronghost.png
rm -f  /usr/local/man/man1/cronghost.1.gz
rm -rf /var/lib/cronghost
update-desktop-database /usr/share/applications/ 2>/dev/null || true
gtk-update-icon-cache /usr/share/icons/hicolor/ 2>/dev/null || true
echo "  Done. CronGhost removed."
echo ""
