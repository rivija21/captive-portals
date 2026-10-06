#!/bin/zsh
# Double-click to check the connection and log in to UoM Wi-Fi right away.
# Handy if the automatic login ever seems stuck; it shows what it's doing.

INSTALLED="$HOME/Library/Application Support/UoMAutoLogin/uom_autologin.py"
if [[ ! -f "$INSTALLED" ]]; then
  echo "Auto-login isn't set up yet. Double-click \"Set Up.command\" first."
  exit 1
fi
/usr/bin/python3 "$INSTALLED" --now --verbose
echo
echo "Full history: ~/Library/Logs/UoMAutoLogin/autologin.log"
