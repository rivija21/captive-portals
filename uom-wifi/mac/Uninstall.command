#!/bin/zsh
# Double-click to turn off automatic UoM Wi-Fi login and remove everything it installed
# (the background job, the installed script, its logs, and the saved Keychain login).

LABEL="lk.uom.wifi-autologin"

osascript -e 'display dialog "Turn off automatic UoM Wi-Fi login and delete the saved password?" buttons {"Cancel", "Turn Off"} default button 2 with title "UoM Wi-Fi Auto-Login" with icon caution' >/dev/null 2>&1 \
  || { echo "Cancelled. Nothing was changed."; exit 1; }

launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null
rm -f "$HOME/Library/LaunchAgents/$LABEL.plist"
rm -rf "$HOME/Library/Application Support/UoMAutoLogin" "$HOME/Library/Logs/UoMAutoLogin"
while security delete-generic-password -s "UoM WiFi Login" >/dev/null 2>&1; do :; done
echo "✓ Automatic UoM Wi-Fi login is turned off and removed."
