#!/bin/zsh
# Double-click to turn on automatic UoM Wi-Fi login, or to change the saved
# username/password. Safe to run again any time.

HERE="${0:A:h}"
SERVICE="UoM WiFi Login"
LABEL="lk.uom.wifi-autologin"
APP_DIR="$HOME/Library/Application Support/UoMAutoLogin"
AGENT="$HOME/Library/LaunchAgents/$LABEL.plist"

# ask <message> <default> [hidden] — shows a dialog and prints what was typed.
ask() {
  local hidden=""
  [[ -n "$3" ]] && hidden="with hidden answer"
  osascript - "$1" "$2" 2>/dev/null <<EOF
on run argv
  display dialog (item 1 of argv) default answer (item 2 of argv) $hidden with title "UoM Wi-Fi Auto-Login" with icon note
  return text returned of result
end run
EOF
}

cancelled() { echo "Cancelled. Nothing was changed."; exit 1; }

echo "== UoM Wi-Fi Auto-Login setup =="

current_user=$(security find-generic-password -s "$SERVICE" 2>/dev/null | sed -n 's/.*"acct"<blob>="\(.*\)"/\1/p')
user=$(ask "Your UoM Wi-Fi username (what you type on the UoM Wi-Fi login page):" "$current_user") || cancelled
user="${user## }"; user="${user%% }"
[[ -z "$user" ]] && { echo "No username entered."; exit 1; }
pass=$(ask "Password for $user:

It is stored only in your Mac's Keychain." "" hidden) || cancelled
[[ -z "$pass" ]] && { echo "No password entered."; exit 1; }

# 1. Save the login in the Keychain (replacing any older one).
while security delete-generic-password -s "$SERVICE" >/dev/null 2>&1; do :; done
security add-generic-password -s "$SERVICE" -a "$user" -w "$pass" -T /usr/bin/security \
  -j "Used by UoM Wi-Fi Auto-Login to sign in at wlan.uom.lk" || { echo "Couldn't save to the Keychain."; exit 1; }
unset pass
echo "✓ Saved your login in the Keychain"

# 2. Install the script outside Downloads (background jobs can't read Downloads).
mkdir -p "$APP_DIR" "$HOME/Library/LaunchAgents"
cp "$HERE/uom_autologin.py" "$APP_DIR/uom_autologin.py"
rm -f "$APP_DIR/state.json"
echo "✓ Installed the script in $APP_DIR"

# 3. Run it whenever the network changes (e.g. after waking up), and every 5 minutes.
cat > "$AGENT" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/python3</string>
    <string>$APP_DIR/uom_autologin.py</string>
  </array>
  <key>LaunchEvents</key>
  <dict>
    <key>com.apple.notifyd.matching</key>
    <dict>
      <key>network-change</key>
      <dict><key>Notification</key><string>com.apple.system.config.network_change</string></dict>
    </dict>
  </dict>
  <key>WatchPaths</key>
  <array><string>/var/run/resolv.conf</string></array>
  <key>StartInterval</key><integer>300</integer>
  <key>ProcessType</key><string>Background</string>
</dict>
</plist>
EOF
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null
launchctl bootstrap "gui/$(id -u)" "$AGENT" || { echo "Couldn't start the background job."; exit 1; }
echo "✓ Turned on automatic login (runs after every wake-up)"

# 4. Try it once right now.
echo
echo "Checking the connection now…"
/usr/bin/python3 "$APP_DIR/uom_autologin.py" --now --verbose

osascript -e 'display dialog "All set! Your Mac will now log in to UoM Wi-Fi by itself after waking up.

To change your password later, just run Set Up again." buttons {"OK"} default button 1 with title "UoM Wi-Fi Auto-Login" with icon note' >/dev/null 2>&1
echo
echo "Done. You can close this window."
