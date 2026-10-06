# Captive portal auto-login

Scripts that sign you in to Wi-Fi login pages ("captive portals") automatically.

## UoM Wi-Fi (University of Moratuwa)

Logs you in to **UoM_Wireless** automatically, so after your laptop wakes from sleep
you're online without typing your username and password into the login page at
wlan.uom.lk.

### Download

Click the green **Code** button above → **Download ZIP**, then unzip it. You only need
the folder for your computer: `uom-wifi/mac` or `uom-wifi/windows`.

### Mac

1. Open `uom-wifi/mac`.
2. Right-click **Set Up.command** → **Open**. macOS asks the first time because the file
   came from the internet; click **Open** again.
3. Type your UoM Wi-Fi username and password into the boxes that appear.

If macOS asks to install the "command line developer tools", click **Install**, wait for it
to finish, then run Set Up again. A "Background Items Added" notice for python3 is this tool.

### Windows

1. Open `uom-wifi\windows`.
2. Double-click **Set Up.bat**. If Windows says "Windows protected your PC", click
   **More info** → **Run anyway**.
3. Type your UoM Wi-Fi username and password into the box that appears.

The Windows version is new and hasn't been tried on a real Windows PC yet. If it doesn't
log you in, the log (see the end of this page) shows what went wrong.

### The files

| Mac | Windows | What it does |
|---|---|---|
| **Set Up.command** | **Set Up.bat** | Saves your username + password and turns auto-login on. Run it again to change your password. |
| **Log In Now.command** | **Log In Now.bat** | Logs in right now and shows what happened. Use it if things ever seem stuck. |
| **Uninstall.command** | **Uninstall.bat** | Turns it off and removes everything, including the saved password. |

### Where your password goes

- **Mac:** your Keychain. **Windows:** an encrypted file in `%LOCALAPPDATA%\UoMAutoLogin`
  that only your Windows account can read.
- None of the files in this repo contain anyone's login, so it's safe to share.
- The password is only ever sent to wlan.uom.lk, and only while you're on the UoM network
  (the campus Wi-Fi hands out the `wifi.uom.lk` domain). Other Wi-Fi login pages, like a
  café's, are left alone.
- If the login page rejects the password, it opens the page so you can sign in by hand and
  waits 10 minutes before trying again, so your account never gets locked out.

### How it works

- A background job runs whenever the network changes or the computer wakes up, plus
  regularly as a backstop (every 30 s on Mac, every 2 min on Windows). Mac: a LaunchAgent.
  Windows: the Task Scheduler task "UoM WiFi Auto-Login".
- It asks Apple's / Microsoft's connectivity check whether the internet works. If it does,
  it stops there.
- Otherwise, on campus, it opens `https://wlan.uom.lk/login.html` (a Cisco wireless
  controller page) and submits the form the same way its Submit button does.
- Mac only: until you log in, macOS blocks ordinary programs from using the campus Wi-Fi.
  The script sends its requests straight through the Wi-Fi interface and asks the campus
  DNS server for addresses itself, like Apple's own login pop-up does. After logging in it
  closes that "Join UoM_Wireless" pop-up, which otherwise keeps asking for the password.

### If it doesn't log in

Double-click **Log In Now** to see what happens. Every attempt is also logged:

- Mac: `~/Library/Logs/UoMAutoLogin/` (Finder → Go → Go to Folder…)
- Windows: `%LOCALAPPDATA%\UoMAutoLogin\Logs\` (paste into File Explorer's address bar)

`autologin.log` lists each attempt, and `portal-page.html` is a copy of the login page it saw.
