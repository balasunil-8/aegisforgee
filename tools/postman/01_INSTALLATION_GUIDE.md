# Postman Installation Guide - Complete Step-by-Step Instructions

## Table of Contents
1. [Before You Install](#before-you-install)
2. [System Requirements](#system-requirements)
3. [Windows Installation](#windows-installation)
4. [macOS Installation](#macos-installation)
5. [Linux Installation](#linux-installation)
6. [Verification Steps](#verification-steps)
7. [Initial Setup](#initial-setup)
8. [Common Problems and Solutions](#common-problems-and-solutions)
9. [Alternative Installation Methods](#alternative-installation-methods)

---

## Before You Install

### What You're About to Install

Postman comes in two main versions:

1. **Postman Desktop App** (Recommended)
   - Full-featured desktop application
   - Works offline
   - Better performance
   - This is what we'll install

2. **Postman Web Version**
   - Runs in your web browser
   - Requires internet connection
   - Limited features
   - Good for quick tests

**For this guide, we'll install the Desktop App** because it has all the features you need for security testing.

### Do You Need an Account?

**Short answer:** Not required, but recommended.

**Without an account:**
- You can use all core features
- Your work is saved locally only
- Can't sync across devices
- Can't collaborate with teams

**With a free account:**
- Sync your collections across devices
- Share collections with teammates
- Access cloud features
- Back up your work automatically

**Don't worry:** You can skip account creation during installation and create one later if you want.

### Download Size and Time

- **File size:** 100-200 MB (depending on your operating system)
- **Download time:** 2-10 minutes (depends on your internet speed)
- **Installation time:** 2-5 minutes

---

## System Requirements

### Windows

**Minimum:**
- Windows 7 or later (64-bit)
- 2 GB RAM
- 500 MB free disk space
- Internet connection for download

**Recommended:**
- Windows 10 or 11
- 4 GB RAM or more
- 1 GB free disk space
- Stable internet connection

### macOS

**Minimum:**
- macOS 10.11 (El Capitan) or later
- 2 GB RAM
- 500 MB free disk space
- Intel or Apple Silicon (M1/M2) processor

**Recommended:**
- macOS 12 (Monterey) or later
- 4 GB RAM or more
- 1 GB free disk space

### Linux

**Minimum:**
- Ubuntu 14.04 or later
- Debian 8 or later
- Fedora 24 or later
- 2 GB RAM
- 500 MB free disk space

**Recommended:**
- Latest LTS version of your distribution
- 4 GB RAM or more
- 1 GB free disk space

**Check your system:** Open Terminal and type:
```bash
uname -m
```
- If it says `x86_64`, you have a 64-bit system ✓
- If it says `i686` or `i386`, you have a 32-bit system (Postman requires 64-bit)

---

## Windows Installation

### Method 1: Official Installer (Recommended)

#### Step 1: Download Postman

1. Open your web browser (Chrome, Firefox, Edge, etc.)

2. Go to: **https://www.postman.com/downloads/**

3. Click the large **"Download"** button
   - The website automatically detects you're using Windows
   - It will show "Download for Windows"

4. Your browser will start downloading `Postman-win64-Setup.exe`
   - Look for the download in your browser's download bar
   - Or check your `Downloads` folder

**Tip:** The file is about 150-200 MB. If your download seems stuck, wait a few minutes or try a different browser.

#### Step 2: Run the Installer

1. **Find the downloaded file:**
   - Open File Explorer (Windows key + E)
   - Click on "Downloads" in the left sidebar
   - Look for `Postman-win64-Setup.exe`

2. **Run the installer:**
   - Double-click on `Postman-win64-Setup.exe`
   - Windows might show a security warning: "Do you want to allow this app to make changes?"
   - Click **"Yes"**

**Why this happens:** Windows protects you from unknown programs. Postman is safe, but Windows checks with you first.

#### Step 3: Wait for Installation

The installer will:
1. Extract files (you'll see a progress bar)
2. Install Postman to your computer
3. Create desktop shortcuts
4. Launch Postman automatically

**This takes 1-3 minutes.** Don't close the window!

**What's happening behind the scenes:**
- Files are being copied to `C:\Users\YourName\AppData\Local\Postman`
- Shortcuts are created on your desktop and Start Menu
- System registry is updated

#### Step 4: First Launch

After installation, Postman will open automatically. You'll see:

1. **Welcome Screen**
   - A friendly greeting
   - Options to sign in or skip

2. **Sign In / Create Account (Optional)**
   - You can click "Skip" at the bottom
   - Or create a free account if you want to sync your work

3. **Main Interface**
   - You'll see Postman's main window with menus, buttons, and panels
   - Don't worry if it looks overwhelming - we'll explain everything in the Basics guide

**Congratulations! Postman is now installed on Windows.**

#### Step 5: Create Desktop Shortcut (if needed)

If the installer didn't create a desktop shortcut:

1. Press **Windows key** (type "Postman")
2. Right-click on **Postman** in the search results
3. Select **"Pin to taskbar"** or **"Open file location"**
4. If you opened file location, right-click the Postman icon and select **"Create shortcut"**
5. Move the shortcut to your desktop

---

### Method 2: Microsoft Store (Alternative)

#### When to Use This Method:
- You prefer installing apps from the Microsoft Store
- You want automatic updates
- You have a restricted work computer that allows Store apps

#### Steps:

1. Press **Windows key** and type **"Microsoft Store"**
2. Open the Microsoft Store app
3. Search for **"Postman"** in the search box
4. Click on the Postman app in search results
5. Click **"Get"** or **"Install"**
6. Wait for download and installation (automatic)
7. Click **"Launch"** when complete

**Note:** The Microsoft Store version is exactly the same as the direct download version.

---

## macOS Installation

### Step 1: Download Postman

1. Open Safari, Chrome, or any web browser

2. Go to: **https://www.postman.com/downloads/**

3. Click the **"Download"** button
   - The site detects your Mac and shows "Download for Mac"
   - You'll see two options if you have an M1/M2 Mac:
     - **Apple Silicon** (for M1/M2 Macs)
     - **Intel Chip** (for older Macs)

**How to know which Mac you have:**
1. Click the Apple menu (top-left corner)
2. Select "About This Mac"
3. Look at the "Chip" or "Processor" line:
   - If it says "Apple M1" or "Apple M2" → download Apple Silicon version
   - If it says "Intel Core" → download Intel version

4. The file `Postman-osx-[version].zip` will download to your Downloads folder

#### Step 2: Install Postman

1. **Find the downloaded file:**
   - Open Finder
   - Click "Downloads" in the sidebar
   - Look for `Postman-osx-[version].zip`

2. **Extract the app:**
   - Double-click the .zip file
   - macOS will automatically extract `Postman.app`

3. **Move to Applications:**
   - Drag `Postman.app` to your **Applications** folder
   - This is important! If you run it from Downloads, it might not work properly

**Why move to Applications:** macOS expects apps to be in the Applications folder. This ensures proper permissions and updates.

#### Step 3: First Launch

1. **Open Postman:**
   - Go to Applications folder
   - Double-click **Postman**

2. **Security prompt:**
   - You might see: "Postman is an app downloaded from the internet. Are you sure you want to open it?"
   - Click **"Open"**

**If you see "Postman cannot be opened because the developer cannot be verified":**

This is a macOS security feature. To fix:
1. Open **System Preferences**
2. Go to **Security & Privacy**
3. Click the **General** tab
4. You'll see a message about Postman being blocked
5. Click **"Open Anyway"**
6. Confirm by clicking **"Open"**

#### Step 4: Grant Permissions (if needed)

Postman might ask for permissions:

1. **Network Access:**
   - Allow this - Postman needs to send requests to APIs
   
2. **Keychain Access (optional):**
   - This lets Postman securely store passwords and tokens
   - You can allow or deny based on your preference

#### Step 5: Verify Installation

1. Postman should now be running
2. You'll see the welcome screen
3. You can optionally sign in or click "Skip"

**Congratulations! Postman is installed on your Mac.**

---

## Linux Installation

Linux has several distributions (Ubuntu, Debian, Fedora, Kali, etc.), so we'll cover the most common methods.

### For Ubuntu / Debian / Kali Linux

#### Method 1: Using Snap (Easiest)

**What is Snap?** It's a package manager that makes installing apps easy on Ubuntu and similar systems.

**Check if you have Snap:**
```bash
snap --version
```

If you see version information, you have Snap installed. If not, install it:
```bash
sudo apt update
sudo apt install snapd
```

**Install Postman with Snap:**

1. Open Terminal (Ctrl + Alt + T)

2. Run this command:
```bash
sudo snap install postman
```

3. Enter your password when prompted

4. Wait for download and installation (2-5 minutes)

5. Launch Postman:
```bash
postman
```

Or find it in your Applications menu.

**Why use Snap:**
- Automatic updates
- Isolated from system files (safer)
- Easy to uninstall
- One command installation

#### Method 2: Download .tar.gz File

If Snap doesn't work or you prefer manual installation:

1. **Download Postman:**
```bash
cd ~/Downloads
wget https://dl.pstmn.io/download/latest/linux64 -O postman-linux-x64.tar.gz
```

2. **Extract the archive:**
```bash
sudo tar -xzf postman-linux-x64.tar.gz -C /opt
```

**What this does:**
- `-x`: Extract files
- `-z`: Decompress gzip
- `-f`: From file
- `-C /opt`: Extract to /opt directory

3. **Create a symbolic link:**
```bash
sudo ln -s /opt/Postman/Postman /usr/bin/postman
```

**What this does:** Creates a shortcut so you can type `postman` from anywhere in Terminal.

4. **Create desktop entry:**
```bash
cat > ~/.local/share/applications/postman.desktop <<EOL
[Desktop Entry]
Name=Postman
Comment=API Development Environment
Exec=/opt/Postman/Postman
Icon=/opt/Postman/app/resources/app/assets/icon.png
Terminal=false
Type=Application
Categories=Development;
EOL
```

**What this does:** Creates a menu entry so Postman appears in your applications menu.

5. **Launch Postman:**
```bash
postman
```

---

### For Fedora / Red Hat / CentOS

#### Using Flatpak

1. **Install Flatpak (if not installed):**
```bash
sudo dnf install flatpak
```

2. **Add Flathub repository:**
```bash
flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo
```

3. **Install Postman:**
```bash
flatpak install flathub com.getpostman.Postman
```

4. **Launch Postman:**
```bash
flatpak run com.getpostman.Postman
```

---

### For Arch Linux

```bash
yay -S postman-bin
```

Or use `pamac` or your preferred AUR helper.

---

## Verification Steps

After installing on any platform, verify Postman works correctly:

### Step 1: Launch Postman

- **Windows:** Click Start Menu → Postman
- **macOS:** Applications → Postman
- **Linux:** Type `postman` in terminal or find in app menu

### Step 2: Check Version

1. Open Postman
2. Click **"Help"** in the top menu (macOS: Postman menu)
3. Click **"About Postman"**
4. You should see version information like: "Postman v10.x.x"

**Why check version:** Ensures you have the latest features and security updates.

### Step 3: Test Basic Functionality

Let's send a simple test request to make sure everything works:

1. In Postman, look for a text box that says "GET" next to "Enter request URL"

2. In the URL box, type:
```
https://httpbin.org/get
```

3. Click the blue **"Send"** button

4. You should see a response below showing:
```json
{
  "args": {},
  "headers": {
    ...
  },
  "url": "https://httpbin.org/get"
}
```

**If you see this response, Postman is working perfectly!**

**What just happened:**
- Postman sent a GET request to httpbin.org (a free testing service)
- The server sent back information about your request
- Postman displayed the response in JSON format

### Step 4: Check Network Connectivity

If the test request failed:

1. **Check your internet connection:**
   - Open a web browser
   - Try visiting https://www.google.com
   - If that doesn't work, fix your internet connection first

2. **Check firewall:**
   - Your firewall might be blocking Postman
   - Temporarily disable firewall to test
   - If that fixes it, add Postman to firewall exceptions

3. **Check proxy settings:**
   - If you're on a corporate network, you might need proxy settings
   - Go to: Settings → Proxy
   - Enter your company's proxy details

---

## Initial Setup

### Optional: Create a Postman Account

**Benefits of creating an account:**
- Sync collections across devices
- Back up your work to the cloud
- Collaborate with teams
- Access to API documentation

**How to create an account:**

1. In Postman, click **"Sign In"** (top-right corner)

2. Choose one of these options:
   - **Email:** Enter your email and create a password
   - **Google:** Sign in with your Google account
   - **GitHub:** Sign in with your GitHub account

3. Check your email for a verification link (if using email signup)

4. Click the verification link

5. Return to Postman - you're now signed in!

**Privacy note:** Postman's free tier is generous. Your data is encrypted, and you control what gets synced.

### Configure Basic Settings

Let's set up Postman for optimal use:

1. **Click the Settings icon** (gear icon, top-right) or go to **File → Settings**

2. **General Tab:**
   - **Theme:** Choose Light or Dark (whichever you prefer)
   - **Send cookies:** Keep enabled
   - **Follow redirects:** Keep enabled
   - **Validate certificates:** Keep enabled for security

3. **Themes:**
   - Try both light and dark modes
   - Pick what's easier on your eyes

4. **Shortcuts:**
   - Review keyboard shortcuts
   - Common ones:
     - `Ctrl/Cmd + Enter`: Send request
     - `Ctrl/Cmd + S`: Save
     - `Ctrl/Cmd + N`: New tab

---

## Common Problems and Solutions

### Problem 1: "Postman won't open" (Windows)

**Symptoms:** Double-clicking Postman does nothing, or it briefly shows then disappears.

**Solutions:**

**Solution A: Run as Administrator**
1. Right-click Postman icon
2. Select "Run as administrator"
3. Click "Yes" on the security prompt

**Solution B: Check Antivirus**
1. Some antivirus programs block Postman
2. Check your antivirus quarantine
3. Add Postman to exceptions/whitelist

**Solution C: Clean Reinstall**
1. Uninstall Postman (Settings → Apps → Postman → Uninstall)
2. Delete folder: `C:\Users\YourName\AppData\Local\Postman`
3. Download and install again

### Problem 2: "Connection Refused" Errors

**Symptoms:** All requests fail with "Could not get any response" or "Connection refused"

**Solution A: Check Proxy Settings**
1. Go to Settings → Proxy
2. If you're NOT on a corporate network:
   - Select "Global Proxy Configuration"
   - Choose "Use System Proxy"
3. If you ARE on a corporate network:
   - Ask your IT department for proxy details
   - Enter them in "Custom Proxy Configuration"

**Solution B: Disable VPN**
1. If you're using a VPN, try disabling it
2. Test if requests work without VPN
3. If they do, configure VPN to allow Postman

**Solution C: Check Firewall**
1. Windows: Control Panel → System and Security → Windows Defender Firewall → Allow an app
2. Find Postman in the list
3. Enable both "Private" and "Public" checkboxes

### Problem 3: "Postman is Slow" (All Platforms)

**Solutions:**

**Solution A: Clear Cache**
1. Go to Settings → Data
2. Click "Clear data"
3. Restart Postman

**Solution B: Disable Unnecessary Features**
1. Settings → General
2. Disable "Automatically persist variable values"
3. Disable "Send anonymous usage data"

**Solution C: Update Postman**
1. Help → Check for Updates
2. Install any available updates
3. Restart Postman

### Problem 4: SSL Certificate Errors

**Symptoms:** Requests to HTTPS sites fail with "SSL certificate problem"

**Solution:**
1. Settings → General
2. Find "SSL certificate verification"
3. Toggle it OFF temporarily
4. Try your request again

**Important:** Only disable SSL verification for testing! Re-enable it for production use.

**Why this happens:** Some test servers use self-signed certificates that Postman doesn't trust by default.

### Problem 5: Can't Import Collections

**Symptoms:** Clicking "Import" does nothing or shows errors

**Solutions:**

**Solution A: Check File Format**
1. Make sure the file is a .json file
2. Open it in a text editor to verify it's valid JSON
3. Look for any obvious syntax errors

**Solution B: Try Dragging and Dropping**
1. Instead of clicking Import
2. Drag the .json file directly into Postman
3. Drop it anywhere in the Postman window

**Solution C: Import from URL**
1. Upload the collection file to GitHub or a file sharing service
2. Get the raw URL
3. In Postman: Import → Link
4. Paste the URL

### Problem 6: Linux-Specific: "Cannot Execute Binary File"

**Symptom:** Running `postman` gives "cannot execute binary file"

**Solution:**
1. Check if you downloaded the correct version:
```bash
uname -m
```
2. Make sure you downloaded `linux64` version
3. Re-download if necessary

### Problem 7: macOS-Specific: "Postman is Damaged"

**Symptom:** "Postman.app is damaged and can't be opened"

**Solution:**
1. This is a Gatekeeper issue
2. Open Terminal
3. Run:
```bash
xattr -cr /Applications/Postman.app
```
4. Try launching Postman again

---

## Alternative Installation Methods

### Portable Version (Windows Only)

If you don't want to install Postman (useful for USB drives):

1. Download Postman zip file from postman.com
2. Extract to a folder
3. Run `Postman.exe` from the extracted folder
4. No installation needed!

**Limitations:**
- Slower to start
- Might have permission issues
- Updates not automatic

### Using Package Managers

**Windows (Chocolatey):**
```powershell
choco install postman
```

**macOS (Homebrew):**
```bash
brew install --cask postman
```

**Linux (Various):**
```bash
# Ubuntu/Debian
sudo snap install postman

# Fedora
sudo flatpak install postman

# Arch
yay -S postman-bin
```

---

## Post-Installation Checklist

Before moving to the next guide, make sure:

- [ ] Postman is installed and launches successfully
- [ ] You completed the test request to httpbin.org
- [ ] You can see the Postman interface clearly
- [ ] (Optional) You created a Postman account
- [ ] Settings are configured to your preference
- [ ] You know where to find Help if needed

---

## Next Steps

**Congratulations!** You've successfully installed Postman and verified it works. 

**What to do next:**

1. **Read 02_POSTMAN_BASICS.md** to learn the interface and basic features
2. **Keep this guide handy** in case you need to troubleshoot
3. **Bookmark the Postman documentation:** https://learning.postman.com/

**Remember:** Installation is just the beginning. The real learning starts when you begin using Postman to test APIs and find vulnerabilities!

---

## Quick Reference

**Installation Commands:**

```bash
# Ubuntu/Debian/Kali
sudo snap install postman

# Fedora
flatpak install flathub com.getpostman.Postman

# macOS
brew install --cask postman

# Windows (Chocolatey)
choco install postman
```

**Test Postman Works:**
```
URL: https://httpbin.org/get
Method: GET
Expected: JSON response with status 200
```

**Key Locations:**

- **Windows:** `C:\Users\YourName\AppData\Local\Postman`
- **macOS:** `/Applications/Postman.app`
- **Linux:** `/opt/Postman` or via Snap/Flatpak

**Getting Help:**

- Help menu in Postman
- https://learning.postman.com/
- https://community.postman.com/
- This guide series!
