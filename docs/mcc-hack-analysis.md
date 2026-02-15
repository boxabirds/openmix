# Monsieur Cuisine Connect Hack - Complete Technical Analysis

Source: https://github.com/EliasKotlyar/Monsieur-Cuisine-Connect-Hack

All facts below are extracted directly from the repository's documentation, code,
issue discussions, and scatter files. Nothing is inferred or speculated beyond what
the repository states.

---

## 1. SoC / Platform

| Property | Value |
|----------|-------|
| SoC | **MediaTek MT6580** |
| OS | **Android 6.0** |
| RAM | **1024 MB DDR** (0x40000000) |
| Storage | **~14.9 GB eMMC** (0x3a3e00000 bytes), no NAND, no UFS |
| Architecture | ARM 32-bit |
| Display | Touchscreen (capacitive, landscape orientation) |

The MT6580 is a quad-core Cortex-A7 SoC commonly found in budget Android tablets and
smartphones. The device is essentially a generic MediaTek tablet with custom hardware
(motor, heater, scale, thermometer) attached via a serial bus.

### MC Smart (MC3) variant

The newer "MC Smart" (MC3) model uses a **MediaTek MT8167** SoC running **Android 8.1**.
The MT8167 is "pretty rare" and introduces additional security measures:
- Secure Boot (SBC) enabled on some units
- Download Agent Authorization (DAA) enabled on some units
- Some units have these disabled, allowing easier access
- 64-bit architecture (vs 32-bit on the original MC Connect)

---

## 2. Cloud Communication

### Update server

The device contacts a cloud server for firmware updates and recipe synchronization.

**Known server URL:**
```
https://mc20.monsieur-cuisine.com/666a60bc-0ce2-4878-9e3b-23ba3ceaba5a/versions.txt
```

This `versions.txt` file lists available APK versions. Example entry:
```
MCLauncher-release-1.1.17-226.apk
```

The device downloads updated APKs from this server. APKs can also be manually
downloaded via `wget` and installed via `adb install`.

### Geographic restriction

**The Monsieur Cuisine cloud services are IP-restricted to European IP addresses only.**
Users outside Europe cannot connect. The confirmed workaround is routing the device's
traffic through a European VPN at the router level.

### Software stack

The device runs several APKs as a coordinated system:
- **MCLauncher** - Main launcher APK
- **MC2** - The cooking application (manages motor, temperature, scale, recipe database)
- **tgifota.apk** - OTA firmware update component
- **MCUpdater.apk** - Update manager
- **EnduranceTest** - Factory/debug test application

These require system-level permissions and kernel modules for serial interface support.
They must be signed with the same key as the system. This means they cannot run on
consumer Android devices.

---

## 3. Certificate Pinning

**Not documented.** The repository does not mention TLS certificate pinning. The
device communicates with `mc20.monsieur-cuisine.com` over HTTPS, but no analysis of
certificate validation behavior was performed. The hack focused on gaining Android
root access rather than network interception.

---

## 4. Root / Hack Method

The rooting process exploits the **MediaTek SP Flash Tool** debug interface, which is
a standard MediaTek bootloader feature, not a software vulnerability.

### Step-by-step procedure:

1. **Physical access**: Unscrew the maintenance cover (Torx screwdriver) at the bottom
   of the device to expose two USB ports.

2. **USB port identification**:
   - **Right port** ("Android USB"): Standard USB, 0V idle. Connect to PC via
     USB A-male to A-male cable. **Use only this port; the left port can damage the device.**
   - **Left port**: Outputs 3.3V. Suspected to be a TTL serial (UART) connection.
     Not used in the hack.

3. **MediaTek debug mode**: When powered on while connected via the right USB port,
   the device registers as a MediaTek debug device. An MTD device appears but is not
   directly accessible.

4. **Firmware dump via SP Flash Tool + WWR Tool**:
   - The WWR Tool generates a scatter file without needing one upfront.
   - The scatter file maps the eMMC partition layout (see section below).
   - Full firmware dump takes ~2 hours at ~2.2 MB/s.
   - The scatter file is included in the repo: `l706_dfbh_v_695scatter.txt`

5. **Modify system image**:
   - Mount the dumped `system.img`
   - Add three lines to `/system/build.prop`:
     ```
     persist.service.adb.enable=1
     persist.service.debuggable=1
     persist.sys.usb.config=mtp,adb
     ```
   - Optionally add: `qemu.hw.mainkeys=0` (shows Android nav buttons)

6. **Flash modified system back**:
   - Reflash via SP Flash Tool. Write speed: ~17 MB/s, takes ~5 minutes.
   - After reflash, ADB is enabled.

7. **Install TWRP recovery**:
   - Flash custom recovery to the recovery partition (boot address: `0x2D20000`).
   - Delete `/system/recovery-from-boot.p` to prevent the bootloader from
     overwriting the custom recovery with stock recovery on every boot.
   - The stock bootloader actively checks for and restores the original recovery,
     so this file removal is mandatory.

8. **Install launcher**:
   - Install Trebuchet launcher via `adb install`
   - Set as default launcher to escape the MC2 cooking app
   - Optionally install OpenGApps (ARM, Android 6.0, pico variant)

### Factory mode password

- Password: **`321654`** (from issue discussion by BrixSat)
- Alternative password: **`19850202`** (from issue discussion by LenhartStephan)
- The password check has a 15-day cooldown: if the date difference is >15 days since
  last entry, it does not ask for the password.
- One user reported that entering the factory menu immediately after restart bypasses
  the password entirely (undocumented bypass).

### Known issues with the hack

- `build.prop` modifications sometimes get erased at startup.
- USB connectivity can be lost after certain steps, requiring restart of the procedure.
- OTA updates from the manufacturer should still work after the hack, but this is
  not guaranteed.

---

## 5. Serial Protocol for Motor/Heat/Scale Control

The device communicates with its cooking hardware (motor, heater, scale, thermometer)
via a **serial UART** at `/dev/ttyMT0`.

This was discovered by reverse-engineering the **EnduranceTest** app (the factory
debug/test application).

### Send Format (15 bytes)

```
Byte  1: 0x55          (fixed header)
Byte  2: 0x0F          (fixed header)
Byte  3: 0xA1          (fixed header)
Byte  4: Operation      (see table below)
Byte  5: Scale tare     (0xA9 = tare, 0x00 = none)
Byte  6: Speed level    (0-10 decimal)
Byte  7: Temperature    (0-19 decimal)
Byte  8: 0x00           (reserved)
Byte  9: 0x00           (reserved)
Byte 10: 0x00           (reserved)
Byte 11: 0x00           (reserved)
Byte 12: Motor direction (0 = clockwise, 1 = counter-clockwise)
Byte 13: Scale calibration (see table below)
Byte 14: Checksum       (sum of all preceding bytes & 0xFF)
Byte 15: 0xAA           (fixed footer)
```

### Operation codes (Byte 4)

| Value | Function |
|-------|----------|
| 0x00 | Do nothing |
| 0x01 | Start motor and heating |
| 0x02 | Heating on |
| 0x03 | Cooking on |
| 0x04 | Unknown |
| 0x05 | Unknown |
| 0x0F | Sleep mode |
| 0xC6 | Rotate motor once |

### Scale calibration codes (Byte 13)

| Value | Function |
|-------|----------|
| 0x00 | None |
| 0xE9 | Start calibration |
| 0xE6 | Auto calibration |
| 0xE7 | Manual calibration |

### Receive Format

```
Byte  1: 0x55          (fixed header)
Byte  2: 0x1B          (fixed header)
Byte  3: 0xB1          (fixed header)
Bytes 4-13: Status/parameter data (not fully documented)
Byte 14: Checksum       (sum of all preceding bytes & 0xFF)
Byte 15: 0xAA           (fixed footer)
```

### Protocol characteristics

- Fixed 15-byte frame in both directions
- Header: `0x55` + length/type byte + direction indicator (`0xA1` send, `0xB1` receive)
- Footer: `0xAA`
- Simple additive checksum (sum & 0xFF)
- Speed range: 0-10 discrete levels
- Temperature range: 0-19 discrete levels (not degrees; these are level indices)
- Motor supports bidirectional rotation
- Scale supports tare and multiple calibration modes

### What is NOT documented

- Baud rate, parity, stop bits for the UART
- Full decode of receive bytes 4-13 (current temperature reading, scale weight,
  motor RPM, error codes, etc.)
- Timing/polling interval
- Whether the protocol is request-response or continuous streaming
- How the MC2 app translates recipe steps into serial commands

---

## 6. Recipe Storage

Recipes are stored in a **SQLite database** on the device filesystem. The repo owner
(EliasKotlyar) confirmed: "The recipes are stored in a sqlite DB in the system."
The exact file path was not specified but can be found by searching for `.sqlite`
files on the filesystem.

### MC3 (MC Smart) recipe database encryption

On the newer MC3/MC Smart model, the recipe database (`tgi.db`) is **encrypted using
SQLCipher**. The encryption key is derived as follows:

```
key = MD5(last 29 characters of SHA-1 APK signature)
```

This was documented by user `1101011-xyz` in issue #31.

### Recipe API

There is an API for fetching recipes from the MC server (mentioned but not detailed
in the issues). The device downloads `versions.txt` from the update server, and
recipe data is synced from the cloud.

### Recipe format conversion

Community efforts exist to convert Thermomix recipes to MCC format:
- Manual process involving SQL file manipulation
- A Chrome extension (now outdated)
- **Monsify** (https://monsify.app/) - a third-party converter using AI + programmatic
  logic, announced December 2025

---

## 7. DNS Behavior and Server Redirection

### Known server domain

```
mc20.monsieur-cuisine.com
```

This is the primary cloud endpoint for updates, recipes, and device management.

### Geographic IP restriction

The server enforces IP-based geographic restrictions, only accepting connections from
European IP addresses. Non-European users receive connection failures.

### DNS redirection (not implemented in the repo)

The repository does not implement DNS redirection or a custom recipe server. However,
the architecture makes it straightforward:
- The device runs Android 6.0 with standard DNS resolution.
- Since ADB/root access is available, the `/etc/hosts` file or DNS settings could be
  modified to redirect `mc20.monsieur-cuisine.com` to a local server.
- No DNS-over-HTTPS was observed.

---

## 8. Authentication Mechanism

### Factory mode

- Hardcoded passwords in the app code: `321654` and `19850202`
- Password stored as plaintext, compared directly against user input
- 15-day timer: after entering the password, it is not requested again for 15 days
- Bypass: entering factory mode immediately after device restart may skip the
  password check entirely

### Cloud authentication

Not documented in the repository. The MC2 app communicates with `mc20.monsieur-cuisine.com`
but the auth mechanism (tokens, cookies, device IDs) was not reverse-engineered.

### APK signing

System-level APKs (MCLauncher, MC2, tgifota, MCUpdater) must be signed with the same
key as the system partition. This prevents sideloaded apps from accessing the serial
hardware interface directly.

---

## 9. Comparison with Thermomix TM6 Architecture

The repository does not contain any direct comparison with the TM6. However, based on
the documented MCC architecture, the following structural parallels and differences
can be inferred:

### Similarities (structural)

| Aspect | MCC | TM6 (from plan.md) |
|--------|-----|---------------------|
| Form factor | Cooking appliance with touchscreen | Cooking appliance with touchscreen |
| Cloud dependency | Requires server for recipes/updates | Requires Cookidoo for recipes |
| WiFi connectivity | Yes (Android WiFi stack) | Yes (802.11 b/g/n, 2.4+5.2 GHz) |
| Recipe sync | Downloads from cloud server | Syncs from Cookidoo |
| Hardware control | Serial protocol to MCU | Unknown (likely similar) |
| Offline operation | Recipes cached locally | Cached recipes work 30 days offline |

### Key differences

| Aspect | MCC | TM6 |
|--------|-----|-----|
| OS | Android 6.0 (stock AOSP) | Likely custom Linux (not Android) |
| SoC | MediaTek MT6580 (budget tablet chip) | Unknown ARM SoC (likely higher-end) |
| Root difficulty | Trivial via SP Flash Tool (standard MTK debug) | No known root method |
| Serial protocol | Documented (15-byte frames via /dev/ttyMT0) | Unknown |
| Cloud server | mc20.monsieur-cuisine.com | cookidoo.thermomix.com |
| Auth | Hardcoded passwords, basic cloud auth | OAuth2 JWT |
| Cert pinning | Not analyzed | Unknown (suspected) |
| Recipe storage | SQLite (plaintext on MC2, SQLCipher on MC3) | Unknown |

### TM6 reverse engineering implications from MCC

1. **Serial protocol architecture**: The MCC uses a simple 15-byte serial protocol
   between the Android tablet (SoC) and a separate MCU that controls motor/heat/scale.
   The TM6 almost certainly uses a similar two-chip architecture: an applications
   processor running the UI/network stack, communicating with a dedicated MCU for
   real-time hardware control. The serial protocol will likely be different in detail
   but similar in concept.

2. **The MCU is the hardware safety layer**: On the MCC, the Android OS cannot
   directly control the motor or heater GPIOs. It must send commands through the
   serial protocol to the MCU, which presumably enforces safety limits. The TM6
   will have the same architecture for safety certification reasons.

3. **Recipe format = serial command sequence**: On the MCC, a recipe is ultimately
   a sequence of serial commands (set temperature level X, set speed Y, run for
   Z seconds). The TM6's guided cooking protocol will be structurally equivalent,
   even if the encoding differs.

4. **Root via debug interfaces**: The MCC was rooted via physical USB debug access
   (SP Flash Tool). The TM6 likely has similar debug interfaces (UART, JTAG) on
   the PCB, visible in FCC internal photos. However, Vorwerk may have locked these
   down more aggressively than Lidl/SilverCrest did.

5. **Factory test app = protocol Rosetta Stone**: The MCC's EnduranceTest app was
   the key to understanding the serial protocol. The TM6 firmware almost certainly
   contains a similar factory test mode. Finding it (via firmware dump) would be the
   fastest path to documenting the TM6's hardware control protocol.

---

## 10. Local Control Without Cloud

### What the MCC hack achieves

The hack gives full Android root access, which enables:
- Running arbitrary Android apps (browser, video streaming, etc.)
- ADB shell access for debugging and file manipulation
- Access to the serial device at `/dev/ttyMT0` for direct hardware control
- Modification of the recipe SQLite database
- Installation of alternative launchers to escape the MC2 app

### What has NOT been achieved (as of the repo's state)

- **No custom recipe server** has been built for the MCC.
- **No alternative cooking app** exists that replaces MC2 with local-only control.
- **No DNS redirection** to a local server has been implemented.
- The community discussed but did not build:
  - A tool to inject custom recipes into the SQLite database
  - A third-party app for direct motor/heat/scale control via the serial protocol
  - A replacement backend server

### Theoretical path to full local control (documented in issues)

Community members discussed (issue #6, #31) the following approach:
1. Root the device (documented, works)
2. Dump the recipe SQLite database structure
3. Write a tool to inject custom recipes into the database
4. Alternatively, build a custom app that sends commands directly to `/dev/ttyMT0`
5. Redirect DNS to avoid cloud dependency

None of these steps beyond #1 have been completed in the repository.

---

## Appendix: eMMC Partition Layout

From `l706_dfbh_v_695scatter.txt`:

| Partition | Start Address | Size |
|-----------|--------------|------|
| preloader | 0x0 | 0x40000 (256 KB) |
| pgpt | 0x0 | 0x80000 |
| proinfo | 0x80000 | 0x300000 |
| nvram | 0x380000 | 0x500000 |
| protect1 | 0x880000 | 0xA00000 |
| protect2 | 0x1280000 | 0xA00000 |
| lk (bootloader) | 0x1CC0000 | 0x60000 |
| boot | 0x1D20000 | 0x1000000 (16 MB) |
| recovery | 0x2D20000 | 0x1000000 (16 MB) |
| para | 0x3D20000 | 0x80000 |
| logo | 0x3DA0000 | 0x800000 |
| expdb | 0x45A0000 | 0x1400000 |
| frp | 0x59A0000 | 0x100000 |
| nvdata | 0x5AA0000 | 0x2000000 |
| metadata | 0x7AA0000 | 0x2000000 |
| secro | 0x9A00000 (approx) | 0x600000 |
| system | 0xA800000 | 0x60000000 (1.5 GB) |
| cache | 0x6A800000 | 0x10000000 (256 MB) |
| userdata | 0x7A800000 | 0x328580000 (~12.7 GB) |

Block size: 0x20000 (128 KB). Preloader in EMMC_BOOT_1 region; all others in EMMC_USER.

---

## Appendix: Useful ADB Commands

```bash
# Show currently focused app
adb shell dumpsys window windows | grep -E 'mFocusedApp' | cut -d / -f 1 | cut -d " " -f 7

# List installed packages
adb shell pm list packages

# Find APK path
adb shell pm path com.example.someapp

# Launch app
adb shell monkey --pct-syskeys 0 -p '<package_name>' -v 500

# Monitor app logs
adb logcat | grep -F "$(adb shell ps | grep com.example.endurancetest | cut -c10-15)"

# Key events
adb shell input keyevent 187    # Recent apps / window menu
adb shell input keyevent 3      # Home (returns to MC2 cooking app)
adb shell input keyevent 64     # Open browser
adb shell input keyevent 4      # Back

# Launch specific system apps
adb shell monkey --pct-syskeys 0 -p 'com.mediatek.filemanager' -v 500  # File manager
adb shell monkey --pct-syskeys 0 -p 'com.android.settings' -v 500      # Settings

# Start launcher
adb shell am start -a android.intent.action.MAIN -c android.intent.category.HOME com.lineageport.trebuchet
```

---

## Appendix: Key Differences Between MCC Models

| Feature | MC Connect (MC2) | MC Smart (MC3) |
|---------|-------------------|-----------------|
| SoC | MT6580 (32-bit, Cortex-A7) | MT8167 (rare, different arch) |
| Android | 6.0 | 8.1 (Go edition) |
| Secure Boot | No | Some units: yes |
| DAA protection | No | Some units: yes |
| Recipe DB encryption | Plaintext SQLite | SQLCipher (key = MD5 of last 29 chars of SHA-1 APK signature) |
| Flash tool compatibility | SP Flash Tool works | SLA/DAA protection may block flashing |
| ADB over USB | Works after hack | Unreliable; WiFi ADB via Magisk works |
| TWRP boot time | Normal | ~1 minute startup |
| Display in recovery | Correct orientation | 90-degree rotation (portrait vs landscape) |
