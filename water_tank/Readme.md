# ESP8266 Water Tank Monitor (Secure Version)

A fully secure IoT water-tank monitoring and relay-control system built using an **ESP8266**, **AES-128 encryption**, and **HMAC SHA-256 authentication**. Includes socket-based control, OTA firmware updates, automatic WiFi recovery, and stable ultrasonic water-level measurement.

## ✨ Features

✔ Encrypted communication (AES-128 CBC mode)  
✔ Authentication using HMAC SHA-256  
✔ Secure Android App only (not a public REST API)  
✔ WebSocket server on port `81`  
✔ Ultrasonic water level measurement with noise filtering  
✔ Dual relay control (pump ON/OFF automation)  
✔ Automatic WiFi reconnect + watchdog safe loop  
✔ OTA firmware updates  
✔ Heartbeat system for detecting dead WebSocket clients  
✔ Auto-healing WiFi reconnection logic  
✔ Clean JSON protocol

## 🛡 Secure Architecture

This project uses two-layer security:

### 🔐 1. HMAC Authentication

Every client must send:
```json
{ "auth":"<hmac>", "ts":"<timestamp>" }
```

The ESP calculates:
```
expected = HMAC_SHA256(timestamp, SECRET_KEY)
```

If they match → connection accepted.  
If not → WebSocket is closed immediately.

### 🔒 2. AES-128 Encryption

All JSON commands and responses are fully encrypted using:

- AES-128 CBC
- Shared IV + Key
- Encrypted Base64 packets

This prevents packet sniffing, replay attacks, and relay hijacking.

## 📡 Hardware Requirements

- NodeMCU / ESP8266 board
- Ultrasonic sensor **HC-SR04**
- 2× Relays
- Any 5V or 3.3V power source

### Pin Mapping

| Component | Pin |
|----------|-----|
| Trigger  | D5  |
| Echo     | D6  |
| Relay 1  | D0  |
| Relay 2  | D3  |

## 📏 Water Level Logic

The ESP measures multiple samples and validates them:

- Outliers are filtered
- Values averaged
- Converted into tank percentage

Set your tank height here:
```cpp
#define TANK_HEIGHT 120
```

## 🔧 Software & Library Dependencies

Install the following:

- ESP8266 Core
- WebSocketsServer_Generic
- ArduinoJson
- ArduinoOTA
- intrbiz/arduino-crypto library
- AESLib

## 🧠 Data Packet Format

### Encrypted messages from Android:
```json
{ "relay1":1, "relay2":0 }
```

### Encrypted ESP response:
```json
{ "level":85, "r1":1, "r2":0 }
```

Broadcast frequency: every 500ms (configurable)

## ⚙ OTA Update Support

Just upload via Arduino IDE with:
```
Network Ports → ESP8266 (OTA)
```
OTA events are printed to Serial Monitor.

## 🔄 WiFi Auto-Recovery

If WiFi disconnects:

- ESP attempts auto-reconnect
- Does NOT insta-restart
- If down for too long → reboot safety

This solves the common WebSocket hang situation.

## 🔌 Relay Control

Used to toggle pump or valve:
```json
{ "relay1": 1 }
{ "relay2": 0 }
```

State is broadcast to all authorized clients.

## 🧱 Architecture Diagram

```
┌─────────┐       WiFi       ┌────────────┐
│ Android │ ↔ WebSockets ↔  │ ESP8266     │
│  App    │  Encrypted JSON  │ WebSocket   │
└─────────┘                  │  Server    │
                             ├────────────┤
                             │ AES + HMAC │
                             │ Relay Ctrl │
                             │ OTA + Heal │
                             │ Tank Level │
                             └────────────┘
```

## 📁 Project Structure

```
/water_tank
  └ water_tank.ino
/android
  └ secure app implementation
```

## 🚀 Getting Started

1. Clone the repo:
```bash
git clone https://github.com/irongabriel7/water-tank
```

2. Open `.ino` in Arduino IDE.

3. Update credentials:
```cpp
const char* ssid     = "HomeServer";
const char* password = "yourpassword";
```

4. Flash to ESP8266.

5. Open Serial Monitor:
```
baud: 115200
```

## 🔥 Security Notes

- Keys must match Android app
- App cannot connect without the key
- No unauthenticated WebSocket control possible

Update keys here:

```cpp
const char* SECRET_KEY = "...";
byte aes_key[16] = {...};
byte aes_iv[16]  = {...};
```

## 🧪 Testing WebSocket

Open port:
```
ws://<your-ip>:81
```

If client sends invalid auth → ESP drops it automatically.

## 🛠 Troubleshooting

| Issue | Fix |
|-------|-----|
| Stuck after WiFi fallback | Auto-heal + reconnect logic |
| No ultrasonic reading | Lower MAX_DISTANCE or change pins |
| Relay reversed | Swap HIGH/LOW |

## 🎯 Roadmap

- WiFi AP fallback mode
- Overcurrent protection with sensors
- MQTT optional backend
- Mobile UI improvement

## 📜 License

Free for educational, and private use.
