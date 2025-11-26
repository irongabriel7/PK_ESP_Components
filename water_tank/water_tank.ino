/******************************************************
 *  ESP8266 Water Tank Monitor — Secure Version (Stable)
 *  Features:
 *  ✔ HMAC SHA256 Authentication (intrbiz/arduino-crypto)
 *  ✔ AES-128 CBC Encrypted Messages (AESLib)
 *  ✔ Only Authorized Android App Can Control ESP
 *  ✔ WiFi auto-heal + watchdog-friendly loop
 *  ✔ Averaged tank water level reading
 ******************************************************/

#include <ESP8266WiFi.h>
#include <WebSocketsServer_Generic.h>
#include <ArduinoJson.h>

#include <ESP8266mDNS.h>
#include <WiFiUdp.h>
#include <ArduinoOTA.h>

#include <AESLib.h>
#include <Crypto.h>           // from intrbiz/arduino-crypto
#include <Hash.h>

// -------------------- WiFi --------------------
const char* ssid     = "HomeServer";
const char* password = "PASSWORD";

WebSocketsServer webSocket = WebSocketsServer(81);

// -------------------- SECURITY --------------------

// Shared secret (must match Android AppConfig.SECRET_KEY)
const char* SECRET_KEY = "PK_SEC_*******"; //Sample Value: PK_SEC_23A9F1D44B7C27EE4A78219F4C55E7C1 Match this value in App as well

// AES-128 Key (16 bytes) – must match AppConfig.AES_KEY 
//This is also SAMPLE KEY, you can create your own
byte aes_key[16] = {
  0x9F,0x12,0xA8,0xC3,0x44,0x77,0x19,0xB2,
  0x8D,0x66,0x3E,0x19,0x74,0xAA,0xC1,0x08
};

// AES IV (16 bytes) – must match AppConfig.AES_IV
byte aes_iv[N_BLOCK] = {
  0xA4,0x51,0x93,0x21,0xD9,0x11,0x8C,0x72,
  0x0F,0x3A,0x55,0x84,0x22,0x1F,0x90,0xB8
};

AESLib aesLib;

// Keep track of which websocket clients are authenticated
bool authorized[10] = {false};

// Some Crypto libraries *don’t* define this, so be safe:
#ifndef SHA256HMAC_SIZE
#define SHA256HMAC_SIZE 32
#endif

// ---------------- Ultrasonic Sensor ----------------
#define TRIG_PIN D5
#define ECHO_PIN D6
#define TANK_HEIGHT 120   // cm
#define MAX_DISTANCE 300  // cm (ignore readings beyond this)
// ---------------- Relay ----------------
#define RELAY_1 D0
#define RELAY_2 D3

long duration;
int relay1 = 1, relay2 = 1;

// ===================================================
//                HELPER: WiFi Setup
// ===================================================
void setupWiFi() {
  Serial.println();
  Serial.println("Connecting WiFi...");

  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(true);   // set this BEFORE begin
  WiFi.persistent(false);        // don't keep reconnect info in flash
  WiFi.begin(ssid, password);

  unsigned long startAttemptTime = millis();

  while (WiFi.status() != WL_CONNECTED &&
         millis() - startAttemptTime < 15000) {
    Serial.print(".");
    delay(500);
    yield();
  }

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("\nWiFi connection failed (boot). Will retry in loop.");
    return; // <-- IMPORTANT: DON'T RESTART HERE
  }

  Serial.println("\nWiFi connected!");
  Serial.print("IP: ");
  Serial.println(WiFi.localIP());
}
// ===================================================
//          WiFi Auto-Heal (No Hard Reboot)
// ===================================================
void maintainWiFi() {
  static unsigned long lastAttempt = 0;

  if (WiFi.status() == WL_CONNECTED) return;

  // WiFi is down
  if (millis() - lastAttempt < 10000) {
    // avoid spamming reconnects
    return;
  }

  lastAttempt = millis();
  Serial.println("WiFi lost! Trying to reconnect...");

  WiFi.disconnect();
  WiFi.begin(ssid, password);
}

// ===================================================
//           AES ENCRYPT / DECRYPT HELPERS
// ===================================================
// NOTE: AESLib encrypt64/decrypt64 signature is:
// uint16_t encrypt64(const byte *input, uint16_t input_length,
//                    char *output, const byte key[], int bits_or_keylen, byte my_iv[]);
// uint16_t decrypt64(char *input, uint16_t input_length,
//                    byte *output, const byte key[], int bits_or_keylen, byte my_iv[]);

String encryptAES(const String& plainText) {
  char encrypted[256];
  memset(encrypted, 0, sizeof(encrypted));

  uint16_t len = plainText.length();
  if (len > 240) len = 240;

  // Use a local IV copy so IV doesn’t get destroyed
  byte iv_copy[N_BLOCK];
  memcpy(iv_copy, aes_iv, N_BLOCK);

  aesLib.encrypt64(
    (const byte*)plainText.c_str(),
    len,
    encrypted,
    aes_key,
    sizeof(aes_key),   // same style as AESLib examples
    iv_copy
  );

  return String(encrypted);   // base64 text
}

String decryptAES(uint8_t* data, size_t len) {
  char decrypted[256];
  memset(decrypted, 0, sizeof(decrypted));

  if (len > 240) len = 240;

  // data is base64-encoded ciphertext string
  // AESLib expects char* for decrypt64 input
  char *input = (char*)data;

  byte iv_copy[N_BLOCK];
  memcpy(iv_copy, aes_iv, N_BLOCK);

  aesLib.decrypt64(
    input,
    (uint16_t)len,
    (byte*)decrypted,
    aes_key,
    sizeof(aes_key),
    iv_copy
  );

  return String(decrypted);
}

// ===================================================
//       HMAC SHA-256 (intrbiz/arduino-crypto)
// ===================================================
// Make sure you actually have *intrbiz* arduino-crypto installed,
// not the unrelated "Arduino Cryptography Library" which also has Crypto.h.
String hmacSHA256(const String& msg, const char* keyStr) {
  uint8_t hash[32];
  br_hmac_key_context kc;
  br_hmac_context ctx;

  br_hmac_key_init(&kc, &br_sha256_vtable, keyStr, strlen(keyStr));
  br_hmac_init(&ctx, &kc, 0);
  br_hmac_update(&ctx, msg.c_str(), msg.length());
  br_hmac_out(&ctx, hash);

  char out[65];
  for (int i = 0; i < 32; i++) {
    sprintf(out + (i * 2), "%02x", hash[i]);
  }
  out[64] = 0;
  return String(out);
}

bool verifyAuth(const String& token, const String& ts) {
  String expected = hmacSHA256(ts, SECRET_KEY);
  Serial.print("Expected HMAC: ");
  Serial.println(expected);
  Serial.print("Client   HMAC: ");
  Serial.println(token);
  return (token == expected);
}

// ===================================================
//        Ultrasonic with Averaging for Stability
// ===================================================
int getTankLevelPercent() {
  const int SAMPLES = 5;
  float sumDist = 0;
  int valid = 0;

  for (int i = 0; i < SAMPLES; i++) {
    digitalWrite(TRIG_PIN, LOW);
    delayMicroseconds(2);
    digitalWrite(TRIG_PIN, HIGH);
    delayMicroseconds(10);
    digitalWrite(TRIG_PIN, LOW);

    duration = pulseIn(ECHO_PIN, HIGH, 30000); // 30ms timeout
    float dist = duration * 0.0343 / 2;        // in cm

    if (dist > 0 && dist <= MAX_DISTANCE) {
      sumDist += dist;
      valid++;
    }

    delay(10);
    yield(); // feed watchdog
  }

  if (valid == 0) {
    // all readings invalid
    return -1;
  }

  float avgDist = sumDist / valid;

  float levelCM = TANK_HEIGHT - avgDist;
  if (levelCM < 0) levelCM = 0;
  if (levelCM > TANK_HEIGHT) levelCM = TANK_HEIGHT;

  int percent = (levelCM * 100.0) / TANK_HEIGHT;
  if (percent < 0) percent = 0;
  if (percent > 100) percent = 100;

  return percent;
}

// ===================================================
//            Send Encrypted Status to Clients
// ===================================================
void sendStatus() {
  // Don't try to send if WiFi or WebSocket is not ready
  if (WiFi.status() != WL_CONNECTED) return;
  if (webSocket.connectedClients() == 0) return;

  StaticJsonDocument<128> doc;
  int level = getTankLevelPercent();

  doc["level"] = level;
  doc["r1"]    = relay1;
  doc["r2"]    = relay2;

  String json;
  serializeJson(doc, json);

  String encrypted = encryptAES(json);

  // In case of weird socket states, wrap in simple guard
  if (encrypted.length() > 0) {
    webSocket.broadcastTXT(encrypted);
  }

  yield(); // let WiFi / watchdog breathe
}

// ===================================================
//                 WebSocket Handler
// ===================================================
void onWebSocketEvent(uint8_t id, WStype_t type, uint8_t *payload, size_t len) {

  switch (type) {

    case WStype_CONNECTED:
      Serial.printf("Client %u connected\n", id);
      if (id < 10) authorized[id] = false;

      // Optionally send initial status here:
      sendStatus();
      break;

    case WStype_DISCONNECTED:
      Serial.printf("Client %u disconnected\n", id);
      if (id < 10) authorized[id] = false;
      break;

    case WStype_TEXT: {
      // First decrypt message
      String decrypted = decryptAES(payload, len);
      Serial.print("Decrypted payload: ");
      Serial.println(decrypted);

      StaticJsonDocument<256> doc;
      DeserializationError err = deserializeJson(doc, decrypted);
      if (err) {
        Serial.print("Bad JSON: ");
        Serial.println(err.c_str());
        return;
      }

      // -------- AUTH MESSAGE ----------
      if (doc.containsKey("auth") && doc.containsKey("ts")) {
        String token = doc["auth"].as<String>();
        String ts    = doc["ts"].as<String>();

        if (verifyAuth(token, ts)) {
          Serial.println("AUTH SUCCESS ✔");
          if (id < 10) authorized[id] = true;
          sendStatus();
        } else {
          Serial.println("AUTH FAIL ❌");
          webSocket.disconnect(id);
        }
        return;
      }

      // Reject if NOT authenticated
      if (id >= 10 || !authorized[id]) {
        Serial.println("Unauthorized client blocked!");
        webSocket.disconnect(id);
        return;
      }

      // -------- Relay Control ----------
      if (doc.containsKey("relay1")) {
        relay1 = doc["relay1"];
        digitalWrite(RELAY_1, relay1);
      }
      if (doc.containsKey("relay2")) {
        relay2 = doc["relay2"];
        digitalWrite(RELAY_2, relay2);
      }

      sendStatus();
      break;
    }
  }
}

// ===================================================
//                       Setup
// ===================================================
void setup() {
  Serial.begin(115200);

  pinMode(TRIG_PIN, OUTPUT);
  pinMode(ECHO_PIN, INPUT);

  pinMode(RELAY_1, OUTPUT);
  pinMode(RELAY_2, OUTPUT);
  digitalWrite(RELAY_1, HIGH);
  digitalWrite(RELAY_2, HIGH);

  setupWiFi();

  // OTA handlers (unchanged)
  ArduinoOTA.onStart([]() {
    String type;
    if (ArduinoOTA.getCommand() == U_FLASH)
      type = "sketch";
    else // U_SPIFFS
      type = "filesystem";
    Serial.println("Start updating " + type);
  });
  ArduinoOTA.onEnd([]() {
    Serial.println("\nEnd");
  });
  ArduinoOTA.onProgress([](unsigned int progress, unsigned int total) {
    Serial.printf("Progress: %u%%\r", (progress / (total / 100)));
  });
  ArduinoOTA.onError([](ota_error_t error) {
    Serial.printf("Error[%u]: ", error);
    if (error == OTA_AUTH_ERROR) Serial.println("Auth Failed");
    else if (error == OTA_BEGIN_ERROR) Serial.println("Begin Failed");
    else if (error == OTA_CONNECT_ERROR) Serial.println("Connect Failed");
    else if (error == OTA_RECEIVE_ERROR) Serial.println("Receive Failed");
    else if (error == OTA_END_ERROR) Serial.println("End Failed");
  });
  ArduinoOTA.begin();

  // AES padding mode (same on Android)
  aesLib.set_paddingmode(paddingMode::CMS);

  webSocket.begin();
  webSocket.onEvent(onWebSocketEvent);

  // Heartbeat: pings clients, drops dead ones
  webSocket.enableHeartbeat(15000, 3000, 2);

  Serial.println("WebSocket server started on port 81");
}

// ===================================================
//                        Loop
// ===================================================
unsigned long lastSend = 0;

void loop() {
  // Keep OTA + WebSocket alive
  ArduinoOTA.handle();
  webSocket.loop();

  // Handle WiFi auto-heal WITHOUT hard restart
  maintainWiFi();

  // If WiFi is down, skip sending anything
  if (WiFi.status() != WL_CONNECTED) {
    // small delay to avoid busy loop
    delay(10);
    yield();
    return;
  }

  // Periodic status broadcast (e.g. every 500ms instead of 100ms)
  if (millis() - lastSend > 500) {
    lastSend = millis();
    sendStatus();
  }

  // Safety reboot after ~24 hours to avoid heap fragmentation
  if (millis() > 86400000UL) {
    Serial.println("24h elapsed, safety restart");
    ESP.restart();
  }

  // Feed watchdog
  yield();
}
