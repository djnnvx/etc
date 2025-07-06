/*
   lila ~ https://djnn.sh/posts/why-fi/

   esp8266 packet-sniffer. relays packets count over mqtt & informs you in case of
   deauth attack.

PLEASE NOTE:

  since it uses the same WiFi stack to run analysis & communicate, this really fucking
  sucks. ive attempted to do this just to do something funny. please dont actually use
  this or attempt to replicate. its fucking stupid.

Dependencies:

- arduinojson
- arduino pubsub client
- base64
- time

 */


#include "base64.hpp"
#include <SPI.h>
#include <ArduinoJson.h>
#include <PubSubClient.h>
#include <WiFiClientSecure.h>
#include <Arduino.h>
#include <TimeLib.h>


#ifdef ESP8266
#include <ESP8266WiFi.h>
#else
#include <WiFi.h>
#endif

extern "C" {
  #include "user_interface.h"
}

// ignore stupid warnings
#pragma GCC diagnostic ignored "-Wwrite-strings"

/* CONSTANTS */

#define LED             2           /* LED pin (2=built-in LED) */
#define SERIAL_BAUD     9600        /* Baudrate for serial communication */
#define CH_TIME         140         /* Scan time (in ms) per channel */

#define DELAY_TIME              1000
#define QUICK_DELAY_TIME        500
#define VERY_QUICK_DELAY_TIME   10


#define MQTT_TOPIC_INPUT    "lila_output"
#define MQTT_TOPIC_OUTPUT   "lila_input" /* name is confusing because the chip output is the server input */
#define MQTT_USERNAME       "lila-sniffer"
#define MQTT_PASSWORD       ""
#define MQTT_SERVER_URL     "broker.hivemq.com"
#define MQTT_CLIENT_ID      "djnn.sh"
#define MQTT_PORT           1883

#define STATE_ASLEEP            0
#define STATE_MONITOR_MODE      1
#define STATE_SOFT_AP_MODE      2

#define COMMAND_SET_ASLEEP    "ASLEEP"
#define COMMAND_SET_MONITOR   "MONITOR_DEAUTH"
#define COMMAND_SET_SOFTAP    "SOFTAP"

#define MSG_OK "OK"
#define MSG_KO "KO"

/* VARIABLES */

#define MQTT_MSG_SIZE 512

// program things
unsigned int program_state = STATE_SOFT_AP_MODE;
char mqtt_msg_to_send[MQTT_MSG_SIZE];

WiFiClient net_client;
PubSubClient ps_client(net_client);

int nb_packets = 0;
char ip_address[256];

char saved_ssid[256];
char saved_pass[256];


/* FUNCTIONS */

// Connects to local WiFi hotspot
void __wifi_local_connect(char const *ssid, char const *pass) {
    WiFi.mode(WIFI_STA);
    WiFi.begin(ssid, pass);
    while (WiFi.status() != WL_CONNECTED) {
        delay(VERY_QUICK_DELAY_TIME);
    }
}


// sets up soft access point on setup
void __wifi_setup_soft_ap() {

    delay(QUICK_DELAY_TIME);
    Serial.println("Setting up soft-AP with credentials: lila1337:lila1337.......");
    if (WiFi.softAP("lila1337", "lila1337")) {
        __blink_success();

        program_state = STATE_SOFT_AP_MODE;

        // ensure we can scan & use AP mode
        WiFi.mode(WIFI_AP_STA);

        IPAddress myIP = WiFi.softAPIP();
        Serial.print("[+] AP IP address: http://");
        Serial.println(myIP);
    } else {
        __blink_failure();
        Serial.println("[!] Could not set up webserver........");
        return;
    }

    Serial.println("Booting up webserver...");

    WiFiClient net_client;
    WiFiServer configWebServer(80);
    configWebServer.begin();

    // run webserver until we have wifi credentials
    while (program_state == STATE_SOFT_AP_MODE) {

        // either scan for Wifi hotspots or connect to them...
        net_client = configWebServer.available();
        if (net_client) {

            char line[64];
            int l = net_client.readBytesUntil('\n', line, sizeof(line));
            line[l] = 0;

            net_client.find((char*) "\r\n\r\n");
            if (strncmp_P(line, PSTR("POST"), strlen("POST")) == 0) {
                l = net_client.readBytes(line, sizeof(line));
                line[l] = 0;

                // parse the parameters sent by the html form
                const char* delims = "=&";
                strtok(line, delims);

                const char* ssid = strtok(NULL, delims);
                strtok(NULL, delims);

                const char* pass = strtok(NULL, delims);

                memset(saved_ssid, 0, 256);
                memset(saved_pass, 0, 256);
                strncpy(saved_ssid, ssid, 256);
                strncpy(saved_pass, pass, 256);

                // send a response before attemting to connect to the WiFi network
                // because it will reset the SoftAP and disconnect the client station
                net_client.println(F("HTTP/1.1 200 OK"));
                net_client.println(F("Connection: close"));
                net_client.println(F("Refresh: 10")); // send a request after 10 seconds
                net_client.println();
                net_client.println(F("<html><body><h3>Configuration AP</h3><br>connecting...</body></html>"));
                net_client.stop();

                Serial.println();
                Serial.print("Attempting to connect to WPA SSID: ");
                Serial.println(ssid);

                WiFi.persistent(true);
                WiFi.setAutoConnect(true);
                WiFi.begin(ssid, pass);
                WiFi.waitForConnectResult();

            } {

                net_client.println(F("HTTP/1.1 200 OK"));
                net_client.println(F("Connection: close"));
                net_client.println();
                net_client.println(F("<html><body><h3>Configuration AP</h3><br>"));

                int status = WiFi.status();
                if (status == WL_CONNECTED) {

                    net_client.println(F("</body></html>"));

                    program_state = STATE_ASLEEP;
                    net_client.println(F("Connection successful. Ending AP."));
                    net_client.stop();

                    delay(1000);
                    Serial.println("Connection successful. Ending AP.");
                    configWebServer.stop();

                    WiFi.mode(WIFI_STA);
                    Serial.print("WiFi status = ");
                    Serial.println(WiFi.status());

                    Serial.print("Local IP address:");
                    Serial.println(WiFi.localIP());


                    return;

                } else {
                    net_client.println(F("<form action='/' method='POST'>WiFi connection failed. Enter valid parameters, please.<br><br>"));
                    net_client.println(F("SSID:<br><input type='text' name='i'><br>"));
                    net_client.println(F("Password:<br><input type='password' name='p'><br><br>"));
                    net_client.println(F("<input type='submit' value='Submit'></form>"));
                    net_client.println(F("</body></html>"));
                }
            }
        }
    }
}

// Reconnects to MQTT server
PubSubClient __mqtt_reconnect(PubSubClient ps_client, WiFiClient net_client, char ip[256]) {

    Serial.printf(
      "[+] Attempting MQTT connection to %s: [username = %s, client id: %s]\n",
      MQTT_SERVER_URL,
      MQTT_USERNAME,
      MQTT_CLIENT_ID
    );

    if (ps_client.connect(MQTT_CLIENT_ID, MQTT_USERNAME, MQTT_PASSWORD)) {
      __blink_success();
      ps_client.subscribe(MQTT_TOPIC_INPUT);
      Serial.printf("Subscribed to topic %s\n", MQTT_TOPIC_INPUT);

    } else {
      __blink_failure();
      Serial.print("error: ");
      Serial.println(ps_client.state());
      return ps_client;
   }

    char mqtt_message[512];
    DynamicJsonDocument js = __get_net_information(net_client, ip);

    serializeJson(js, mqtt_message);
    ps_client.publish(MQTT_TOPIC_OUTPUT, mqtt_message, true);
    Serial.printf("[+] net info: %s\n", mqtt_message);
    return ps_client;
}

// returns public ip address by querying various "what's my IP" services
void __net_get_public_ip(WiFiClient net_client, char *output, size_t output_size) {

    char return_value[256];

    memset(output, 0, output_size);

    strncpy(return_value, "0.0.0.0", 256);
    strncpy(output, return_value, output_size - 1);
    output[output_size - 1] = '\0';

    Serial.println("Attempting to retrieve Public IP address...");

    delay(QUICK_DELAY_TIME);

    // check if service is up & we can connect
    if (!net_client.connect("ipecho.net", 80)) {
        Serial.print("could not connect. status = ");
        Serial.println(net_client.status());
        __blink_failure();
        return;
    }

    // hand-write the request
    net_client.println(F("GET /plain HTTP/1.0"));
    net_client.println(F("Host: ipecho.net"));
    net_client.println(F("User-Agent: lila (ESP8266 packet sniffer)"));
    net_client.println(F("Accept: */*"));
    net_client.println(F("Connection: close"));
    net_client.println();

    delay(5000);

    // skip all lines until last one
    String line;
    do {
        line = net_client.readStringUntil('\n');
    } while (net_client.available());

    // Copy the last line to return_value
    strncpy(output, line.c_str(), output_size - 1);

    Serial.printf("IP Address: %s\n", output);
}


// returns wifi security type (WEP, WPA, etc) as a string to be serialized
char *__wifi_get_security() {
    char *security_descriptors[] = {
        "UNKNOWN",
        "UNKNOWN",
        "TKIP (WPA)",
        "UNKNOWN",
        "CCMP (WPA)",
        "WEP",
        "UNKNOWN",
        "NONE",
        "AUTO",
    };

    return security_descriptors[8];
}

// Retrieves network information related to current SSID
DynamicJsonDocument __get_net_information(WiFiClient net_client, char ip[256]) {

    /*
       Retrieve following information and return it in a JSON-formatted string:

       - SSID
       - signal strength
       - public IP address
       - Security (WPA/WPA2)
       - channel number
       - number of packets
     */

    DynamicJsonDocument js(MQTT_MSG_SIZE);

    js["ssid"] = WiFi.SSID();
    js["mac"] = WiFi.macAddress();
    js["channel"] = WiFi.channel();
    js["strength"] = WiFi.RSSI();
    js["ip-address"] = ip;
    js["security"] = __wifi_get_security();
    js["nb_packets"] = nb_packets;

    return js;
}


// MQTT callback on message read
void __mqtt_read_callback(char* topic, byte* payload, unsigned int length) {

    String msg = "";
    for (int i = 0; i < length; i++)
      msg += (char)payload[i];

    Serial.println("[MQTT] received [" + String(topic) + "]: " + msg);
    if (!strcmp(msg.c_str(), COMMAND_SET_ASLEEP) && program_state != STATE_ASLEEP) {
      Serial.println("SET MODE ASLEEP");
      program_state = STATE_ASLEEP;

      wifi_promiscuous_enable(0);
      wifi_set_promiscuous_rx_cb(__sniffer_asleep);
      wifi_set_channel(WiFi.channel());
      wifi_promiscuous_enable(1);
      goto CALLBACK_SEND_OK;
    }

    if (!strcmp(msg.c_str(), COMMAND_SET_MONITOR) && program_state != STATE_MONITOR_MODE) {
      Serial.println("SET MODE MONITOR");
      program_state = STATE_MONITOR_MODE;

      wifi_promiscuous_enable(0);
      wifi_set_promiscuous_rx_cb(__sniffer_monitor);
      wifi_promiscuous_enable(1);
      goto CALLBACK_SEND_OK;
    }


    if (!strcmp(msg.c_str(), COMMAND_SET_SOFTAP)) { // cannot interact once softap mode enabled
      Serial.println("SET MODE SOFT_AP");
      program_state = STATE_SOFT_AP_MODE;

      wifi_promiscuous_enable(0);
      goto CALLBACK_SEND_OK;
    }

    strncpy(mqtt_msg_to_send, MSG_KO, sizeof(MSG_KO));
    return;

CALLBACK_SEND_OK:
    strncpy(mqtt_msg_to_send, MSG_OK, sizeof(MSG_OK));
    return;
}


// blink for a long time in case of error
void __blink_failure() {
    digitalWrite(LED, LOW);
    delay(DELAY_TIME);
    digitalWrite(LED, HIGH);
}

// blink for a short time in case of success
void __blink_success() {
    digitalWrite(LED, LOW);
    delay(QUICK_DELAY_TIME);
    digitalWrite(LED, HIGH);
}

void __sniffer_relay(uint8_t *buf, uint16_t len) {

  char mqtt_message[512];
  DynamicJsonDocument js(512);

  char pcap[64];
  encode_base64(buf, len, (unsigned char *)pcap);

  js["mac"] = WiFi.macAddress();
  js["strength"] = WiFi.RSSI();
  js["pcap"] = pcap;

  serializeJson(js, mqtt_message);

  Serial.println(mqtt_message);
}


void __sniffer_monitor(uint8_t *buf, uint16_t len) {
  if (buf && len >= 27) {
    byte pkt_type = buf[12];

    // If captured packet is a deauthentication or dissassociaten frame
    if (pkt_type == 0xA0 || pkt_type == 0xC0) {
      ps_client.publish(MQTT_TOPIC_OUTPUT, "ALERT DEAUTH", true);
      Serial.println("Spotted DEAUTH attack!");
    }
  }
}

void __sniffer_asleep(uint8_t *buf, uint16_t len) {
   if (buf && len >= 27)
      nb_packets += 1;
}

void __switch_promiscuous_mode(int mode) {
  if (mode == 1) {

    WiFi.disconnect();

    if (program_state == STATE_ASLEEP) {
      wifi_set_promiscuous_rx_cb(__sniffer_asleep);
    } else if (program_state == STATE_MONITOR_MODE) {
      wifi_set_promiscuous_rx_cb(__sniffer_monitor);
    }

    wifi_promiscuous_enable(1);
    delay(VERY_QUICK_DELAY_TIME);

  } else {

    wifi_promiscuous_enable(0);
    __wifi_local_connect(saved_ssid, saved_pass);
    ps_client.setServer(MQTT_SERVER_URL, MQTT_PORT);
    ps_client.setCallback(__mqtt_read_callback);

    if (ps_client.connect(MQTT_CLIENT_ID, MQTT_USERNAME, MQTT_PASSWORD)) {
      ps_client.subscribe(MQTT_TOPIC_INPUT);
    }
  }

}

/*
 * Main routines for arduino things
 *
 * setup -> constructor, will set up the environment for the esp to do it thing
 * loop -> main execution loop. manages state etc
 */


void setup() {

    // init led
    pinMode(LED, OUTPUT);
    randomSeed(millis());

    // init serial output
    Serial.begin(SERIAL_BAUD);
    while (!Serial) delay(QUICK_DELAY_TIME);

    delay(QUICK_DELAY_TIME);

    Serial.println("waking up.......");
    __wifi_setup_soft_ap();
    __blink_success();
   __net_get_public_ip(net_client, ip_address, 256);
   __switch_promiscuous_mode(1);
}


void loop() {
    Serial.println("[+] Looping...");

    delay(DELAY_TIME * 3);
    __switch_promiscuous_mode(0);
    delay(DELAY_TIME);
    ps_client.loop();
    __switch_promiscuous_mode(1);


    if (program_state == STATE_SOFT_AP_MODE) {
      __wifi_setup_soft_ap();
      goto endloop;
    }

    if (program_state == STATE_ASLEEP) {
      memset(mqtt_msg_to_send, 0, MQTT_MSG_SIZE);

      __switch_promiscuous_mode(0);
      DynamicJsonDocument js = __get_net_information(net_client, ip_address);
      serializeJson(js, mqtt_msg_to_send);
      Serial.printf("[MQTT] sending: %s\n", mqtt_msg_to_send);
      ps_client.publish(MQTT_TOPIC_OUTPUT, mqtt_msg_to_send, true);
      nb_packets = 0;
      __switch_promiscuous_mode(1);
    }

endloop:
    delay(DELAY_TIME);

}
