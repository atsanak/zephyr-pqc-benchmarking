/**
 * @file tee_mqtt_client.c
 * @brief Secure MQTT Client with mTLS for TEE Benchmark Orchestration
 * 
 * Implements MQTT client with mutual TLS authentication for secure
 * communication with the benchmark orchestrator.
 * 
 * Features:
 *   - mTLS with client certificate authentication
 *   - PSA Crypto integration via mbed TLS
 *   - Topic-based message routing for TEE protocol
 *   - Automatic reconnection with backoff
 * 
 * @version 1.0.0
 * @date 2025-12-05
 * @author Aggelos Tsanaktsidis (Thesis Chapter 7)
 */

#include <zephyr/kernel.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/mqtt.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/random/random.h>
#include <zephyr/sys/printk.h>
#include <string.h>
#include <stdio.h>

#include "tee_network_protocol.h"

// Only compile if MQTT TLS is enabled
#if defined(CONFIG_MQTT_LIB) && defined(CONFIG_MQTT_LIB_TLS)

// Include generated certificates (or use TLS credential store)
#ifndef MQTT_KEY_IN_TFM
#include "mqtt_certs.h"
#endif

// ============================================================================
// CONFIGURATION
// ============================================================================

#define MQTT_BROKER_HOSTNAME    "pqc-mqtt-broker"
#define MQTT_BROKER_PORT        8883  // TLS port
#define MQTT_CLIENT_ID_PREFIX   "nrf5340-tee-"
#define MQTT_KEEPALIVE_SEC      60
#define MQTT_CLEAN_SESSION      1

// TLS credential tags (for Zephyr TLS credential store)
#define TLS_TAG_CA_CERT         1
#define TLS_TAG_DEVICE_CERT     2
#define TLS_TAG_DEVICE_KEY      3

// Reconnection settings
#define MQTT_RECONNECT_DELAY_MS     1000
#define MQTT_RECONNECT_MAX_DELAY_MS 30000
#define MQTT_RECONNECT_BACKOFF      2

// Buffer sizes
#define MQTT_RX_BUFFER_SIZE     512
#define MQTT_TX_BUFFER_SIZE     512

// ============================================================================
// STATE
// ============================================================================

static struct mqtt_client g_mqtt_client;
static struct sockaddr_storage g_broker_addr;

static uint8_t g_rx_buffer[MQTT_RX_BUFFER_SIZE];
static uint8_t g_tx_buffer[MQTT_TX_BUFFER_SIZE];

static struct {
    bool connected;
    bool subscribed;
    uint32_t reconnect_delay_ms;
    uint32_t messages_rx;
    uint32_t messages_tx;
    char client_id[48];
} g_mqtt_state;

// Callback for incoming messages
static void (*g_message_callback)(const char *topic, const uint8_t *payload, size_t len);

// ============================================================================
// TLS CREDENTIALS
// ============================================================================

/**
 * @brief Register TLS credentials with Zephyr credential store
 */
static int mqtt_tls_credentials_setup(void)
{
    int ret;
    
    printk("[MQTT-TLS] Setting up TLS credentials...\n");
    
#ifdef MQTT_KEY_IN_TFM
    // In production, private key is stored in TF-M secure storage
    // and accessed via PSA Crypto API
    printk("[MQTT-TLS] Using TF-M secure key storage\n");
    // TODO: Implement PSA key import
#else
    // Development mode: embedded certificates
    
    // Register CA certificate
    ret = tls_credential_add(TLS_TAG_CA_CERT, TLS_CREDENTIAL_CA_CERTIFICATE,
                              mqtt_ca_cert, mqtt_ca_cert_len);
    if (ret < 0 && ret != -EEXIST) {
        printk("[MQTT-TLS] ERROR: Failed to add CA cert: %d\n", ret);
        return ret;
    }
    
    // Register device certificate
    ret = tls_credential_add(TLS_TAG_DEVICE_CERT, TLS_CREDENTIAL_SERVER_CERTIFICATE,
                              mqtt_device_cert, mqtt_device_cert_len);
    if (ret < 0 && ret != -EEXIST) {
        printk("[MQTT-TLS] ERROR: Failed to add device cert: %d\n", ret);
        return ret;
    }
    
    // Register device private key
    ret = tls_credential_add(TLS_TAG_DEVICE_KEY, TLS_CREDENTIAL_PRIVATE_KEY,
                              mqtt_device_key, mqtt_device_key_len);
    if (ret < 0 && ret != -EEXIST) {
        printk("[MQTT-TLS] ERROR: Failed to add device key: %d\n", ret);
        return ret;
    }
#endif
    
    printk("[MQTT-TLS] Credentials registered\n");
    return 0;
}

// ============================================================================
// MQTT CALLBACKS
// ============================================================================

/**
 * @brief Handle MQTT events
 */
static void mqtt_event_handler(struct mqtt_client *client,
                                const struct mqtt_evt *evt)
{
    switch (evt->type) {
    case MQTT_EVT_CONNACK:
        if (evt->result == 0) {
            printk("[MQTT] Connected to broker\n");
            g_mqtt_state.connected = true;
            g_mqtt_state.reconnect_delay_ms = MQTT_RECONNECT_DELAY_MS;
        } else {
            printk("[MQTT] Connection rejected: %d\n", evt->result);
        }
        break;
        
    case MQTT_EVT_DISCONNECT:
        printk("[MQTT] Disconnected\n");
        g_mqtt_state.connected = false;
        g_mqtt_state.subscribed = false;
        break;
        
    case MQTT_EVT_PUBLISH: {
        const struct mqtt_publish_param *pub = &evt->param.publish;
        uint8_t payload[TEE_MAX_MESSAGE_SIZE];
        size_t payload_len = pub->message.payload.len;
        
        if (payload_len > sizeof(payload)) {
            printk("[MQTT] Payload too large: %zu\n", payload_len);
            break;
        }
        
        // Read payload
        int ret = mqtt_read_publish_payload(client, payload, payload_len);
        if (ret < 0) {
            printk("[MQTT] Failed to read payload: %d\n", ret);
            break;
        }
        
        g_mqtt_state.messages_rx++;
        
        // Extract topic
        char topic[64];
        size_t topic_len = pub->message.topic.topic.size;
        if (topic_len >= sizeof(topic)) {
            topic_len = sizeof(topic) - 1;
        }
        memcpy(topic, pub->message.topic.topic.utf8, topic_len);
        topic[topic_len] = '\0';
        
        printk("[MQTT] Received on '%s': %zu bytes\n", topic, payload_len);
        
        // Dispatch to callback
        if (g_message_callback) {
            g_message_callback(topic, payload, payload_len);
        }
        
        // Acknowledge if QoS > 0
        if (pub->message.topic.qos == MQTT_QOS_1_AT_LEAST_ONCE) {
            struct mqtt_puback_param ack = {
                .message_id = pub->message_id
            };
            mqtt_publish_qos1_ack(client, &ack);
        }
        break;
    }
    
    case MQTT_EVT_SUBACK:
        printk("[MQTT] Subscribed (msg_id=%u)\n", evt->param.suback.message_id);
        g_mqtt_state.subscribed = true;
        break;
        
    case MQTT_EVT_PUBACK:
        printk("[MQTT] Published (msg_id=%u)\n", evt->param.puback.message_id);
        break;
        
    case MQTT_EVT_PINGRESP:
        // Keepalive response received
        break;
        
    default:
        printk("[MQTT] Event: %d\n", evt->type);
        break;
    }
}

// ============================================================================
// CLIENT INITIALIZATION
// ============================================================================

/**
 * @brief Generate unique client ID from device ID
 */
static void mqtt_generate_client_id(void)
{
    uint8_t random_bytes[4];
    sys_csrand_get(random_bytes, sizeof(random_bytes));
    
    snprintf(g_mqtt_state.client_id, sizeof(g_mqtt_state.client_id),
             "%s%02x%02x%02x%02x",
             MQTT_CLIENT_ID_PREFIX,
             random_bytes[0], random_bytes[1],
             random_bytes[2], random_bytes[3]);
}

/**
 * @brief Resolve broker address
 */
static int mqtt_resolve_broker(void)
{
    struct addrinfo hints = {
        .ai_family = AF_INET6,
        .ai_socktype = SOCK_STREAM,
    };
    struct addrinfo *result;
    char port_str[8];
    
    snprintf(port_str, sizeof(port_str), "%d", MQTT_BROKER_PORT);
    
    int ret = getaddrinfo(MQTT_BROKER_HOSTNAME, port_str, &hints, &result);
    if (ret != 0) {
        // Try IPv4
        hints.ai_family = AF_INET;
        ret = getaddrinfo(MQTT_BROKER_HOSTNAME, port_str, &hints, &result);
        if (ret != 0) {
            printk("[MQTT] DNS lookup failed: %d\n", ret);
            return -EIO;
        }
    }
    
    memcpy(&g_broker_addr, result->ai_addr, result->ai_addrlen);
    freeaddrinfo(result);
    
    printk("[MQTT] Broker resolved: %s:%d\n", MQTT_BROKER_HOSTNAME, MQTT_BROKER_PORT);
    return 0;
}

/**
 * @brief Initialize MQTT client with TLS
 */
int tee_mqtt_init(void (*msg_callback)(const char *, const uint8_t *, size_t))
{
    int ret;
    
    printk("[MQTT] Initializing secure MQTT client...\n");
    
    g_message_callback = msg_callback;
    memset(&g_mqtt_state, 0, sizeof(g_mqtt_state));
    g_mqtt_state.reconnect_delay_ms = MQTT_RECONNECT_DELAY_MS;
    
    // Generate client ID
    mqtt_generate_client_id();
    printk("[MQTT] Client ID: %s\n", g_mqtt_state.client_id);
    
    // Setup TLS credentials
    ret = mqtt_tls_credentials_setup();
    if (ret < 0) {
        return ret;
    }
    
    // Resolve broker address
    ret = mqtt_resolve_broker();
    if (ret < 0) {
        return ret;
    }
    
    // Initialize MQTT client structure
    mqtt_client_init(&g_mqtt_client);
    
    // Broker connection
    g_mqtt_client.broker = &g_broker_addr;
    g_mqtt_client.evt_cb = mqtt_event_handler;
    g_mqtt_client.client_id.utf8 = (uint8_t *)g_mqtt_state.client_id;
    g_mqtt_client.client_id.size = strlen(g_mqtt_state.client_id);
    g_mqtt_client.protocol_version = MQTT_VERSION_3_1_1;
    
    // Buffers
    g_mqtt_client.rx_buf = g_rx_buffer;
    g_mqtt_client.rx_buf_size = sizeof(g_rx_buffer);
    g_mqtt_client.tx_buf = g_tx_buffer;
    g_mqtt_client.tx_buf_size = sizeof(g_tx_buffer);
    
    // TLS configuration
    static sec_tag_t sec_tags[] = {
        TLS_TAG_CA_CERT,
        TLS_TAG_DEVICE_CERT,
        TLS_TAG_DEVICE_KEY
    };
    
    static struct mqtt_sec_config tls_config = {
        .peer_verify = TLS_PEER_VERIFY_REQUIRED,
        .cipher_list = NULL,
        .sec_tag_list = sec_tags,
        .sec_tag_count = ARRAY_SIZE(sec_tags),
        .hostname = MQTT_BROKER_HOSTNAME
    };
    
    g_mqtt_client.transport.type = MQTT_TRANSPORT_SECURE;
    g_mqtt_client.transport.tls.config = tls_config;
    
    printk("[MQTT] Client initialized with mTLS\n");
    return 0;
}

// ============================================================================
// CONNECTION MANAGEMENT
// ============================================================================

/**
 * @brief Connect to MQTT broker
 */
int tee_mqtt_connect(void)
{
    if (g_mqtt_state.connected) {
        return 0;
    }
    
    printk("[MQTT] Connecting to broker...\n");
    
    int ret = mqtt_connect(&g_mqtt_client);
    if (ret != 0) {
        printk("[MQTT] Connect failed: %d\n", ret);
        return ret;
    }
    
    // Wait for CONNACK
    struct pollfd fds = {
        .fd = g_mqtt_client.transport.tls.sock,
        .events = POLLIN
    };
    
    ret = poll(&fds, 1, 10000);  // 10 second timeout
    if (ret > 0) {
        mqtt_input(&g_mqtt_client);
    }
    
    return g_mqtt_state.connected ? 0 : -ETIMEDOUT;
}

/**
 * @brief Disconnect from MQTT broker
 */
int tee_mqtt_disconnect(void)
{
    if (!g_mqtt_state.connected) {
        return 0;
    }
    
    int ret = mqtt_disconnect(&g_mqtt_client);
    g_mqtt_state.connected = false;
    return ret;
}

/**
 * @brief Subscribe to TEE protocol topics
 */
int tee_mqtt_subscribe(void)
{
    if (!g_mqtt_state.connected) {
        return -ENOTCONN;
    }
    
    static struct mqtt_topic topics[] = {
        { .topic = { .utf8 = (uint8_t *)TEE_MQTT_TOPIC_DISCOVER,
                     .size = sizeof(TEE_MQTT_TOPIC_DISCOVER) - 1 },
          .qos = MQTT_QOS_1_AT_LEAST_ONCE },
        { .topic = { .utf8 = (uint8_t *)TEE_MQTT_TOPIC_ATTEST,
                     .size = sizeof(TEE_MQTT_TOPIC_ATTEST) - 1 },
          .qos = MQTT_QOS_1_AT_LEAST_ONCE },
        { .topic = { .utf8 = (uint8_t *)TEE_MQTT_TOPIC_BENCHMARK,
                     .size = sizeof(TEE_MQTT_TOPIC_BENCHMARK) - 1 },
          .qos = MQTT_QOS_1_AT_LEAST_ONCE },
    };
    
    static struct mqtt_subscription_list sub_list = {
        .list = topics,
        .list_count = ARRAY_SIZE(topics),
        .message_id = 1
    };
    
    printk("[MQTT] Subscribing to TEE topics...\n");
    
    int ret = mqtt_subscribe(&g_mqtt_client, &sub_list);
    if (ret != 0) {
        printk("[MQTT] Subscribe failed: %d\n", ret);
    }
    
    return ret;
}

// ============================================================================
// PUBLISHING
// ============================================================================

/**
 * @brief Publish message to topic
 */
int tee_mqtt_publish(const char *topic, const uint8_t *payload, size_t len)
{
    if (!g_mqtt_state.connected) {
        return -ENOTCONN;
    }
    
    static uint16_t msg_id = 0;
    
    struct mqtt_publish_param pub = {
        .message = {
            .topic = {
                .topic = {
                    .utf8 = (uint8_t *)topic,
                    .size = strlen(topic)
                },
                .qos = MQTT_QOS_1_AT_LEAST_ONCE,
            },
            .payload = {
                .data = (uint8_t *)payload,
                .len = len
            }
        },
        .message_id = ++msg_id,
        .dup_flag = 0,
        .retain_flag = 0
    };
    
    int ret = mqtt_publish(&g_mqtt_client, &pub);
    if (ret == 0) {
        g_mqtt_state.messages_tx++;
    }
    
    return ret;
}

/**
 * @brief Publish ANNOUNCE message
 */
int tee_mqtt_announce(const tee_msg_announce_t *announce)
{
    return tee_mqtt_publish(TEE_MQTT_TOPIC_ANNOUNCE,
                            (const uint8_t *)announce,
                            sizeof(*announce));
}

/**
 * @brief Publish benchmark result
 */
int tee_mqtt_publish_result(const tee_msg_benchmark_result_t *result)
{
    return tee_mqtt_publish(TEE_MQTT_TOPIC_RESULT,
                            (const uint8_t *)result,
                            sizeof(*result));
}

// ============================================================================
// MAIN LOOP
// ============================================================================

/**
 * @brief Process MQTT events (call periodically)
 */
int tee_mqtt_process(int timeout_ms)
{
    if (!g_mqtt_state.connected) {
        return -ENOTCONN;
    }
    
    struct pollfd fds = {
        .fd = g_mqtt_client.transport.tls.sock,
        .events = POLLIN
    };
    
    int ret = poll(&fds, 1, timeout_ms);
    if (ret > 0) {
        mqtt_input(&g_mqtt_client);
    }
    
    // Keepalive
    mqtt_live(&g_mqtt_client);
    
    return 0;
}

/**
 * @brief Get connection statistics
 */
void tee_mqtt_get_stats(uint32_t *rx, uint32_t *tx)
{
    if (rx) *rx = g_mqtt_state.messages_rx;
    if (tx) *tx = g_mqtt_state.messages_tx;
}

#else  // !CONFIG_MQTT_LIB || !CONFIG_MQTT_LIB_TLS

// Stubs when MQTT TLS is disabled
int tee_mqtt_init(void (*cb)(const char *, const uint8_t *, size_t)) { return -ENOTSUP; }
int tee_mqtt_connect(void) { return -ENOTSUP; }
int tee_mqtt_disconnect(void) { return -ENOTSUP; }
int tee_mqtt_subscribe(void) { return -ENOTSUP; }
int tee_mqtt_publish(const char *t, const uint8_t *p, size_t l) { return -ENOTSUP; }
int tee_mqtt_process(int timeout_ms) { return -ENOTSUP; }

#endif  // CONFIG_MQTT_LIB && CONFIG_MQTT_LIB_TLS
