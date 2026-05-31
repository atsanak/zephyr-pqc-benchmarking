/**
 * @file tee_network_protocol.h
 * @brief TEE Network Orchestration Protocol for PQC Benchmarking
 * 
 * This header defines the protocol for remote orchestration of TEE-enabled
 * PQC benchmarks over constrained networks (CoAP/MQTT).
 * 
 * ARCHITECTURE:
 *   ┌──────────────────────┐
 *   │   ORCHESTRATOR       │  (Edge Gateway / Cloud)
 *   │   - Python script    │
 *   │   - Collects CSV     │
 *   └──────────┬───────────┘
 *              │ CoAP/MQTT
 *   ┌──────────▼───────────┐
 *   │   nRF5340-DK         │
 *   │   - TEE (TF-M)       │
 *   │   - PQC Benchmark    │
 *   │   - Network Stack    │
 *   └──────────────────────┘
 * 
 * PROTOCOL FLOW:
 *   1. DISCOVER  - Orchestrator broadcasts to find TEE-capable devices
 *   2. ANNOUNCE  - Device responds with capabilities
 *   3. ATTEST    - Orchestrator requests TEE attestation
 *   4. ATTEST_RESPONSE - Device provides attestation token
 *   5. RUN_BENCHMARK - Orchestrator triggers benchmark
 *   6. BENCHMARK_RESULT - Device returns CSV data
 * 
 * @version 1.0.0
 * @date 2025-12-05
 * @author Aggelos Tsanaktsidis (Thesis Chapter 7)
 */

#ifndef TEE_NETWORK_PROTOCOL_H
#define TEE_NETWORK_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// PROTOCOL CONSTANTS
// ============================================================================

#define TEE_PROTO_VERSION           0x01
#define TEE_PROTO_MAGIC             0x54454550  // "TEEP" in ASCII

// CoAP resource paths
#define TEE_COAP_PATH_DISCOVER      "/.well-known/tee"
#define TEE_COAP_PATH_ATTEST        "/tee/attest"
#define TEE_COAP_PATH_BENCHMARK     "/tee/benchmark"
#define TEE_COAP_PATH_STATUS        "/tee/status"

// MQTT topics
#define TEE_MQTT_TOPIC_DISCOVER     "pqc/tee/discover"
#define TEE_MQTT_TOPIC_ANNOUNCE     "pqc/tee/announce"
#define TEE_MQTT_TOPIC_ATTEST       "pqc/tee/attest"
#define TEE_MQTT_TOPIC_BENCHMARK    "pqc/tee/benchmark"
#define TEE_MQTT_TOPIC_RESULT       "pqc/tee/result"

// Maximum sizes (constrained device limits)
#define TEE_MAX_DEVICE_ID_LEN       32
#define TEE_MAX_ALGORITHM_NAME      24
#define TEE_MAX_ALGORITHMS          8
#define TEE_NONCE_SIZE              32
#define TEE_ATTESTATION_TOKEN_SIZE  256
#define TEE_MAX_MESSAGE_SIZE        1024

// ============================================================================
// MESSAGE TYPES
// ============================================================================

/**
 * @brief Protocol message types
 */
typedef enum {
    TEE_MSG_DISCOVER        = 0x01,  /**< Broadcast: find TEE devices */
    TEE_MSG_ANNOUNCE        = 0x02,  /**< Response: device capabilities */
    TEE_MSG_ATTEST_REQUEST  = 0x03,  /**< Request: TEE attestation */
    TEE_MSG_ATTEST_RESPONSE = 0x04,  /**< Response: attestation token */
    TEE_MSG_BENCHMARK_START = 0x05,  /**< Command: start benchmark */
    TEE_MSG_BENCHMARK_STOP  = 0x06,  /**< Command: abort benchmark */
    TEE_MSG_BENCHMARK_RESULT= 0x07,  /**< Response: benchmark CSV data */
    TEE_MSG_STATUS_REQUEST  = 0x08,  /**< Request: device status */
    TEE_MSG_STATUS_RESPONSE = 0x09,  /**< Response: device status */
    TEE_MSG_ERROR           = 0xFF   /**< Error response */
} tee_msg_type_t;

/**
 * @brief Error codes
 */
typedef enum {
    TEE_ERR_NONE            = 0x00,
    TEE_ERR_INVALID_MSG     = 0x01,
    TEE_ERR_UNSUPPORTED_ALG = 0x02,
    TEE_ERR_TEE_NOT_READY   = 0x03,
    TEE_ERR_ATTESTATION_FAIL= 0x04,
    TEE_ERR_BENCHMARK_FAIL  = 0x05,
    TEE_ERR_OUT_OF_MEMORY   = 0x06,
    TEE_ERR_BUSY            = 0x07,
    TEE_ERR_TIMEOUT         = 0x08
} tee_error_t;

// ============================================================================
// MESSAGE STRUCTURES (Binary format for constrained networks)
// ============================================================================

/**
 * @brief Common message header (8 bytes)
 */
typedef struct __attribute__((packed)) {
    uint32_t magic;          /**< TEE_PROTO_MAGIC */
    uint8_t  version;        /**< Protocol version */
    uint8_t  msg_type;       /**< tee_msg_type_t */
    uint16_t payload_len;    /**< Payload length in bytes */
} tee_msg_header_t;

/**
 * @brief DISCOVER message (Orchestrator → Broadcast)
 * 
 * Sent by orchestrator to find TEE-capable devices.
 * Payload: just header (no additional data)
 */
typedef struct __attribute__((packed)) {
    tee_msg_header_t header;
    uint8_t capabilities_filter;  /**< 0x01=TEE, 0x02=PQC, 0x03=both */
} tee_msg_discover_t;

/**
 * @brief ANNOUNCE message (Device → Orchestrator)
 * 
 * Device announces its TEE capabilities.
 */
typedef struct __attribute__((packed)) {
    tee_msg_header_t header;
    char     device_id[TEE_MAX_DEVICE_ID_LEN];  /**< Unique device ID */
    uint8_t  tee_mode;           /**< Current TEE mode (tee_mode_t) */
    uint8_t  tee_provider;       /**< TEE provider (tee_provider_t) */
    uint16_t ram_available_kb;   /**< Available RAM for algorithms */
    uint16_t flash_available_kb; /**< Available Flash */
    uint8_t  num_algorithms;     /**< Number of supported algorithms */
    char     algorithms[TEE_MAX_ALGORITHMS][TEE_MAX_ALGORITHM_NAME];
} tee_msg_announce_t;

/**
 * @brief ATTEST_REQUEST message (Orchestrator → Device)
 * 
 * Request TEE attestation with a nonce for freshness.
 */
typedef struct __attribute__((packed)) {
    tee_msg_header_t header;
    uint8_t nonce[TEE_NONCE_SIZE];  /**< Random nonce from orchestrator */
} tee_msg_attest_request_t;

/**
 * @brief ATTEST_RESPONSE message (Device → Orchestrator)
 * 
 * TEE attestation token (platform-specific format).
 * For TF-M: PSA Initial Attestation Token (COSE_Sign1)
 */
typedef struct __attribute__((packed)) {
    tee_msg_header_t header;
    char     device_id[TEE_MAX_DEVICE_ID_LEN];
    uint16_t token_len;
    uint8_t  token[TEE_ATTESTATION_TOKEN_SIZE];  /**< PSA attestation token */
    uint8_t  tee_mode;
    uint8_t  tee_provider;
} tee_msg_attest_response_t;

/**
 * @brief BENCHMARK_START message (Orchestrator → Device)
 * 
 * Command device to run a specific benchmark.
 */
typedef struct __attribute__((packed)) {
    tee_msg_header_t header;
    char     algorithm[TEE_MAX_ALGORITHM_NAME];  /**< e.g., "ml-kem-512" */
    uint16_t iterations;       /**< Number of benchmark iterations */
    uint16_t warmup_iters;     /**< Warmup iterations */
    uint8_t  tee_phase;        /**< 0=none, 1=RNG-only, 2=full */
    uint8_t  flags;            /**< Reserved */
} tee_msg_benchmark_start_t;

/**
 * @brief BENCHMARK_RESULT message (Device → Orchestrator)
 * 
 * Benchmark results in compact binary format.
 * Includes network overhead metrics.
 */
typedef struct __attribute__((packed)) {
    tee_msg_header_t header;
    char     device_id[TEE_MAX_DEVICE_ID_LEN];
    char     algorithm[TEE_MAX_ALGORITHM_NAME];
    
    // Timing metrics (cycles)
    uint64_t keygen_cycles;
    uint64_t encaps_cycles;     // or sign_cycles for DSA
    uint64_t decaps_cycles;     // or verify_cycles for DSA
    
    // Statistical metrics
    uint64_t keygen_min;
    uint64_t keygen_max;
    uint64_t keygen_avg;
    
    // Memory metrics
    uint32_t stack_usage;
    uint32_t heap_usage;
    uint32_t code_size;
    
    // Key/signature sizes
    uint16_t pk_size;
    uint16_t sk_size;
    uint16_t ct_size;           // or sig_size for DSA
    uint16_t ss_size;           // shared secret (KEM only)
    
    // TEE metrics
    uint8_t  tee_mode;
    uint8_t  tee_provider;
    uint64_t tee_overhead_cycles;
    uint64_t tee_rng_overhead_cycles;
    uint32_t tee_rng_calls;
    
    // Network metrics (NEW for orchestration)
    uint32_t e2e_latency_ms;    /**< End-to-end benchmark time */
    uint16_t tx_packets;        /**< Packets transmitted */
    uint16_t rx_packets;        /**< Packets received */
    uint16_t tx_bytes;          /**< Bytes transmitted */
    uint16_t rx_bytes;          /**< Bytes received */
    
    // Status
    uint8_t  error_code;        /**< 0 = success */
    uint16_t iterations_completed;
} tee_msg_benchmark_result_t;

/**
 * @brief STATUS_RESPONSE message (Device → Orchestrator)
 * 
 * Current device status for monitoring.
 */
typedef struct __attribute__((packed)) {
    tee_msg_header_t header;
    char     device_id[TEE_MAX_DEVICE_ID_LEN];
    uint8_t  tee_mode;
    uint8_t  tee_provider;
    uint8_t  tee_health;        /**< 0=ok, 1=warning, 2=error */
    uint16_t ram_free_kb;
    uint16_t uptime_seconds;
    uint32_t benchmarks_completed;
    uint32_t last_benchmark_cycles;
    uint8_t  is_busy;           /**< 1 if benchmark in progress */
} tee_msg_status_response_t;

/**
 * @brief ERROR message
 */
typedef struct __attribute__((packed)) {
    tee_msg_header_t header;
    char     device_id[TEE_MAX_DEVICE_ID_LEN];
    uint8_t  error_code;        /**< tee_error_t */
    uint8_t  original_msg_type; /**< Message that caused error */
    char     error_msg[64];     /**< Human-readable error */
} tee_msg_error_t;

// ============================================================================
// PROTOCOL API
// ============================================================================

/**
 * @brief Initialize protocol handler
 * @return 0 on success
 */
int tee_proto_init(void);

/**
 * @brief Process incoming message
 * @param data Raw message bytes
 * @param len Message length
 * @param response Output buffer for response
 * @param response_len Output: response length
 * @return 0 on success, negative on error
 */
int tee_proto_handle_message(const uint8_t *data, size_t len,
                              uint8_t *response, size_t *response_len);

/**
 * @brief Create ANNOUNCE message
 * @param msg Output message buffer
 * @return Message length
 */
size_t tee_proto_create_announce(tee_msg_announce_t *msg);

/**
 * @brief Create ATTEST_RESPONSE message
 * @param msg Output message buffer
 * @param nonce Nonce from request
 * @return Message length, negative on error
 */
int tee_proto_create_attest_response(tee_msg_attest_response_t *msg,
                                      const uint8_t *nonce);

/**
 * @brief Create BENCHMARK_RESULT message
 * @param msg Output message buffer
 * @param algorithm Algorithm name
 * @return Message length
 */
size_t tee_proto_create_benchmark_result(tee_msg_benchmark_result_t *msg,
                                          const char *algorithm);

/**
 * @brief Validate message header
 * @param header Message header to validate
 * @return true if valid
 */
static inline bool tee_proto_validate_header(const tee_msg_header_t *header) {
    return header && 
           header->magic == TEE_PROTO_MAGIC &&
           header->version == TEE_PROTO_VERSION;
}

/**
 * @brief Get message type name (for debugging)
 */
const char* tee_proto_msg_type_name(tee_msg_type_t type);

/**
 * @brief Get error name (for debugging)
 */
const char* tee_proto_error_name(tee_error_t error);

// ============================================================================
// JSON HELPERS (for MQTT/debugging)
// ============================================================================

/**
 * @brief Serialize ANNOUNCE to JSON
 * @param msg Message to serialize
 * @param buf Output buffer
 * @param buf_len Buffer size
 * @return JSON string length
 */
int tee_proto_announce_to_json(const tee_msg_announce_t *msg,
                                char *buf, size_t buf_len);

/**
 * @brief Serialize BENCHMARK_RESULT to JSON
 * @param msg Message to serialize
 * @param buf Output buffer
 * @param buf_len Buffer size
 * @return JSON string length
 */
int tee_proto_result_to_json(const tee_msg_benchmark_result_t *msg,
                              char *buf, size_t buf_len);

/**
 * @brief Serialize BENCHMARK_RESULT to CSV line
 * @param msg Message to serialize
 * @param buf Output buffer
 * @param buf_len Buffer size
 * @return CSV line length
 */
int tee_proto_result_to_csv(const tee_msg_benchmark_result_t *msg,
                             char *buf, size_t buf_len);

#ifdef __cplusplus
}
#endif

#endif /* TEE_NETWORK_PROTOCOL_H */
