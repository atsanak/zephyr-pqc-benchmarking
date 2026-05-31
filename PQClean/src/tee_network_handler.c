/**
 * @file tee_network_handler.c
 * @brief TEE Network Orchestration Protocol Handler
 * 
 * Implements the network message handler for remote TEE benchmark orchestration.
 * Supports CoAP server for receiving commands and sending results.
 * 
 * @version 1.0.0
 * @date 2025-12-05
 * @author Aggelos Tsanaktsidis (Thesis Chapter 7)
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/coap.h>
#include <zephyr/random/random.h>
#include <string.h>
#include <stdio.h>

#include "tee_network_protocol.h"
#include "tee_abstraction.h"

// Only compile if networking is enabled
#if defined(CONFIG_NETWORKING) && defined(CONFIG_COAP)

// ============================================================================
// CONFIGURATION
// ============================================================================

#define COAP_PORT           5683
#define COAP_MAX_MSG_SIZE   512
#define DEVICE_ID_PREFIX    "nrf5340-tee-"

// ============================================================================
// STATE
// ============================================================================

static struct {
    bool initialized;
    char device_id[TEE_MAX_DEVICE_ID_LEN];
    tee_context_t *tee_ctx;
    
    // Current benchmark state
    bool benchmark_running;
    char current_algorithm[TEE_MAX_ALGORITHM_NAME];
    uint16_t current_iterations;
    uint64_t benchmark_start_time;
    
    // Network statistics
    uint32_t tx_packets;
    uint32_t rx_packets;
    uint32_t tx_bytes;
    uint32_t rx_bytes;
    
    // Last benchmark result (for async retrieval)
    tee_msg_benchmark_result_t last_result;
    bool result_available;
} g_handler_state;

// Supported algorithms (must match CMake build configuration)
static const char* g_supported_algorithms[] = {
#if defined(ENABLE_ML_KEM_512)
    "ml-kem-512",
#endif
#if defined(ENABLE_ML_KEM_768)
    "ml-kem-768",
#endif
#if defined(ENABLE_ML_KEM_1024)
    "ml-kem-1024",
#endif
#if defined(ENABLE_ML_DSA_44)
    "ml-dsa-44",
#endif
#if defined(ENABLE_ML_DSA_65)
    "ml-dsa-65",
#endif
#if defined(ENABLE_ML_DSA_87)
    "ml-dsa-87",
#endif
#if defined(ENABLE_FALCON_512)
    "falcon-512",
#endif
#if defined(ENABLE_FALCON_1024)
    "falcon-1024",
#endif
    NULL  // Sentinel
};

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

static void generate_device_id(void) {
    uint8_t random_bytes[4];
    sys_csrand_get(random_bytes, sizeof(random_bytes));
    
    snprintf(g_handler_state.device_id, TEE_MAX_DEVICE_ID_LEN,
             "%s%02x%02x%02x%02x",
             DEVICE_ID_PREFIX,
             random_bytes[0], random_bytes[1],
             random_bytes[2], random_bytes[3]);
}

static int count_supported_algorithms(void) {
    int count = 0;
    for (int i = 0; g_supported_algorithms[i] != NULL; i++) {
        count++;
    }
    return count;
}

static bool is_algorithm_supported(const char *algorithm) {
    for (int i = 0; g_supported_algorithms[i] != NULL; i++) {
        if (strcmp(g_supported_algorithms[i], algorithm) == 0) {
            return true;
        }
    }
    return false;
}

// ============================================================================
// MESSAGE CREATION
// ============================================================================

size_t tee_proto_create_announce(tee_msg_announce_t *msg) {
    if (!msg) return 0;
    
    memset(msg, 0, sizeof(*msg));
    
    // Header
    msg->header.magic = TEE_PROTO_MAGIC;
    msg->header.version = TEE_PROTO_VERSION;
    msg->header.msg_type = TEE_MSG_ANNOUNCE;
    msg->header.payload_len = sizeof(*msg) - sizeof(tee_msg_header_t);
    
    // Device info
    strncpy(msg->device_id, g_handler_state.device_id, TEE_MAX_DEVICE_ID_LEN - 1);
    
    // TEE info
    if (g_handler_state.tee_ctx) {
        msg->tee_mode = g_handler_state.tee_ctx->mode;
        msg->tee_provider = g_handler_state.tee_ctx->provider;
    } else {
        msg->tee_mode = TEE_MODE_NONE;
        msg->tee_provider = TEE_PROVIDER_NONE;
    }
    
    // Memory info (approximate available after fixed overhead)
    msg->ram_available_kb = 314;  // ~314KB available with network stack
    msg->flash_available_kb = 768;
    
    // Supported algorithms
    msg->num_algorithms = 0;
    for (int i = 0; g_supported_algorithms[i] != NULL && i < TEE_MAX_ALGORITHMS; i++) {
        strncpy(msg->algorithms[i], g_supported_algorithms[i], TEE_MAX_ALGORITHM_NAME - 1);
        msg->num_algorithms++;
    }
    
    return sizeof(*msg);
}

int tee_proto_create_attest_response(tee_msg_attest_response_t *msg,
                                      const uint8_t *nonce) {
    if (!msg || !nonce) return -1;
    
    memset(msg, 0, sizeof(*msg));
    
    // Header
    msg->header.magic = TEE_PROTO_MAGIC;
    msg->header.version = TEE_PROTO_VERSION;
    msg->header.msg_type = TEE_MSG_ATTEST_RESPONSE;
    msg->header.payload_len = sizeof(*msg) - sizeof(tee_msg_header_t);
    
    // Device info
    strncpy(msg->device_id, g_handler_state.device_id, TEE_MAX_DEVICE_ID_LEN - 1);
    
    // TEE info
    if (g_handler_state.tee_ctx) {
        msg->tee_mode = g_handler_state.tee_ctx->mode;
        msg->tee_provider = g_handler_state.tee_ctx->provider;
    }
    
    // Attestation token
    // In real implementation, this would call psa_initial_attest_get_token()
    // For now, create a placeholder token
#if defined(CONFIG_BUILD_WITH_TFM) && defined(CONFIG_PSA_INITIAL_ATTESTATION)
    psa_status_t status;
    size_t token_size = 0;
    
    status = psa_initial_attest_get_token(
        nonce, TEE_NONCE_SIZE,
        msg->token, TEE_ATTESTATION_TOKEN_SIZE,
        &token_size
    );
    
    if (status == PSA_SUCCESS) {
        msg->token_len = token_size;
    } else {
        printk("WARNING: PSA attestation failed: %d\n", (int)status);
        msg->token_len = 0;
    }
#else
    // Placeholder: echo nonce + device ID hash
    memcpy(msg->token, nonce, TEE_NONCE_SIZE);
    msg->token[TEE_NONCE_SIZE] = msg->tee_mode;
    msg->token[TEE_NONCE_SIZE + 1] = msg->tee_provider;
    msg->token_len = TEE_NONCE_SIZE + 2;
    printk("NOTE: Using placeholder attestation (TF-M attestation not enabled)\n");
#endif
    
    return sizeof(*msg);
}

size_t tee_proto_create_benchmark_result(tee_msg_benchmark_result_t *msg,
                                          const char *algorithm) {
    if (!msg) return 0;
    
    memset(msg, 0, sizeof(*msg));
    
    // Header
    msg->header.magic = TEE_PROTO_MAGIC;
    msg->header.version = TEE_PROTO_VERSION;
    msg->header.msg_type = TEE_MSG_BENCHMARK_RESULT;
    msg->header.payload_len = sizeof(*msg) - sizeof(tee_msg_header_t);
    
    // Copy from last result
    *msg = g_handler_state.last_result;
    
    // Update header (was zeroed in copy)
    msg->header.magic = TEE_PROTO_MAGIC;
    msg->header.version = TEE_PROTO_VERSION;
    msg->header.msg_type = TEE_MSG_BENCHMARK_RESULT;
    msg->header.payload_len = sizeof(*msg) - sizeof(tee_msg_header_t);
    
    // Network metrics
    msg->tx_packets = g_handler_state.tx_packets;
    msg->rx_packets = g_handler_state.rx_packets;
    msg->tx_bytes = g_handler_state.tx_bytes;
    msg->rx_bytes = g_handler_state.rx_bytes;
    
    return sizeof(*msg);
}

// ============================================================================
// MESSAGE HANDLING
// ============================================================================

static int handle_discover(const tee_msg_discover_t *req,
                            uint8_t *response, size_t *response_len) {
    printk("NET: Received DISCOVER request\n");
    
    tee_msg_announce_t *announce = (tee_msg_announce_t *)response;
    *response_len = tee_proto_create_announce(announce);
    
    g_handler_state.tx_packets++;
    g_handler_state.tx_bytes += *response_len;
    
    printk("NET: Sending ANNOUNCE (device=%s, tee_mode=%d, algos=%d)\n",
           announce->device_id, announce->tee_mode, announce->num_algorithms);
    
    return 0;
}

static int handle_attest_request(const tee_msg_attest_request_t *req,
                                  uint8_t *response, size_t *response_len) {
    printk("NET: Received ATTEST request\n");
    
    tee_msg_attest_response_t *attest = (tee_msg_attest_response_t *)response;
    int ret = tee_proto_create_attest_response(attest, req->nonce);
    
    if (ret < 0) {
        // Send error
        tee_msg_error_t *err = (tee_msg_error_t *)response;
        memset(err, 0, sizeof(*err));
        err->header.magic = TEE_PROTO_MAGIC;
        err->header.version = TEE_PROTO_VERSION;
        err->header.msg_type = TEE_MSG_ERROR;
        err->error_code = TEE_ERR_ATTESTATION_FAIL;
        strncpy(err->error_msg, "Attestation failed", 63);
        *response_len = sizeof(*err);
        return -1;
    }
    
    *response_len = ret;
    g_handler_state.tx_packets++;
    g_handler_state.tx_bytes += *response_len;
    
    printk("NET: Sending ATTEST_RESPONSE (token_len=%d)\n", attest->token_len);
    
    return 0;
}

static int handle_benchmark_start(const tee_msg_benchmark_start_t *req,
                                   uint8_t *response, size_t *response_len) {
    printk("NET: Received BENCHMARK_START (algo=%s, iters=%d, phase=%d)\n",
           req->algorithm, req->iterations, req->tee_phase);
    
    // Check if already running
    if (g_handler_state.benchmark_running) {
        tee_msg_error_t *err = (tee_msg_error_t *)response;
        memset(err, 0, sizeof(*err));
        err->header.magic = TEE_PROTO_MAGIC;
        err->header.version = TEE_PROTO_VERSION;
        err->header.msg_type = TEE_MSG_ERROR;
        err->error_code = TEE_ERR_BUSY;
        strncpy(err->error_msg, "Benchmark already in progress", 63);
        *response_len = sizeof(*err);
        return -1;
    }
    
    // Check algorithm support
    if (!is_algorithm_supported(req->algorithm)) {
        tee_msg_error_t *err = (tee_msg_error_t *)response;
        memset(err, 0, sizeof(*err));
        err->header.magic = TEE_PROTO_MAGIC;
        err->header.version = TEE_PROTO_VERSION;
        err->header.msg_type = TEE_MSG_ERROR;
        err->error_code = TEE_ERR_UNSUPPORTED_ALG;
        snprintf(err->error_msg, 63, "Algorithm not supported: %s", req->algorithm);
        *response_len = sizeof(*err);
        return -1;
    }
    
    // Start benchmark (will run asynchronously)
    g_handler_state.benchmark_running = true;
    strncpy(g_handler_state.current_algorithm, req->algorithm, TEE_MAX_ALGORITHM_NAME - 1);
    g_handler_state.current_iterations = req->iterations;
    g_handler_state.benchmark_start_time = k_uptime_get();
    g_handler_state.result_available = false;
    
    // Send acknowledgment (actual result will come later via BENCHMARK_RESULT)
    tee_msg_status_response_t *status = (tee_msg_status_response_t *)response;
    memset(status, 0, sizeof(*status));
    status->header.magic = TEE_PROTO_MAGIC;
    status->header.version = TEE_PROTO_VERSION;
    status->header.msg_type = TEE_MSG_STATUS_RESPONSE;
    strncpy(status->device_id, g_handler_state.device_id, TEE_MAX_DEVICE_ID_LEN - 1);
    status->is_busy = 1;
    *response_len = sizeof(*status);
    
    g_handler_state.tx_packets++;
    g_handler_state.tx_bytes += *response_len;
    
    printk("NET: Benchmark started, will send result when complete\n");
    
    // NOTE: Actual benchmark execution happens in main loop
    // This handler just sets the flag
    
    return 0;
}

static int handle_status_request(uint8_t *response, size_t *response_len) {
    printk("NET: Received STATUS request\n");
    
    tee_msg_status_response_t *status = (tee_msg_status_response_t *)response;
    memset(status, 0, sizeof(*status));
    
    status->header.magic = TEE_PROTO_MAGIC;
    status->header.version = TEE_PROTO_VERSION;
    status->header.msg_type = TEE_MSG_STATUS_RESPONSE;
    status->header.payload_len = sizeof(*status) - sizeof(tee_msg_header_t);
    
    strncpy(status->device_id, g_handler_state.device_id, TEE_MAX_DEVICE_ID_LEN - 1);
    
    if (g_handler_state.tee_ctx) {
        status->tee_mode = g_handler_state.tee_ctx->mode;
        status->tee_provider = g_handler_state.tee_ctx->provider;
    }
    
    status->tee_health = 0;  // OK
    status->ram_free_kb = 200;  // Approximate
    status->uptime_seconds = k_uptime_get() / 1000;
    status->is_busy = g_handler_state.benchmark_running ? 1 : 0;
    
    *response_len = sizeof(*status);
    
    g_handler_state.tx_packets++;
    g_handler_state.tx_bytes += *response_len;
    
    return 0;
}

int tee_proto_handle_message(const uint8_t *data, size_t len,
                              uint8_t *response, size_t *response_len) {
    if (!data || len < sizeof(tee_msg_header_t) || !response || !response_len) {
        return -1;
    }
    
    const tee_msg_header_t *header = (const tee_msg_header_t *)data;
    
    // Validate header
    if (!tee_proto_validate_header(header)) {
        printk("NET: Invalid message header\n");
        return -1;
    }
    
    g_handler_state.rx_packets++;
    g_handler_state.rx_bytes += len;
    
    // Dispatch by message type
    switch (header->msg_type) {
        case TEE_MSG_DISCOVER:
            return handle_discover((const tee_msg_discover_t *)data,
                                   response, response_len);
        
        case TEE_MSG_ATTEST_REQUEST:
            return handle_attest_request((const tee_msg_attest_request_t *)data,
                                          response, response_len);
        
        case TEE_MSG_BENCHMARK_START:
            return handle_benchmark_start((const tee_msg_benchmark_start_t *)data,
                                           response, response_len);
        
        case TEE_MSG_STATUS_REQUEST:
            return handle_status_request(response, response_len);
        
        default:
            printk("NET: Unknown message type: 0x%02x\n", header->msg_type);
            return -1;
    }
}

// ============================================================================
// JSON/CSV SERIALIZATION
// ============================================================================

int tee_proto_announce_to_json(const tee_msg_announce_t *msg,
                                char *buf, size_t buf_len) {
    if (!msg || !buf) return -1;
    
    int len = snprintf(buf, buf_len,
        "{"
        "\"device_id\":\"%s\","
        "\"tee_mode\":%d,"
        "\"tee_provider\":%d,"
        "\"ram_available_kb\":%d,"
        "\"num_algorithms\":%d,"
        "\"algorithms\":[",
        msg->device_id,
        msg->tee_mode,
        msg->tee_provider,
        msg->ram_available_kb,
        msg->num_algorithms);
    
    for (int i = 0; i < msg->num_algorithms && len < buf_len - 20; i++) {
        len += snprintf(buf + len, buf_len - len,
                        "%s\"%s\"",
                        i > 0 ? "," : "",
                        msg->algorithms[i]);
    }
    
    len += snprintf(buf + len, buf_len - len, "]}");
    
    return len;
}

int tee_proto_result_to_json(const tee_msg_benchmark_result_t *msg,
                              char *buf, size_t buf_len) {
    if (!msg || !buf) return -1;
    
    return snprintf(buf, buf_len,
        "{"
        "\"device_id\":\"%s\","
        "\"algorithm\":\"%s\","
        "\"keygen_cycles\":%llu,"
        "\"encaps_cycles\":%llu,"
        "\"decaps_cycles\":%llu,"
        "\"stack_usage\":%u,"
        "\"heap_usage\":%u,"
        "\"tee_mode\":%d,"
        "\"tee_provider\":%d,"
        "\"tee_overhead_cycles\":%llu,"
        "\"tee_rng_calls\":%u,"
        "\"e2e_latency_ms\":%u,"
        "\"tx_packets\":%u,"
        "\"rx_packets\":%u"
        "}",
        msg->device_id,
        msg->algorithm,
        (unsigned long long)msg->keygen_cycles,
        (unsigned long long)msg->encaps_cycles,
        (unsigned long long)msg->decaps_cycles,
        msg->stack_usage,
        msg->heap_usage,
        msg->tee_mode,
        msg->tee_provider,
        (unsigned long long)msg->tee_overhead_cycles,
        msg->tee_rng_calls,
        msg->e2e_latency_ms,
        msg->tx_packets,
        msg->rx_packets);
}

int tee_proto_result_to_csv(const tee_msg_benchmark_result_t *msg,
                             char *buf, size_t buf_len) {
    if (!msg || !buf) return -1;
    
    // CSV header (for reference):
    // Device,Algorithm,KeyGen,Encaps,Decaps,Stack,Heap,TEE_Mode,TEE_Provider,
    // TEE_Overhead,TEE_RNG_Calls,E2E_Latency_ms,TX_Packets,RX_Packets
    
    return snprintf(buf, buf_len,
        "%s,%s,%llu,%llu,%llu,%u,%u,%d,%d,%llu,%u,%u,%u,%u",
        msg->device_id,
        msg->algorithm,
        (unsigned long long)msg->keygen_cycles,
        (unsigned long long)msg->encaps_cycles,
        (unsigned long long)msg->decaps_cycles,
        msg->stack_usage,
        msg->heap_usage,
        msg->tee_mode,
        msg->tee_provider,
        (unsigned long long)msg->tee_overhead_cycles,
        msg->tee_rng_calls,
        msg->e2e_latency_ms,
        msg->tx_packets,
        msg->rx_packets);
}

// ============================================================================
// PROTOCOL INITIALIZATION
// ============================================================================

int tee_proto_init(void) {
    memset(&g_handler_state, 0, sizeof(g_handler_state));
    
    generate_device_id();
    
    printk("NET: Protocol handler initialized\n");
    printk("NET: Device ID: %s\n", g_handler_state.device_id);
    printk("NET: Supported algorithms: %d\n", count_supported_algorithms());
    
    g_handler_state.initialized = true;
    
    return 0;
}

void tee_proto_set_tee_context(tee_context_t *ctx) {
    g_handler_state.tee_ctx = ctx;
}

bool tee_proto_is_benchmark_requested(void) {
    return g_handler_state.benchmark_running && !g_handler_state.result_available;
}

const char* tee_proto_get_requested_algorithm(void) {
    return g_handler_state.current_algorithm;
}

uint16_t tee_proto_get_requested_iterations(void) {
    return g_handler_state.current_iterations;
}

void tee_proto_set_benchmark_result(const tee_msg_benchmark_result_t *result) {
    if (result) {
        memcpy(&g_handler_state.last_result, result, sizeof(*result));
        
        // Calculate E2E latency
        uint64_t end_time = k_uptime_get();
        g_handler_state.last_result.e2e_latency_ms = 
            (uint32_t)(end_time - g_handler_state.benchmark_start_time);
        
        g_handler_state.result_available = true;
        g_handler_state.benchmark_running = false;
    }
}

bool tee_proto_has_result(void) {
    return g_handler_state.result_available;
}

const char* tee_proto_msg_type_name(tee_msg_type_t type) {
    switch (type) {
        case TEE_MSG_DISCOVER:         return "DISCOVER";
        case TEE_MSG_ANNOUNCE:         return "ANNOUNCE";
        case TEE_MSG_ATTEST_REQUEST:   return "ATTEST_REQUEST";
        case TEE_MSG_ATTEST_RESPONSE:  return "ATTEST_RESPONSE";
        case TEE_MSG_BENCHMARK_START:  return "BENCHMARK_START";
        case TEE_MSG_BENCHMARK_STOP:   return "BENCHMARK_STOP";
        case TEE_MSG_BENCHMARK_RESULT: return "BENCHMARK_RESULT";
        case TEE_MSG_STATUS_REQUEST:   return "STATUS_REQUEST";
        case TEE_MSG_STATUS_RESPONSE:  return "STATUS_RESPONSE";
        case TEE_MSG_ERROR:            return "ERROR";
        default:                       return "UNKNOWN";
    }
}

const char* tee_proto_error_name(tee_error_t error) {
    switch (error) {
        case TEE_ERR_NONE:             return "NONE";
        case TEE_ERR_INVALID_MSG:      return "INVALID_MSG";
        case TEE_ERR_UNSUPPORTED_ALG:  return "UNSUPPORTED_ALG";
        case TEE_ERR_TEE_NOT_READY:    return "TEE_NOT_READY";
        case TEE_ERR_ATTESTATION_FAIL: return "ATTESTATION_FAIL";
        case TEE_ERR_BENCHMARK_FAIL:   return "BENCHMARK_FAIL";
        case TEE_ERR_OUT_OF_MEMORY:    return "OUT_OF_MEMORY";
        case TEE_ERR_BUSY:             return "BUSY";
        case TEE_ERR_TIMEOUT:          return "TIMEOUT";
        default:                       return "UNKNOWN";
    }
}

#else  // Networking not enabled

int tee_proto_init(void) {
    printk("NET: Protocol handler disabled (CONFIG_NETWORKING not set)\n");
    return -1;
}

int tee_proto_handle_message(const uint8_t *data, size_t len,
                              uint8_t *response, size_t *response_len) {
    (void)data; (void)len; (void)response; (void)response_len;
    return -1;
}

#endif  // CONFIG_NETWORKING && CONFIG_COAP
