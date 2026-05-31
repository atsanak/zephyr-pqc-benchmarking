// Benchmark Status and Control System
// Provides stop/resume mechanism, progress tracking, and error monitoring

#ifndef BENCHMARK_CONTROL_H
#define BENCHMARK_CONTROL_H

#include <stdint.h>
#include <stdbool.h>
#include "utils.h"

// Benchmark control states
typedef enum {
    BENCHMARK_STATE_STOPPED,
    BENCHMARK_STATE_RUNNING,
    BENCHMARK_STATE_PAUSED,
    BENCHMARK_STATE_COMPLETED,
    BENCHMARK_STATE_ERROR
} benchmark_state_t;

// Benchmark session tracking
typedef struct {
    uint32_t total_kems;
    uint32_t completed_kems;
    uint32_t current_kem_index;
    uint32_t failed_kems;
    uint32_t total_operations;
    uint32_t completed_operations;
    benchmark_state_t state;
    uint64_t start_time_ms;
    uint64_t elapsed_time_ms;
    char current_kem_name[64];
    char current_operation[16];
    bool should_stop;
    bool should_pause;
    char last_error[256];
} benchmark_session_t;

// Per-KEM result tracking
typedef struct {
    char kem_name[64];
    char kem_variant[32];
    uint32_t pk_bytes;
    uint32_t sk_bytes;
    uint32_t ct_bytes;
    uint32_t ss_bytes;
    bool keypair_success;
    bool encaps_success;
    bool decaps_success;
    uint64_t keypair_cycles;
    uint64_t encaps_cycles;
    uint64_t decaps_cycles;
    char error_message[256];
    uint32_t stack_usage_bytes;
} kem_result_t;

// Per-DSA/Sign result tracking (mirrors kem_result_t for consistency)
typedef struct {
    char sign_name[64];
    char sign_variant[32];
    uint32_t pk_bytes;
    uint32_t sk_bytes;
    uint32_t sig_bytes;
    bool keypair_success;
    bool sign_success;
    bool verify_success;
    uint64_t keypair_cycles;
    uint64_t sign_cycles;
    uint64_t verify_cycles;
    char error_message[256];
    uint32_t stack_usage_bytes;
} sign_result_t;

// Global session instance
extern benchmark_session_t g_benchmark_session;
extern kem_result_t g_kem_results[16]; // Support for all 16 KEMs
extern sign_result_t g_sign_results[20]; // Support for all 20 DSA algorithms

// Control functions
void benchmark_session_init(void);
void benchmark_session_start(void);
void benchmark_session_pause(void);
void benchmark_session_resume(void);
void benchmark_session_stop(void);
bool benchmark_should_continue(void);
void benchmark_update_progress(uint32_t kem_index, const char* operation);
void benchmark_record_error(const char* error_msg);
void benchmark_record_kem_result(uint32_t kem_index, kem_info_t* kem, 
                                benchmark_results_t results[3], bool success);
void benchmark_record_sign_result(uint32_t sign_index, sign_info_t* sign, 
                                  benchmark_results_t results[3], bool success);

// Status reporting
void benchmark_print_status(void);
void benchmark_print_summary(void);
void benchmark_save_state(void);
bool benchmark_load_state(void);

// Stack usage monitoring
void stack_usage_init(void);
uint32_t stack_usage_get_current(void);
uint32_t stack_usage_get_peak(void);
void stack_usage_print_report(void);

#endif // BENCHMARK_CONTROL_H
