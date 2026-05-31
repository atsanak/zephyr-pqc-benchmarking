#ifndef HARNESS_H
#define HARNESS_H

#include <zephyr/kernel.h>
#include <stdint.h>
#include <stdbool.h>
#include "utils.h"

// Note: operation_type_t is defined in utils.h to avoid circular dependency

// Dynamic iteration functions for KEM benchmarking
uint32_t run_dynamic_iterations(operation_type_t op_type, uint64_t *cycles_out);
uint32_t run_dynamic_iterations_for_kem(kem_info_t* kem, operation_type_t op_type, uint64_t *cycles_out);

// Dynamic iteration function for DSA/Signature benchmarking
uint32_t run_dynamic_iterations_for_sign(sign_info_t* sign, operation_type_t op_type, uint64_t *cycles_out);

double calculate_ci_half_width(uint64_t *samples, size_t n, double mean);

// Time budget functions
void benchmark_timing_init(void);
void benchmark_timing_start(void);
uint64_t benchmark_timing_counter_get(void);
uint64_t benchmark_timing_cycles_get(uint64_t *start, uint64_t *end);

// Environment setup
bool step0_environment_setup(void);

#endif // HARNESS_H
