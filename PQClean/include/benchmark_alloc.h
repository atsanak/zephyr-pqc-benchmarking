#ifndef BENCHMARK_ALLOC_H
#define BENCHMARK_ALLOC_H

#include <stddef.h>
#include <stdint.h>

void benchmark_heap_tracker_reset(void);
void *benchmark_k_malloc(size_t size);
void benchmark_k_free(void *ptr);
size_t benchmark_heap_peak_bytes(void);
uint64_t benchmark_heap_alloc_total_bytes(void);
uint32_t benchmark_heap_alloc_calls(void);

#endif // BENCHMARK_ALLOC_H
