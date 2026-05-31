#include "benchmark_alloc.h"

#include <zephyr/kernel.h>

typedef struct {
    size_t size;
} benchmark_alloc_header_t;

static size_t g_heap_current_bytes;
static size_t g_heap_peak_bytes;
static uint64_t g_heap_alloc_total_bytes;
static uint32_t g_heap_alloc_calls;

void benchmark_heap_tracker_reset(void)
{
    g_heap_current_bytes = 0U;
    g_heap_peak_bytes = 0U;
    g_heap_alloc_total_bytes = 0U;
    g_heap_alloc_calls = 0U;
}

void *benchmark_k_malloc(size_t size)
{
    size_t total_size = sizeof(benchmark_alloc_header_t) + size;
    benchmark_alloc_header_t *header = k_malloc(total_size);

    if (!header) {
        return NULL;
    }

    header->size = size;
    g_heap_current_bytes += size;
    g_heap_alloc_total_bytes += size;
    g_heap_alloc_calls += 1U;
    if (g_heap_current_bytes > g_heap_peak_bytes) {
        g_heap_peak_bytes = g_heap_current_bytes;
    }

    return (void *)(header + 1);
}

void benchmark_k_free(void *ptr)
{
    benchmark_alloc_header_t *header;

    if (!ptr) {
        return;
    }

    header = ((benchmark_alloc_header_t *)ptr) - 1;
    if (header->size <= g_heap_current_bytes) {
        g_heap_current_bytes -= header->size;
    } else {
        g_heap_current_bytes = 0U;
    }
    k_free(header);
}

size_t benchmark_heap_peak_bytes(void)
{
    return g_heap_peak_bytes;
}

uint64_t benchmark_heap_alloc_total_bytes(void)
{
    return g_heap_alloc_total_bytes;
}

uint32_t benchmark_heap_alloc_calls(void)
{
    return g_heap_alloc_calls;
}
