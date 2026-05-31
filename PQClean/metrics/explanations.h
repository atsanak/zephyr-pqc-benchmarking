#include <stdio.h>
// Benchmark metric explanations
#ifndef BENCHMARK_METRIC_EXPLANATIONS_H
#define BENCHMARK_METRIC_EXPLANATIONS_H

// Print explanations of each benchmark metric
void print_benchmark_explanations(void) {
    printf("\n=== BENCHMARK METRICS EXPLANATION ===\n");
    printf("CPU Cycles: Number of CPU cycles required for operation (lower is better)\n");
    printf("Mean: Average value across all iterations\n");
    printf("Median: Middle value when sorted (less affected by outliers)\n");
    printf("StdDev: Standard deviation - measure of variability\n");
    printf("Min/Max: Lowest and highest measurements\n");
    printf("\n=== MEMORY USAGE INFORMATION ===\n");
    printf("Stack/Heap Usage: Shows configured values, not measured values\n");
    printf("These are static configuration parameters set at build time\n");
    printf("Actual memory usage may vary depending on implementation\n");
    printf("\n=== BENCHMARK OPERATIONS ===\n");
    printf("KeyGen: Key generation process (creates public and private keys)\n");
    printf("Encaps: Encapsulation process (creates shared secret using public key)\n");
    printf("Decaps: Decapsulation process (recovers shared secret using private key)\n");
    printf("\n=== STATISTICAL SIGNIFICANCE ===\n");
    printf("All operations are run multiple times to ensure measurement validity\n");
    printf("The same number of iterations are performed for all algorithms\n\n");
}

#endif // BENCHMARK_METRIC_EXPLANATIONS_H
