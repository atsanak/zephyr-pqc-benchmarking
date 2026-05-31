#ifndef PMU_CONFIG_H
#define PMU_CONFIG_H


// Authentic Performance Monitoring Unit (PMU) Configuration
// This header enables real hardware measurement capabilities

// Enable PMU features based on architecture
/* #ifdef CONFIG_ARM
    // ARM PMU configuration
    #define CONFIG_ARM_PMU 1
    #ifdef CONFIG_ARM_CORTEX_A
        #define CONFIG_ARM_PMU_PERFCTR 1
        #define CONFIG_ARM_PMU_USER_ACCESS 1
    #endif
#endif

#ifdef CONFIG_X86
    // x86 PMU configuration  
    #define CONFIG_X86_PMU 1
    #define CONFIG_X86_MSR_ACCESS 1
#endif

#ifdef CONFIG_RISCV
    // RISC-V PMU configuration
    #define CONFIG_RISCV_PMU 1
#endif

// Power measurement configuration
#define CONFIG_PM_DEVICE_RUNTIME 1

// SoC-specific power measurement
#ifdef CONFIG_SOC_FAMILY_STM32
    #define CONFIG_SOC_POWER_MEASUREMENT 1
#endif

#ifdef CONFIG_SOC_FAMILY_NRF
    #define CONFIG_SOC_POWER_MEASUREMENT 1
#endif

#ifdef CONFIG_SOC_FAMILY_ESP32
    #define CONFIG_SOC_POWER_MEASUREMENT 1
#endif

// QEMU simulator enhancements
#ifdef CONFIG_BOARD_QEMU_X86
    #define CONFIG_COUNTER_NATIVE_POSIX 1
#endif

#ifdef CONFIG_BOARD_QEMU_CORTEX_M3
    #define CONFIG_COUNTER_NATIVE_POSIX 1
#endif

#ifdef CONFIG_BOARD_QEMU_RISCV32
    #define CONFIG_COUNTER_NATIVE_POSIX 1
#endif

#ifdef CONFIG_BOARD_QEMU_RISCV64
    #define CONFIG_COUNTER_NATIVE_POSIX 1
#endif */
/*
 * PMU validation thresholds only.
 *
 * Do not synthesize Zephyr CONFIG_* capability macros here. Benchmark code
 * must use the real Kconfig selections emitted by the active build so that
 * unsupported QEMU features are not mislabeled as hardware-backed.
 */

// PMU measurement validation thresholds
#define PMU_MIN_INSTRUCTION_COUNT 100
#define PMU_MAX_CACHE_MISS_RATE 0.1    // 10% max cache miss rate
#define PMU_MAX_BRANCH_MISS_RATE 0.2   // 20% max branch miss rate

// Energy measurement validation
#define ENERGY_MIN_MICROJOULES 0.001   // 1nJ minimum
#define ENERGY_MAX_MICROJOULES 10000.0 // 10mJ maximum per operation

#endif // PMU_CONFIG_H
