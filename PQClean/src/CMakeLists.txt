# Zephyr 4.3.0 Compatible Configuration
cmake_minimum_required(VERSION 3.20.5)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(pqclean_comprehensive_benchmark)

# Comprehensive KEM Configuration options - ALL OFF BY DEFAULT
option(ENABLE_ML_KEM_512 "Enable ML-KEM-512" OFF)
option(ENABLE_ML_KEM_768 "Enable ML-KEM-768" OFF)
option(ENABLE_ML_KEM_1024 "Enable ML-KEM-1024" OFF)
option(ENABLE_HQC_128 "Enable HQC-128" OFF)
option(ENABLE_HQC_192 "Enable HQC-192" OFF)
option(ENABLE_HQC_256 "Enable HQC-256" OFF)
option(ENABLE_MCELIECE_348864 "Enable McEliece 348864" OFF)
option(ENABLE_MCELIECE_348864F "Enable McEliece 348864f" OFF)
option(ENABLE_MCELIECE_460896 "Enable McEliece 460896" OFF)
option(ENABLE_MCELIECE_460896F "Enable McEliece 460896f" OFF)
option(ENABLE_MCELIECE_6688128 "Enable McEliece 6688128" OFF)
option(ENABLE_MCELIECE_6688128F "Enable McEliece 6688128f" OFF)
option(ENABLE_MCELIECE_6960119 "Enable McEliece 6960119" OFF)
option(ENABLE_MCELIECE_6960119F "Enable McEliece 6960119f" OFF)
option(ENABLE_MCELIECE_8192128 "Enable McEliece 8192128" OFF)
option(ENABLE_MCELIECE_8192128F "Enable McEliece 8192128f" OFF)

# Comprehensive DSA Configuration options - ALL OFF BY DEFAULT
# ML-DSA (Dilithium) Family
option(ENABLE_ML_DSA_44 "Enable ML-DSA-44" OFF)
option(ENABLE_ML_DSA_65 "Enable ML-DSA-65" OFF)
option(ENABLE_ML_DSA_87 "Enable ML-DSA-87" OFF)

# Falcon Family
option(ENABLE_FALCON_512 "Enable Falcon-512" OFF)
option(ENABLE_FALCON_1024 "Enable Falcon-1024" OFF)
option(ENABLE_FALCON_PADDED_512 "Enable Falcon-padded-512" OFF)
option(ENABLE_FALCON_PADDED_1024 "Enable Falcon-padded-1024" OFF)

# SPHINCS+ SHA2 Family
option(ENABLE_SPHINCS_SHA2_128F "Enable SPHINCS+-SHA2-128f-simple" OFF)
option(ENABLE_SPHINCS_SHA2_128S "Enable SPHINCS+-SHA2-128s-simple" OFF)
option(ENABLE_SPHINCS_SHA2_192F "Enable SPHINCS+-SHA2-192f-simple" OFF)
option(ENABLE_SPHINCS_SHA2_192S "Enable SPHINCS+-SHA2-192s-simple" OFF)
option(ENABLE_SPHINCS_SHA2_256F "Enable SPHINCS+-SHA2-256f-simple" OFF)
option(ENABLE_SPHINCS_SHA2_256S "Enable SPHINCS+-SHA2-256s-simple" OFF)

# SPHINCS+ SHAKE Family
option(ENABLE_SPHINCS_SHAKE_128F "Enable SPHINCS+-SHAKE-128f-simple" OFF)
option(ENABLE_SPHINCS_SHAKE_128S "Enable SPHINCS+-SHAKE-128s-simple" OFF)
option(ENABLE_SPHINCS_SHAKE_192F "Enable SPHINCS+-SHAKE-192f-simple" OFF)
option(ENABLE_SPHINCS_SHAKE_192S "Enable SPHINCS+-SHAKE-192s-simple" OFF)
option(ENABLE_SPHINCS_SHAKE_256F "Enable SPHINCS+-SHAKE-256f-simple" OFF)
option(ENABLE_SPHINCS_SHAKE_256S "Enable SPHINCS+-SHAKE-256s-simple" OFF)

# TEE Integration Options (Phase 1-3)
option(ENABLE_TEE "Enable TEE integration" OFF)
set(TEE_PROVIDER "none" CACHE STRING "TEE provider (none, tfm, keystone, sgx, tdx, simulated)")

# Main application sources (modular framework)
target_sources(app PRIVATE 
    main.c
    utils.c
    benchmark_alloc.c
    symmetric_profile.c
    kem_registry.c
    sig_registry.c
    benchmark_control.c
    ../harness/dynamic_iters.c
    ../harness/time_budget.c
    ../harness/timing_port.c
    ../metrics/cycles.c
    ../metrics/energy.c
    ../metrics/jitter.c
    ../metrics/entropy.c
    ../metrics/entropy_consumption.c
    ../metrics/memory.c
    ../metrics/throttle.c
    ../metrics/deadline.c
    ../metrics/isr_tax.c
    ../metrics/fairness.c
    ../metrics/release_jitter.c
    ../metrics/profiler.c
    # Common PQClean components (always needed)
    ../common/fips202.c
    ../common/sha2.c
    ../common/aes.c
    ../common/sp800-185.c
    ../common/randombytes.c
    # TEE abstraction layer (always compiled)
    tee_abstraction.c
    tee_none.c
)

# Prefer scheme-local PQClean API headers over duplicated fallback constants so
# exported size metadata stays tied to the compiled implementation.
target_compile_definitions(app PRIVATE TRY_REAL_API_HEADERS=1)

# Conditional TEE backend sources
if(ENABLE_TEE)
    message(STATUS "TEE integration enabled, provider: ${TEE_PROVIDER}")
    target_compile_definitions(app PRIVATE ENABLE_TEE=1)
    
    if(TEE_PROVIDER STREQUAL "tfm")
        target_sources(app PRIVATE tee_tfm_rng.c)
        target_compile_definitions(app PRIVATE CONFIG_TEE_TFM_ENABLED=1)
        message(STATUS "TF-M backend enabled")
    elseif(TEE_PROVIDER STREQUAL "simulated")
        target_sources(app PRIVATE tee_simulated.c)
        target_compile_definitions(app PRIVATE CONFIG_TEE_SIMULATED=1)
        message(STATUS "Simulated TEE backend enabled")
    endif()
else()
    message(STATUS "TEE integration disabled (baseline mode only)")
endif()

# =============================================================================
# Network Orchestration (mTLS MQTT / CoAP)
# =============================================================================
option(ENABLE_NETWORK_ORCHESTRATION "Enable network-based TEE orchestration" OFF)

if(ENABLE_NETWORK_ORCHESTRATION)
    message(STATUS "Network orchestration enabled")
    target_compile_definitions(app PRIVATE ENABLE_NETWORK_ORCHESTRATION=1)
    
    # Network protocol handler (CoAP)
    target_sources(app PRIVATE tee_network_handler.c)
    
    # MQTT client with mTLS (if TLS enabled in Kconfig)
    if(CONFIG_MQTT_LIB_TLS)
        message(STATUS "mTLS MQTT client enabled")
        target_sources(app PRIVATE tee_mqtt_client.c)
        target_compile_definitions(app PRIVATE ENABLE_MQTT_TLS=1)
        
        # Include generated certificate header
        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../certs/mqtt_certs.h")
            target_include_directories(app PRIVATE ../certs)
            message(STATUS "Using embedded TLS certificates from certs/mqtt_certs.h")
        else()
            message(WARNING "mqtt_certs.h not found - run certs/generate_certs.sh first")
        endif()
        
        # Option to store private key in TF-M secure storage
        option(MQTT_KEY_IN_TFM "Store MQTT private key in TF-M secure storage" OFF)
        if(MQTT_KEY_IN_TFM)
            target_compile_definitions(app PRIVATE MQTT_KEY_IN_TFM=1)
            message(STATUS "MQTT private key will be stored in TF-M secure storage")
        endif()
    else()
        message(STATUS "MQTT TLS disabled - using CoAP only")
    endif()
endif()

# Base include directories
target_include_directories(app PRIVATE
    ../include
    ../common
    ../harness
    ../metrics
)

# Use real Zephyr Kconfig capability macros from autoconf.h.
# Do not fabricate PMU / PM runtime support with compile definitions, since
# that makes QEMU targets look more hardware-capable than they really are.

# ML-KEM-512 (default enabled)
if(ENABLE_ML_KEM_512)
    target_sources(app PRIVATE
        ../crypto_kem/ml-kem-512/clean/kem.c
        ../crypto_kem/ml-kem-512/clean/indcpa.c
        ../crypto_kem/ml-kem-512/clean/polyvec.c
        ../crypto_kem/ml-kem-512/clean/poly.c
        ../crypto_kem/ml-kem-512/clean/ntt.c
        ../crypto_kem/ml-kem-512/clean/cbd.c
        ../crypto_kem/ml-kem-512/clean/reduce.c
        ../crypto_kem/ml-kem-512/clean/verify.c
        ../crypto_kem/ml-kem-512/clean/symmetric-shake.c
    )
    target_include_directories(app PRIVATE ../crypto_kem/ml-kem-512/clean)
    target_compile_definitions(app PRIVATE ENABLE_ML_KEM_512=1)
    message(STATUS "ML-KEM-512 enabled")
endif()

# ML-KEM-768 (optional)
if(ENABLE_ML_KEM_768)
    target_sources(app PRIVATE
        ../crypto_kem/ml-kem-768/clean/kem.c
        ../crypto_kem/ml-kem-768/clean/indcpa.c
        ../crypto_kem/ml-kem-768/clean/polyvec.c
        ../crypto_kem/ml-kem-768/clean/poly.c
        ../crypto_kem/ml-kem-768/clean/ntt.c
        ../crypto_kem/ml-kem-768/clean/cbd.c
        ../crypto_kem/ml-kem-768/clean/reduce.c
        ../crypto_kem/ml-kem-768/clean/verify.c
        ../crypto_kem/ml-kem-768/clean/symmetric-shake.c
    )
    target_include_directories(app PRIVATE ../crypto_kem/ml-kem-768/clean)
    target_compile_definitions(app PRIVATE ENABLE_ML_KEM_768=1)
    message(STATUS "ML-KEM-768 enabled")
endif()

# ML-KEM-1024 (optional)
if(ENABLE_ML_KEM_1024)
    target_sources(app PRIVATE
        ../crypto_kem/ml-kem-1024/clean/kem.c
        ../crypto_kem/ml-kem-1024/clean/indcpa.c
        ../crypto_kem/ml-kem-1024/clean/polyvec.c
        ../crypto_kem/ml-kem-1024/clean/poly.c
        ../crypto_kem/ml-kem-1024/clean/ntt.c
        ../crypto_kem/ml-kem-1024/clean/cbd.c
        ../crypto_kem/ml-kem-1024/clean/reduce.c
        ../crypto_kem/ml-kem-1024/clean/verify.c
        ../crypto_kem/ml-kem-1024/clean/symmetric-shake.c
    )
    target_include_directories(app PRIVATE ../crypto_kem/ml-kem-1024/clean)
    target_compile_definitions(app PRIVATE ENABLE_ML_KEM_1024=1)
    message(STATUS "ML-KEM-1024 enabled")
endif()

# HQC-128 (optional)
if(ENABLE_HQC_128)
    target_sources(app PRIVATE
        ../crypto_kem/hqc-128/clean/kem.c
        ../crypto_kem/hqc-128/clean/hqc.c
        ../crypto_kem/hqc-128/clean/code.c
        ../crypto_kem/hqc-128/clean/fft.c
        ../crypto_kem/hqc-128/clean/gf.c
        ../crypto_kem/hqc-128/clean/gf2x.c
        ../crypto_kem/hqc-128/clean/parsing.c
        ../crypto_kem/hqc-128/clean/reed_muller.c
        ../crypto_kem/hqc-128/clean/reed_solomon.c
        ../crypto_kem/hqc-128/clean/shake_ds.c
        ../crypto_kem/hqc-128/clean/shake_prng.c
        ../crypto_kem/hqc-128/clean/vector.c
    )
    target_include_directories(app PRIVATE ../crypto_kem/hqc-128/clean)
    target_compile_definitions(app PRIVATE ENABLE_HQC_128=1)
    message(STATUS "HQC-128 enabled")
endif()

# HQC-192 (optional)
if(ENABLE_HQC_192)
    target_sources(app PRIVATE
        ../crypto_kem/hqc-192/clean/kem.c
        ../crypto_kem/hqc-192/clean/hqc.c
        ../crypto_kem/hqc-192/clean/code.c
        ../crypto_kem/hqc-192/clean/fft.c
        ../crypto_kem/hqc-192/clean/gf.c
        ../crypto_kem/hqc-192/clean/gf2x.c
        ../crypto_kem/hqc-192/clean/parsing.c
        ../crypto_kem/hqc-192/clean/reed_muller.c
        ../crypto_kem/hqc-192/clean/reed_solomon.c
        ../crypto_kem/hqc-192/clean/shake_ds.c
        ../crypto_kem/hqc-192/clean/shake_prng.c
        ../crypto_kem/hqc-192/clean/vector.c
    )
    target_include_directories(app PRIVATE ../crypto_kem/hqc-192/clean)
    target_compile_definitions(app PRIVATE ENABLE_HQC_192=1)
    message(STATUS "HQC-192 enabled")
endif()

# HQC-256 (optional)
if(ENABLE_HQC_256)
    target_sources(app PRIVATE
        ../crypto_kem/hqc-256/clean/kem.c
        ../crypto_kem/hqc-256/clean/hqc.c
        ../crypto_kem/hqc-256/clean/code.c
        ../crypto_kem/hqc-256/clean/fft.c
        ../crypto_kem/hqc-256/clean/gf.c
        ../crypto_kem/hqc-256/clean/gf2x.c
        ../crypto_kem/hqc-256/clean/parsing.c
        ../crypto_kem/hqc-256/clean/reed_muller.c
        ../crypto_kem/hqc-256/clean/reed_solomon.c
        ../crypto_kem/hqc-256/clean/shake_ds.c
        ../crypto_kem/hqc-256/clean/shake_prng.c
        ../crypto_kem/hqc-256/clean/vector.c
    )
    target_include_directories(app PRIVATE ../crypto_kem/hqc-256/clean)
    target_compile_definitions(app PRIVATE ENABLE_HQC_256=1)
    message(STATUS "HQC-256 enabled")
endif()

# McEliece 348864 (optional - WARNING: large memory requirements)
if(ENABLE_MCELIECE_348864)
    file(GLOB MCELIECE_348864_SOURCES "../crypto_kem/mceliece348864/clean/*.c")
    target_sources(app PRIVATE ${MCELIECE_348864_SOURCES})
    target_include_directories(app PRIVATE ../crypto_kem/mceliece348864/clean)
    target_compile_definitions(app PRIVATE ENABLE_MCELIECE_348864=1)
    message(STATUS "McEliece 348864 enabled (WARNING: 261KB public key)")
endif()

# McEliece 348864f (optional - fast variant)
if(ENABLE_MCELIECE_348864F)
    file(GLOB MCELIECE_348864F_SOURCES "../crypto_kem/mceliece348864f/clean/*.c")
    target_sources(app PRIVATE ${MCELIECE_348864F_SOURCES})
    target_include_directories(app PRIVATE ../crypto_kem/mceliece348864f/clean)
    target_compile_definitions(app PRIVATE ENABLE_MCELIECE_348864F=1)
    message(STATUS "McEliece 348864f enabled (fast variant)")
endif()

# McEliece 460896 (optional)
if(ENABLE_MCELIECE_460896)
    file(GLOB MCELIECE_460896_SOURCES "../crypto_kem/mceliece460896/clean/*.c")
    target_sources(app PRIVATE ${MCELIECE_460896_SOURCES})
    target_include_directories(app PRIVATE ../crypto_kem/mceliece460896/clean)
    target_compile_definitions(app PRIVATE ENABLE_MCELIECE_460896=1)
    message(STATUS "McEliece 460896 enabled")
endif()

# McEliece 460896f (optional - fast variant)
if(ENABLE_MCELIECE_460896F)
    file(GLOB MCELIECE_460896F_SOURCES "../crypto_kem/mceliece460896f/clean/*.c")
    target_sources(app PRIVATE ${MCELIECE_460896F_SOURCES})
    target_include_directories(app PRIVATE ../crypto_kem/mceliece460896f/clean)
    target_compile_definitions(app PRIVATE ENABLE_MCELIECE_460896F=1)
    message(STATUS "McEliece 460896f enabled (fast variant)")
endif()

# McEliece 6688128 (optional)
if(ENABLE_MCELIECE_6688128)
    file(GLOB MCELIECE_6688128_SOURCES "../crypto_kem/mceliece6688128/clean/*.c")
    target_sources(app PRIVATE ${MCELIECE_6688128_SOURCES})
    target_include_directories(app PRIVATE ../crypto_kem/mceliece6688128/clean)
    target_compile_definitions(app PRIVATE ENABLE_MCELIECE_6688128=1)
    message(STATUS "McEliece 6688128 enabled")
endif()

# McEliece 6688128f (optional - fast variant)
if(ENABLE_MCELIECE_6688128F)
    file(GLOB MCELIECE_6688128F_SOURCES "../crypto_kem/mceliece6688128f/clean/*.c")
    target_sources(app PRIVATE ${MCELIECE_6688128F_SOURCES})
    target_include_directories(app PRIVATE ../crypto_kem/mceliece6688128f/clean)
    target_compile_definitions(app PRIVATE ENABLE_MCELIECE_6688128F=1)
    message(STATUS "McEliece 6688128f enabled (fast variant)")
endif()

# McEliece 6960119 (optional)
if(ENABLE_MCELIECE_6960119)
    file(GLOB MCELIECE_6960119_SOURCES "../crypto_kem/mceliece6960119/clean/*.c")
    target_sources(app PRIVATE ${MCELIECE_6960119_SOURCES})
    target_include_directories(app PRIVATE ../crypto_kem/mceliece6960119/clean)
    target_compile_definitions(app PRIVATE ENABLE_MCELIECE_6960119=1)
    message(STATUS "McEliece 6960119 enabled")
endif()

# McEliece 6960119f (optional - fast variant)
if(ENABLE_MCELIECE_6960119F)
    file(GLOB MCELIECE_6960119F_SOURCES "../crypto_kem/mceliece6960119f/clean/*.c")
    target_sources(app PRIVATE ${MCELIECE_6960119F_SOURCES})
    target_include_directories(app PRIVATE ../crypto_kem/mceliece6960119f/clean)
    target_compile_definitions(app PRIVATE ENABLE_MCELIECE_6960119F=1)
    message(STATUS "McEliece 6960119f enabled (fast variant)")
endif()

# McEliece 8192128 (optional)
if(ENABLE_MCELIECE_8192128)
    file(GLOB MCELIECE_8192128_SOURCES "../crypto_kem/mceliece8192128/clean/*.c")
    target_sources(app PRIVATE ${MCELIECE_8192128_SOURCES})
    target_include_directories(app PRIVATE ../crypto_kem/mceliece8192128/clean)
    target_compile_definitions(app PRIVATE ENABLE_MCELIECE_8192128=1)
    message(STATUS "McEliece 8192128 enabled")
endif()

# McEliece 8192128f (optional - fast variant)
if(ENABLE_MCELIECE_8192128F)
    file(GLOB MCELIECE_8192128F_SOURCES "../crypto_kem/mceliece8192128f/clean/*.c")
    target_sources(app PRIVATE ${MCELIECE_8192128F_SOURCES})
    target_include_directories(app PRIVATE ../crypto_kem/mceliece8192128f/clean)
    target_compile_definitions(app PRIVATE ENABLE_MCELIECE_8192128F=1)
    message(STATUS "McEliece 8192128f enabled (fast variant)")
endif()

# ===================================================================
# DSA (Digital Signature Algorithm) Sources
# ===================================================================

# ML-DSA-44 (Dilithium)
if(ENABLE_ML_DSA_44)
    target_sources(app PRIVATE
        ../crypto_sign/ml-dsa-44/clean/sign.c
        ../crypto_sign/ml-dsa-44/clean/packing.c
        ../crypto_sign/ml-dsa-44/clean/polyvec.c
        ../crypto_sign/ml-dsa-44/clean/poly.c
        ../crypto_sign/ml-dsa-44/clean/ntt.c
        ../crypto_sign/ml-dsa-44/clean/reduce.c
        ../crypto_sign/ml-dsa-44/clean/rounding.c
        ../crypto_sign/ml-dsa-44/clean/symmetric-shake.c
    )
    target_include_directories(app PRIVATE ../crypto_sign/ml-dsa-44/clean)
    target_compile_definitions(app PRIVATE ENABLE_ML_DSA_44=1)
    message(STATUS "ML-DSA-44 enabled")
endif()

# ML-DSA-65 (Dilithium)
if(ENABLE_ML_DSA_65)
    target_sources(app PRIVATE
        ../crypto_sign/ml-dsa-65/clean/sign.c
        ../crypto_sign/ml-dsa-65/clean/packing.c
        ../crypto_sign/ml-dsa-65/clean/polyvec.c
        ../crypto_sign/ml-dsa-65/clean/poly.c
        ../crypto_sign/ml-dsa-65/clean/ntt.c
        ../crypto_sign/ml-dsa-65/clean/reduce.c
        ../crypto_sign/ml-dsa-65/clean/rounding.c
        ../crypto_sign/ml-dsa-65/clean/symmetric-shake.c
    )
    target_include_directories(app PRIVATE ../crypto_sign/ml-dsa-65/clean)
    target_compile_definitions(app PRIVATE ENABLE_ML_DSA_65=1)
    message(STATUS "ML-DSA-65 enabled")
endif()

# ML-DSA-87 (Dilithium)
if(ENABLE_ML_DSA_87)
    target_sources(app PRIVATE
        ../crypto_sign/ml-dsa-87/clean/sign.c
        ../crypto_sign/ml-dsa-87/clean/packing.c
        ../crypto_sign/ml-dsa-87/clean/polyvec.c
        ../crypto_sign/ml-dsa-87/clean/poly.c
        ../crypto_sign/ml-dsa-87/clean/ntt.c
        ../crypto_sign/ml-dsa-87/clean/reduce.c
        ../crypto_sign/ml-dsa-87/clean/rounding.c
        ../crypto_sign/ml-dsa-87/clean/symmetric-shake.c
    )
    target_include_directories(app PRIVATE ../crypto_sign/ml-dsa-87/clean)
    target_compile_definitions(app PRIVATE ENABLE_ML_DSA_87=1)
    message(STATUS "ML-DSA-87 enabled")
endif()

# Falcon-512
if(ENABLE_FALCON_512)
    target_sources(app PRIVATE
        ../crypto_sign/falcon-512/clean/pqclean.c
        ../crypto_sign/falcon-512/clean/codec.c
        ../crypto_sign/falcon-512/clean/common.c
        ../crypto_sign/falcon-512/clean/fft.c
        ../crypto_sign/falcon-512/clean/fpr.c
        ../crypto_sign/falcon-512/clean/keygen.c
        ../crypto_sign/falcon-512/clean/rng.c
        ../crypto_sign/falcon-512/clean/sign.c
        ../crypto_sign/falcon-512/clean/vrfy.c
    )
    target_include_directories(app PRIVATE ../crypto_sign/falcon-512/clean)
    target_compile_definitions(app PRIVATE ENABLE_FALCON_512=1)
    message(STATUS "Falcon-512 enabled")
endif()

# Falcon-1024
if(ENABLE_FALCON_1024)
    target_sources(app PRIVATE
        ../crypto_sign/falcon-1024/clean/pqclean.c
        ../crypto_sign/falcon-1024/clean/codec.c
        ../crypto_sign/falcon-1024/clean/common.c
        ../crypto_sign/falcon-1024/clean/fft.c
        ../crypto_sign/falcon-1024/clean/fpr.c
        ../crypto_sign/falcon-1024/clean/keygen.c
        ../crypto_sign/falcon-1024/clean/rng.c
        ../crypto_sign/falcon-1024/clean/sign.c
        ../crypto_sign/falcon-1024/clean/vrfy.c
    )
    target_include_directories(app PRIVATE ../crypto_sign/falcon-1024/clean)
    target_compile_definitions(app PRIVATE ENABLE_FALCON_1024=1)
    message(STATUS "Falcon-1024 enabled")
endif()

# Falcon-padded-512
if(ENABLE_FALCON_PADDED_512)
    target_sources(app PRIVATE
        ../crypto_sign/falcon-padded-512/clean/pqclean.c
        ../crypto_sign/falcon-padded-512/clean/codec.c
        ../crypto_sign/falcon-padded-512/clean/common.c
        ../crypto_sign/falcon-padded-512/clean/fft.c
        ../crypto_sign/falcon-padded-512/clean/fpr.c
        ../crypto_sign/falcon-padded-512/clean/keygen.c
        ../crypto_sign/falcon-padded-512/clean/rng.c
        ../crypto_sign/falcon-padded-512/clean/sign.c
        ../crypto_sign/falcon-padded-512/clean/vrfy.c
    )
    target_include_directories(app PRIVATE ../crypto_sign/falcon-padded-512/clean)
    target_compile_definitions(app PRIVATE ENABLE_FALCON_PADDED_512=1)
    message(STATUS "Falcon-padded-512 enabled")
endif()

# Falcon-padded-1024
if(ENABLE_FALCON_PADDED_1024)
    target_sources(app PRIVATE
        ../crypto_sign/falcon-padded-1024/clean/pqclean.c
        ../crypto_sign/falcon-padded-1024/clean/codec.c
        ../crypto_sign/falcon-padded-1024/clean/common.c
        ../crypto_sign/falcon-padded-1024/clean/fft.c
        ../crypto_sign/falcon-padded-1024/clean/fpr.c
        ../crypto_sign/falcon-padded-1024/clean/keygen.c
        ../crypto_sign/falcon-padded-1024/clean/rng.c
        ../crypto_sign/falcon-padded-1024/clean/sign.c
        ../crypto_sign/falcon-padded-1024/clean/vrfy.c
    )
    target_include_directories(app PRIVATE ../crypto_sign/falcon-padded-1024/clean)
    target_compile_definitions(app PRIVATE ENABLE_FALCON_PADDED_1024=1)
    message(STATUS "Falcon-padded-1024 enabled")
endif()

# SPHINCS+ SHA2 128f
if(ENABLE_SPHINCS_SHA2_128F)
    target_sources(app PRIVATE
        ../crypto_sign/sphincs-sha2-128f-simple/clean/sign.c
        ../crypto_sign/sphincs-sha2-128f-simple/clean/address.c
        ../crypto_sign/sphincs-sha2-128f-simple/clean/context_sha2.c
        ../crypto_sign/sphincs-sha2-128f-simple/clean/fors.c
        ../crypto_sign/sphincs-sha2-128f-simple/clean/hash_sha2.c
        ../crypto_sign/sphincs-sha2-128f-simple/clean/merkle.c
        ../crypto_sign/sphincs-sha2-128f-simple/clean/thash_sha2_simple.c
        ../crypto_sign/sphincs-sha2-128f-simple/clean/utils.c
        ../crypto_sign/sphincs-sha2-128f-simple/clean/utilsx1.c
        ../crypto_sign/sphincs-sha2-128f-simple/clean/wots.c
        ../crypto_sign/sphincs-sha2-128f-simple/clean/wotsx1.c
    )
    target_include_directories(app PRIVATE ../crypto_sign/sphincs-sha2-128f-simple/clean)
    target_compile_definitions(app PRIVATE ENABLE_SPHINCS_SHA2_128F=1)
    message(STATUS "SPHINCS+-SHA2-128f-simple enabled")
endif()

# SPHINCS+ SHA2 128s
if(ENABLE_SPHINCS_SHA2_128S)
    target_sources(app PRIVATE
        ../crypto_sign/sphincs-sha2-128s-simple/clean/sign.c
        ../crypto_sign/sphincs-sha2-128s-simple/clean/address.c
        ../crypto_sign/sphincs-sha2-128s-simple/clean/context_sha2.c
        ../crypto_sign/sphincs-sha2-128s-simple/clean/fors.c
        ../crypto_sign/sphincs-sha2-128s-simple/clean/hash_sha2.c
        ../crypto_sign/sphincs-sha2-128s-simple/clean/merkle.c
        ../crypto_sign/sphincs-sha2-128s-simple/clean/thash_sha2_simple.c
        ../crypto_sign/sphincs-sha2-128s-simple/clean/utils.c
        ../crypto_sign/sphincs-sha2-128s-simple/clean/utilsx1.c
        ../crypto_sign/sphincs-sha2-128s-simple/clean/wots.c
        ../crypto_sign/sphincs-sha2-128s-simple/clean/wotsx1.c
    )
    target_include_directories(app PRIVATE ../crypto_sign/sphincs-sha2-128s-simple/clean)
    target_compile_definitions(app PRIVATE ENABLE_SPHINCS_SHA2_128S=1)
    message(STATUS "SPHINCS+-SHA2-128s-simple enabled")
endif()

# SPHINCS+ SHA2 192f
if(ENABLE_SPHINCS_SHA2_192F)
    target_sources(app PRIVATE
        ../crypto_sign/sphincs-sha2-192f-simple/clean/sign.c
        ../crypto_sign/sphincs-sha2-192f-simple/clean/address.c
        ../crypto_sign/sphincs-sha2-192f-simple/clean/context_sha2.c
        ../crypto_sign/sphincs-sha2-192f-simple/clean/fors.c
        ../crypto_sign/sphincs-sha2-192f-simple/clean/hash_sha2.c
        ../crypto_sign/sphincs-sha2-192f-simple/clean/merkle.c
        ../crypto_sign/sphincs-sha2-192f-simple/clean/thash_sha2_simple.c
        ../crypto_sign/sphincs-sha2-192f-simple/clean/utils.c
        ../crypto_sign/sphincs-sha2-192f-simple/clean/utilsx1.c
        ../crypto_sign/sphincs-sha2-192f-simple/clean/wots.c
        ../crypto_sign/sphincs-sha2-192f-simple/clean/wotsx1.c
    )
    target_include_directories(app PRIVATE ../crypto_sign/sphincs-sha2-192f-simple/clean)
    target_compile_definitions(app PRIVATE ENABLE_SPHINCS_SHA2_192F=1)
    message(STATUS "SPHINCS+-SHA2-192f-simple enabled")
endif()

# SPHINCS+ SHA2 192s
if(ENABLE_SPHINCS_SHA2_192S)
    target_sources(app PRIVATE
        ../crypto_sign/sphincs-sha2-192s-simple/clean/sign.c
        ../crypto_sign/sphincs-sha2-192s-simple/clean/address.c
        ../crypto_sign/sphincs-sha2-192s-simple/clean/context_sha2.c
        ../crypto_sign/sphincs-sha2-192s-simple/clean/fors.c
        ../crypto_sign/sphincs-sha2-192s-simple/clean/hash_sha2.c
        ../crypto_sign/sphincs-sha2-192s-simple/clean/merkle.c
        ../crypto_sign/sphincs-sha2-192s-simple/clean/thash_sha2_simple.c
        ../crypto_sign/sphincs-sha2-192s-simple/clean/utils.c
        ../crypto_sign/sphincs-sha2-192s-simple/clean/utilsx1.c
        ../crypto_sign/sphincs-sha2-192s-simple/clean/wots.c
        ../crypto_sign/sphincs-sha2-192s-simple/clean/wotsx1.c
    )
    target_include_directories(app PRIVATE ../crypto_sign/sphincs-sha2-192s-simple/clean)
    target_compile_definitions(app PRIVATE ENABLE_SPHINCS_SHA2_192S=1)
    message(STATUS "SPHINCS+-SHA2-192s-simple enabled")
endif()

# SPHINCS+ SHA2 256f
if(ENABLE_SPHINCS_SHA2_256F)
    target_sources(app PRIVATE
        ../crypto_sign/sphincs-sha2-256f-simple/clean/sign.c
        ../crypto_sign/sphincs-sha2-256f-simple/clean/address.c
        ../crypto_sign/sphincs-sha2-256f-simple/clean/context_sha2.c
        ../crypto_sign/sphincs-sha2-256f-simple/clean/fors.c
        ../crypto_sign/sphincs-sha2-256f-simple/clean/hash_sha2.c
        ../crypto_sign/sphincs-sha2-256f-simple/clean/merkle.c
        ../crypto_sign/sphincs-sha2-256f-simple/clean/thash_sha2_simple.c
        ../crypto_sign/sphincs-sha2-256f-simple/clean/utils.c
        ../crypto_sign/sphincs-sha2-256f-simple/clean/utilsx1.c
        ../crypto_sign/sphincs-sha2-256f-simple/clean/wots.c
        ../crypto_sign/sphincs-sha2-256f-simple/clean/wotsx1.c
    )
    target_include_directories(app PRIVATE ../crypto_sign/sphincs-sha2-256f-simple/clean)
    target_compile_definitions(app PRIVATE ENABLE_SPHINCS_SHA2_256F=1)
    message(STATUS "SPHINCS+-SHA2-256f-simple enabled")
endif()

# SPHINCS+ SHA2 256s
if(ENABLE_SPHINCS_SHA2_256S)
    target_sources(app PRIVATE
        ../crypto_sign/sphincs-sha2-256s-simple/clean/sign.c
        ../crypto_sign/sphincs-sha2-256s-simple/clean/address.c
        ../crypto_sign/sphincs-sha2-256s-simple/clean/context_sha2.c
        ../crypto_sign/sphincs-sha2-256s-simple/clean/fors.c
        ../crypto_sign/sphincs-sha2-256s-simple/clean/hash_sha2.c
        ../crypto_sign/sphincs-sha2-256s-simple/clean/merkle.c
        ../crypto_sign/sphincs-sha2-256s-simple/clean/thash_sha2_simple.c
        ../crypto_sign/sphincs-sha2-256s-simple/clean/utils.c
        ../crypto_sign/sphincs-sha2-256s-simple/clean/utilsx1.c
        ../crypto_sign/sphincs-sha2-256s-simple/clean/wots.c
        ../crypto_sign/sphincs-sha2-256s-simple/clean/wotsx1.c
    )
    target_include_directories(app PRIVATE ../crypto_sign/sphincs-sha2-256s-simple/clean)
    target_compile_definitions(app PRIVATE ENABLE_SPHINCS_SHA2_256S=1)
    message(STATUS "SPHINCS+-SHA2-256s-simple enabled")
endif()

# SPHINCS+ SHAKE 128f
if(ENABLE_SPHINCS_SHAKE_128F)
    target_sources(app PRIVATE
        ../crypto_sign/sphincs-shake-128f-simple/clean/sign.c
        ../crypto_sign/sphincs-shake-128f-simple/clean/address.c
        ../crypto_sign/sphincs-shake-128f-simple/clean/context_shake.c
        ../crypto_sign/sphincs-shake-128f-simple/clean/fors.c
        ../crypto_sign/sphincs-shake-128f-simple/clean/hash_shake.c
        ../crypto_sign/sphincs-shake-128f-simple/clean/merkle.c
        ../crypto_sign/sphincs-shake-128f-simple/clean/thash_shake_simple.c
        ../crypto_sign/sphincs-shake-128f-simple/clean/utils.c
        ../crypto_sign/sphincs-shake-128f-simple/clean/utilsx1.c
        ../crypto_sign/sphincs-shake-128f-simple/clean/wots.c
        ../crypto_sign/sphincs-shake-128f-simple/clean/wotsx1.c
    )
    target_include_directories(app PRIVATE ../crypto_sign/sphincs-shake-128f-simple/clean)
    target_compile_definitions(app PRIVATE ENABLE_SPHINCS_SHAKE_128F=1)
    message(STATUS "SPHINCS+-SHAKE-128f-simple enabled")
endif()

# SPHINCS+ SHAKE 128s
if(ENABLE_SPHINCS_SHAKE_128S)
    target_sources(app PRIVATE
        ../crypto_sign/sphincs-shake-128s-simple/clean/sign.c
        ../crypto_sign/sphincs-shake-128s-simple/clean/address.c
        ../crypto_sign/sphincs-shake-128s-simple/clean/context_shake.c
        ../crypto_sign/sphincs-shake-128s-simple/clean/fors.c
        ../crypto_sign/sphincs-shake-128s-simple/clean/hash_shake.c
        ../crypto_sign/sphincs-shake-128s-simple/clean/merkle.c
        ../crypto_sign/sphincs-shake-128s-simple/clean/thash_shake_simple.c
        ../crypto_sign/sphincs-shake-128s-simple/clean/utils.c
        ../crypto_sign/sphincs-shake-128s-simple/clean/utilsx1.c
        ../crypto_sign/sphincs-shake-128s-simple/clean/wots.c
        ../crypto_sign/sphincs-shake-128s-simple/clean/wotsx1.c
    )
    target_include_directories(app PRIVATE ../crypto_sign/sphincs-shake-128s-simple/clean)
    target_compile_definitions(app PRIVATE ENABLE_SPHINCS_SHAKE_128S=1)
    message(STATUS "SPHINCS+-SHAKE-128s-simple enabled")
endif()

# SPHINCS+ SHAKE 192f
if(ENABLE_SPHINCS_SHAKE_192F)
    target_sources(app PRIVATE
        ../crypto_sign/sphincs-shake-192f-simple/clean/sign.c
        ../crypto_sign/sphincs-shake-192f-simple/clean/address.c
        ../crypto_sign/sphincs-shake-192f-simple/clean/context_shake.c
        ../crypto_sign/sphincs-shake-192f-simple/clean/fors.c
        ../crypto_sign/sphincs-shake-192f-simple/clean/hash_shake.c
        ../crypto_sign/sphincs-shake-192f-simple/clean/merkle.c
        ../crypto_sign/sphincs-shake-192f-simple/clean/thash_shake_simple.c
        ../crypto_sign/sphincs-shake-192f-simple/clean/utils.c
        ../crypto_sign/sphincs-shake-192f-simple/clean/utilsx1.c
        ../crypto_sign/sphincs-shake-192f-simple/clean/wots.c
        ../crypto_sign/sphincs-shake-192f-simple/clean/wotsx1.c
    )
    target_include_directories(app PRIVATE ../crypto_sign/sphincs-shake-192f-simple/clean)
    target_compile_definitions(app PRIVATE ENABLE_SPHINCS_SHAKE_192F=1)
    message(STATUS "SPHINCS+-SHAKE-192f-simple enabled")
endif()

# SPHINCS+ SHAKE 192s
if(ENABLE_SPHINCS_SHAKE_192S)
    target_sources(app PRIVATE
        ../crypto_sign/sphincs-shake-192s-simple/clean/sign.c
        ../crypto_sign/sphincs-shake-192s-simple/clean/address.c
        ../crypto_sign/sphincs-shake-192s-simple/clean/context_shake.c
        ../crypto_sign/sphincs-shake-192s-simple/clean/fors.c
        ../crypto_sign/sphincs-shake-192s-simple/clean/hash_shake.c
        ../crypto_sign/sphincs-shake-192s-simple/clean/merkle.c
        ../crypto_sign/sphincs-shake-192s-simple/clean/thash_shake_simple.c
        ../crypto_sign/sphincs-shake-192s-simple/clean/utils.c
        ../crypto_sign/sphincs-shake-192s-simple/clean/utilsx1.c
        ../crypto_sign/sphincs-shake-192s-simple/clean/wots.c
        ../crypto_sign/sphincs-shake-192s-simple/clean/wotsx1.c
    )
    target_include_directories(app PRIVATE ../crypto_sign/sphincs-shake-192s-simple/clean)
    target_compile_definitions(app PRIVATE ENABLE_SPHINCS_SHAKE_192S=1)
    message(STATUS "SPHINCS+-SHAKE-192s-simple enabled")
endif()

# SPHINCS+ SHAKE 256f
if(ENABLE_SPHINCS_SHAKE_256F)
    target_sources(app PRIVATE
        ../crypto_sign/sphincs-shake-256f-simple/clean/sign.c
        ../crypto_sign/sphincs-shake-256f-simple/clean/address.c
        ../crypto_sign/sphincs-shake-256f-simple/clean/context_shake.c
        ../crypto_sign/sphincs-shake-256f-simple/clean/fors.c
        ../crypto_sign/sphincs-shake-256f-simple/clean/hash_shake.c
        ../crypto_sign/sphincs-shake-256f-simple/clean/merkle.c
        ../crypto_sign/sphincs-shake-256f-simple/clean/thash_shake_simple.c
        ../crypto_sign/sphincs-shake-256f-simple/clean/utils.c
        ../crypto_sign/sphincs-shake-256f-simple/clean/utilsx1.c
        ../crypto_sign/sphincs-shake-256f-simple/clean/wots.c
        ../crypto_sign/sphincs-shake-256f-simple/clean/wotsx1.c
    )
    target_include_directories(app PRIVATE ../crypto_sign/sphincs-shake-256f-simple/clean)
    target_compile_definitions(app PRIVATE ENABLE_SPHINCS_SHAKE_256F=1)
    message(STATUS "SPHINCS+-SHAKE-256f-simple enabled")
endif()

# SPHINCS+ SHAKE 256s
if(ENABLE_SPHINCS_SHAKE_256S)
    target_sources(app PRIVATE
        ../crypto_sign/sphincs-shake-256s-simple/clean/sign.c
        ../crypto_sign/sphincs-shake-256s-simple/clean/address.c
        ../crypto_sign/sphincs-shake-256s-simple/clean/context_shake.c
        ../crypto_sign/sphincs-shake-256s-simple/clean/fors.c
        ../crypto_sign/sphincs-shake-256s-simple/clean/hash_shake.c
        ../crypto_sign/sphincs-shake-256s-simple/clean/merkle.c
        ../crypto_sign/sphincs-shake-256s-simple/clean/thash_shake_simple.c
        ../crypto_sign/sphincs-shake-256s-simple/clean/utils.c
        ../crypto_sign/sphincs-shake-256s-simple/clean/utilsx1.c
        ../crypto_sign/sphincs-shake-256s-simple/clean/wots.c
        ../crypto_sign/sphincs-shake-256s-simple/clean/wotsx1.c
    )
    target_include_directories(app PRIVATE ../crypto_sign/sphincs-shake-256s-simple/clean)
    target_compile_definitions(app PRIVATE ENABLE_SPHINCS_SHAKE_256S=1)
    message(STATUS "SPHINCS+-SHAKE-256s-simple enabled")
endif()

# Print comprehensive configuration summary
message(STATUS "")
message(STATUS "===============================================")
message(STATUS "PQClean Comprehensive KEM Configuration:")
message(STATUS "===============================================")
message(STATUS "ML-KEM Family:")
message(STATUS "  ML-KEM-512:  ${ENABLE_ML_KEM_512}")
message(STATUS "  ML-KEM-768:  ${ENABLE_ML_KEM_768}")
message(STATUS "  ML-KEM-1024: ${ENABLE_ML_KEM_1024}")
message(STATUS "")
message(STATUS "HQC Family:")
message(STATUS "  HQC-128: ${ENABLE_HQC_128}")
message(STATUS "  HQC-192: ${ENABLE_HQC_192}")
message(STATUS "  HQC-256: ${ENABLE_HQC_256}")
message(STATUS "")
message(STATUS "McEliece Family (Large Memory):")
message(STATUS "  McEliece 348864:  ${ENABLE_MCELIECE_348864}")
message(STATUS "  McEliece 348864f: ${ENABLE_MCELIECE_348864F}")
message(STATUS "  McEliece 460896:  ${ENABLE_MCELIECE_460896}")
message(STATUS "  McEliece 460896f: ${ENABLE_MCELIECE_460896F}")
message(STATUS "  McEliece 6688128: ${ENABLE_MCELIECE_6688128}")
message(STATUS "  McEliece 6688128f: ${ENABLE_MCELIECE_6688128F}")
message(STATUS "  McEliece 6960119: ${ENABLE_MCELIECE_6960119}")
message(STATUS "  McEliece 6960119f: ${ENABLE_MCELIECE_6960119F}")
message(STATUS "  McEliece 8192128: ${ENABLE_MCELIECE_8192128}")
message(STATUS "  McEliece 8192128f: ${ENABLE_MCELIECE_8192128F}")
message(STATUS "===============================================")
message(STATUS "")
message(STATUS "===============================================")
message(STATUS "PQClean Comprehensive DSA Configuration:")
message(STATUS "===============================================")
message(STATUS "ML-DSA (Dilithium) Family:")
message(STATUS "  ML-DSA-44:  ${ENABLE_ML_DSA_44}")
message(STATUS "  ML-DSA-65:  ${ENABLE_ML_DSA_65}")
message(STATUS "  ML-DSA-87:  ${ENABLE_ML_DSA_87}")
message(STATUS "")
message(STATUS "Falcon Family:")
message(STATUS "  Falcon-512:        ${ENABLE_FALCON_512}")
message(STATUS "  Falcon-1024:       ${ENABLE_FALCON_1024}")
message(STATUS "  Falcon-padded-512: ${ENABLE_FALCON_PADDED_512}")
message(STATUS "  Falcon-padded-1024: ${ENABLE_FALCON_PADDED_1024}")
message(STATUS "")
message(STATUS "SPHINCS+ SHA2 Family:")
message(STATUS "  SHA2-128f: ${ENABLE_SPHINCS_SHA2_128F}")
message(STATUS "  SHA2-128s: ${ENABLE_SPHINCS_SHA2_128S}")
message(STATUS "  SHA2-192f: ${ENABLE_SPHINCS_SHA2_192F}")
message(STATUS "  SHA2-192s: ${ENABLE_SPHINCS_SHA2_192S}")
message(STATUS "  SHA2-256f: ${ENABLE_SPHINCS_SHA2_256F}")
message(STATUS "  SHA2-256s: ${ENABLE_SPHINCS_SHA2_256S}")
message(STATUS "")
message(STATUS "SPHINCS+ SHAKE Family:")
message(STATUS "  SHAKE-128f: ${ENABLE_SPHINCS_SHAKE_128F}")
message(STATUS "  SHAKE-128s: ${ENABLE_SPHINCS_SHAKE_128S}")
message(STATUS "  SHAKE-192f: ${ENABLE_SPHINCS_SHAKE_192F}")
message(STATUS "  SHAKE-192s: ${ENABLE_SPHINCS_SHAKE_192S}")
message(STATUS "  SHAKE-256f: ${ENABLE_SPHINCS_SHAKE_256F}")
message(STATUS "  SHAKE-256s: ${ENABLE_SPHINCS_SHAKE_256S}")
message(STATUS "===============================================")
message(STATUS "Note: McEliece algorithms require >250KB RAM for keys")
message(STATUS "Enable with caution on memory-constrained targets")
message(STATUS "===============================================")
