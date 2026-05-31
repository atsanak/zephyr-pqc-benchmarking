#!/usr/bin/env python3
"""Quick overview of unified_benchmark_results.csv"""
import csv
from collections import Counter

with open('../unified_benchmark_results.csv') as f:
    reader = csv.DictReader(f)
    rows = list(reader)

print(f"Total rows: {len(rows)}")

# Unique algorithms
algos = sorted(set(r['Algorithm'] for r in rows))
print(f"\n=== ALGORITHMS ({len(algos)}) ===")
for a in algos:
    print(f"  {a}")

# Unique ISAs
isas = sorted(set(r['ISA'] for r in rows))
print(f"\n=== ISAs ({len(isas)}) ===")
for i in isas:
    print(f"  {i}")

# Unique operations
ops = sorted(set(r['Operation'] for r in rows))
print(f"\n=== OPERATIONS ({len(ops)}) ===")
for o in ops:
    print(f"  {o}")

# Unique algorithm types
types = sorted(set(r['Algorithm_Type'] for r in rows))
print(f"\n=== ALGORITHM TYPES ({len(types)}) ===")
for t in types:
    print(f"  {t}")

# FIPS Standards
fips = sorted(set(r['FIPS_Standard'] for r in rows))
print(f"\n=== FIPS STANDARDS ({len(fips)}) ===")
for f_ in fips:
    print(f"  {f_}")

# Variants
variants = sorted(set(r['Variant'] for r in rows))
print(f"\n=== VARIANTS ({len(variants)}) ===")
for v in variants:
    print(f"  {v}")

# Count by type
type_counts = Counter(r['Algorithm_Type'] for r in rows)
print("\n=== ROWS BY TYPE ===")
for t, c in type_counts.most_common():
    print(f"  {t}: {c}")

# Count by ISA
isa_counts = Counter(r['ISA'] for r in rows)
print("\n=== ROWS BY ISA ===")
for i, c in sorted(isa_counts.items()):
    print(f"  {i}: {c}")

# Count by Algorithm
algo_counts = Counter(r['Algorithm'] for r in rows)
print("\n=== ROWS BY ALGORITHM ===")
for a, c in algo_counts.most_common():
    print(f"  {a}: {c}")

# Count by Operation
op_counts = Counter(r['Operation'] for r in rows)
print("\n=== ROWS BY OPERATION ===")
for o, c in op_counts.most_common():
    print(f"  {o}: {c}")

# Check for zero/NaN in critical columns
critical_cols = ['Avg_Cycles', 'Energy_uJ', 'CoeffVar_pct', 'Entropy_Success_pct']
print("\n=== DATA QUALITY CHECK ===")
for col in critical_cols:
    zeros = sum(1 for r in rows if r.get(col, '') == '0' or r.get(col, '') == '0.0')
    empty = sum(1 for r in rows if r.get(col, '') == '' or r.get(col, '') == 'NaN')
    negative = sum(1 for r in rows if r.get(col, '') and r[col] not in ('', 'NaN') and float(r[col]) < 0)
    print(f"  {col}: zeros={zeros}, empty/NaN={empty}, negative={negative}")

# Key sizes sample
print("\n=== KEY SIZES (unique PK_Bytes) ===")
pk_sizes = sorted(set(int(r['PK_Bytes']) for r in rows))
print(f"  {pk_sizes}")

# Energy range
energies = [float(r['Energy_uJ']) for r in rows if r['Energy_uJ'] and r['Energy_uJ'] != 'NaN']
print(f"\n=== ENERGY RANGE ===")
print(f"  Min: {min(energies):.3f} uJ")
print(f"  Max: {max(energies):.3f} uJ")
print(f"  Count: {len(energies)}")

# CV range
cvs = [float(r['CoeffVar_pct']) for r in rows if r['CoeffVar_pct'] and r['CoeffVar_pct'] != 'NaN']
print(f"\n=== COEFF OF VARIATION RANGE ===")
print(f"  Min: {min(cvs):.6f}%")
print(f"  Max: {max(cvs):.6f}%")

# TAF range
tafs = [float(r['Tail_Amplification_Factor']) for r in rows if r['Tail_Amplification_Factor'] and r['Tail_Amplification_Factor'] != 'NaN' and float(r['Tail_Amplification_Factor']) > 0]
print(f"\n=== TAIL AMPLIFICATION FACTOR RANGE ===")
print(f"  Min: {min(tafs):.6f}")
print(f"  Max: {max(tafs):.6f}")
print(f"  Count: {len(tafs)}")

# TEE non-zero check
tee_nonzero = sum(1 for r in rows if r.get('TEE_Mode', '0') not in ('0', '', 'none'))
print(f"\n=== TEE MODE non-zero rows: {tee_nonzero} ===")

# Failure rates
f128 = [float(r['Failure_128KB_pct']) for r in rows if r['Failure_128KB_pct'] and r['Failure_128KB_pct'] != 'NaN']
f64 = [float(r['Failure_64KB_pct']) for r in rows if r['Failure_64KB_pct'] and r['Failure_64KB_pct'] != 'NaN']
print(f"\n=== MEMORY FAILURE RATES ===")
print(f"  128KB cap: min={min(f128):.2f}%, max={max(f128):.2f}%, >0 count={sum(1 for x in f128 if x > 0)}")
print(f"  64KB cap:  min={min(f64):.2f}%, max={max(f64):.2f}%, >0 count={sum(1 for x in f64 if x > 0)}")

# Stack usage
stacks = [int(r['Stack_Used_Bytes']) for r in rows if r['Stack_Used_Bytes'] and r['Stack_Used_Bytes'] != 'NaN']
print(f"\n=== STACK USAGE ===")
print(f"  Min: {min(stacks)} bytes")
print(f"  Max: {max(stacks)} bytes")
print(f"  Zeros: {sum(1 for s in stacks if s == 0)}")

# Entropy success
ent = [float(r['Entropy_Success_pct']) for r in rows if r['Entropy_Success_pct'] and r['Entropy_Success_pct'] != 'NaN']
print(f"\n=== ENTROPY SUCCESS ===")
print(f"  Min: {min(ent):.2f}%")
print(f"  Max: {max(ent):.2f}%")
print(f"  <100%: {sum(1 for e in ent if e < 100)}")

# RNG Failures
rng_f = [int(r['RNG_Failures']) for r in rows if r['RNG_Failures'] and r['RNG_Failures'] != 'NaN']
print(f"\n=== RNG FAILURES ===")
print(f"  Max: {max(rng_f)}")
print(f"  >0 count: {sum(1 for x in rng_f if x > 0)}")
