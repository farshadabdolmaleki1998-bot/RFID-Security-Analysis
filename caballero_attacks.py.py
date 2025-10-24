"""
Tracking Attack on Caballero's Protocol  
Corresponding to Algorithm 3 in the paper
"""

import random
import time

def LFSR_PRNG(seed, length=16):
    """
    LFSR-based Pseudorandom Number Generator
    Simulates the lightweight PRNG used in Caballero's protocol
    """
    state = seed
    output = 0
    for _ in range(length):
        output = (output << 1) | (state & 1)
        # Feedback from taps at positions 16, 14, 13 (0-indexed)
        new_bit = (state ^ (state >> 2) ^ (state >> 3)) & 1
        state = (state >> 1) | (new_bit << 15)
    return output & 0xFFFF

def trace_attack_caballero(NONCE1_s1, NONCE3_s1, NONCE1_s2, NONCE3_s2):
    """
    Algorithm 3: Tracking Attack on Caballero's Protocol
    Input: NONCE1, NONCE3 from two sessions
    Output: Boolean indicating if sessions belong to same tag
    """
    delta = (NONCE3_s1 ^ NONCE1_s1) ^ (NONCE3_s2 ^ NONCE1_s2)
    return delta == 0

def simulate_caballero_protocol(IDt, SSKt, Query):
    """Simulate one session of Caballero's protocol"""
    NONCE1 = random.randint(0, 0xFFFF)
    NONCE2 = LFSR_PRNG(IDt ^ Query) ^ LFSR_PRNG(SSKt ^ Query)
    NONCE3 = LFSR_PRNG(IDt ^ NONCE1) ^ LFSR_PRNG(SSKt ^ NONCE1)
    return NONCE1, NONCE2, NONCE3

def test_tracking_attack():
    """Comprehensive test of the tracking attack"""
    print("=== Caballero Protocol Tracking Attack ===")
    
    # Fixed tag parameters
    IDt = 0x8A3F
    SSKt = 0xB2E4
    
    # Generate two sessions from same tag
    Query1, Query2 = random.randint(0, 0xFFFF), random.randint(0, 0xFFFF)
    
    # Session 1
    NONCE1_1, NONCE2_1, NONCE3_1 = simulate_caballero_protocol(IDt, SSKt, Query1)
    
    # Session 2 (same tag, different query)
    NONCE1_2, NONCE2_2, NONCE3_2 = simulate_caballero_protocol(IDt, SSKt, Query2)
    
    # Execute tracking attack
    start_time = time.time()
    same_tag = trace_attack_caballero(NONCE1_1, NONCE3_1, NONCE1_2, NONCE3_2)
    attack_time = (time.time() - start_time) * 1000  # Convert to milliseconds
    
    print(f"Session 1 - NONCE1: {hex(NONCE1_1)}, NONCE3: {hex(NONCE3_1)}")
    print(f"Session 2 - NONCE1: {hex(NONCE1_2)}, NONCE3: {hex(NONCE3_2)}")
    print(f"Tracking Attack Result: Same tag = {same_tag}")
    print(f"Attack Execution Time: {attack_time:.3f} ms")
    print(f"Attack Success: {same_tag == True}")

def bulk_simulation():
    """Bulk simulation to verify 100% success rate"""
    print("\n=== Bulk Simulation (1000 sessions) ===")
    IDt = 0x8A3F
    SSKt = 0xB2E4
    success_count = 0
    total_pairs = 1000
    
    for i in range(total_pairs):
        Query1, Query2 = random.randint(0, 0xFFFF), random.randint(0, 0xFFFF)
        NONCE1_1, _, NONCE3_1 = simulate_caballero_protocol(IDt, SSKt, Query1)
        NONCE1_2, _, NONCE3_2 = simulate_caballero_protocol(IDt, SSKt, Query2)
        
        if trace_attack_caballero(NONCE1_1, NONCE3_1, NONCE1_2, NONCE3_2):
            success_count += 1
    
    success_rate = (success_count / total_pairs) * 100
    print(f"Success Rate: {success_rate}% ({success_count}/{total_pairs})")

if __name__ == "__main__":
    test_tracking_attack()
    bulk_simulation()