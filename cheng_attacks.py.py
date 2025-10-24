"""
EPC Disclosure and Tracking Attacks on Cheng's Protocol
Corresponding to Algorithms 1 & 2 in the paper
"""

import time
import random
from Crypto.Hash import SHA256

def PRNG(x):
    """Lightweight PRNG simulation for EPC Gen2 constraints"""
    return int(SHA256.new(str(x).encode()).hexdigest()[:4], 16)

def EPC_attack(B, C, D, RndR, N):
    """
    Algorithm 1: EPC Disclosure Attack
    Input: Messages B, C, D, RndR; Known N
    Output: EPC value and execution time
    """
    start_time = time.time()
    RT2 = C ^ PRNG(N ^ RndR)
    
    # Brute force search through 16-bit EPC space
    for EPC_guess in range(0x10000):
        if D == PRNG(N ^ RT2 ^ EPC_guess ^ RndR):
            execution_time = time.time() - start_time
            return EPC_guess, execution_time
    return None, None

def trace_attack(IDS_old, RT2):
    """
    Algorithm 2: Tag Tracking Attack  
    Input: Old IDS, RT2
    Output: Predicted new IDS
    """
    return PRNG(IDS_old ^ RT2)

def simulate_cheng_attacks():
    """Comprehensive simulation of both attacks on Cheng's protocol"""
    print("=== Cheng Protocol Attack Simulations ===")
    
    # Test parameters
    N = 0x4A2F
    RndR = 0xB3D8 
    EPC_real = 0x8C31
    RT1 = 0x1E4A
    RT2 = 0x9F7B
    
    # Generate protocol messages
    B_val = PRNG(N ^ RT1 ^ EPC_real ^ RndR)
    C_val = PRNG(N ^ RndR) ^ RT2
    D_val = PRNG(N ^ RT2 ^ EPC_real ^ RndR)
    
    # Execute EPC disclosure attack
    print("\n1. EPC Disclosure Attack (Algorithm 1):")
    EPC_found, exec_time = EPC_attack(B_val, C_val, D_val, RndR, N)
    print(f"   Real EPC: {hex(EPC_real)}")
    print(f"   Found EPC: {hex(EPC_found)}")
    print(f"   Execution Time: {exec_time:.3f} seconds")
    print(f"   Success: {EPC_found == EPC_real}")
    
    # Execute tracking attack
    print("\n2. Tag Tracking Attack (Algorithm 2):")
    IDS_old = 0xABCD
    IDS_new_real = PRNG(IDS_old ^ RT2)
    IDS_new_pred = trace_attack(IDS_old, RT2)
    print(f"   Old IDS: {hex(IDS_old)}")
    print(f"   Real New IDS: {hex(IDS_new_real)}") 
    print(f"   Predicted New IDS: {hex(IDS_new_pred)}")
    print(f"   Success: {IDS_new_real == IDS_new_pred}")

if __name__ == "__main__":
    simulate_cheng_attacks()