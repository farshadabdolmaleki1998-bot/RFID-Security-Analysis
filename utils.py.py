"""
Utility functions and constants for RFID protocol simulations
"""

def simulate_EPC_tag():
    """
    Simulate EPC Gen2 tag memory constraints
    Returns: Dictionary with tag specifications
    """
    return {
        'total_memory': 512,      # bits
        'epc_size': 96,           # bits (EPC number)
        'epc_working': 16,        # bits (working EPC size)
        'password_size': 32,      # bits (access/kill passwords)
        'ids_size': 16,           # bits (session ID size)
        'random_size': 16         # bits (random number size)
    }

def print_memory_usage():
    """Display memory usage analysis for EPC Gen2 tags"""
    tag_spec = simulate_EPC_tag()
    print("=== EPC Gen2 Tag Memory Analysis ===")
    for key, value in tag_spec.items():
        print(f"{key}: {value} bits ({value/8} bytes)")
    
    total_bits = sum(tag_spec.values())
    print(f"\nTotal estimated memory: {total_bits} bits ({total_bits/8} bytes)")

def hex_format(value, bits=16):
    """Format value as hexadecimal with specified bit width"""
    return f"0x{value:0{bits//4}X}"

if __name__ == "__main__":
    print_memory_usage()