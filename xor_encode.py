import argparse

def main():
    parser = argparse.ArgumentParser(description = "XOR encrypt/decrypt")
    parser.add_argument(
        "--file", 
        required=True, 
        help="File path to process"
    )
    parser.add_argument(
        "--key", 
        default=0x42, 
        type=lambda x: int(x, 0), 
        help="XOR key (example: 5, 0x5A, 255, etc.)"
    )
    parser.add_argument(
        "--out",
        default="xored.bin",
        help="Output file (default: output.bin)"
    )
    args=parser.parse_args()

    with open(args.file, "rb") as f:
        data = bytearray(f.read())

    encrypted = bytearray([b ^ args.key for b in data])

    with open(args.out, "wb") as f:
        f.write(encrypted)

    print(f"File processed with XOR key {hex(args.key)}.")
    print(f"Output written to: {args.out}")

if __name__ == "__main__":
    main()