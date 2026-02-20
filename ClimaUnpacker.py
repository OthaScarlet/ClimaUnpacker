#! /usr/bin/env python3
import os
import struct
import zlib
import argparse

argparser = argparse.ArgumentParser(description="Unpack .pak files from BetyByte's Clima games")
argparser.add_argument("-i","--pakfile",help="Path to the .pak file to unpack")
argparser.add_argument("-o","--output", help="Output directory (default: <pakfile>_extracted)", default=None)
argparser.add_argument('-c','--convert', action=argparse.BooleanOptionalAction)
argparser.add_argument("-r",'--recursive', action=argparse.BooleanOptionalAction)
args = argparser.parse_args()

def parse_directory(data):
    fileCount  = data[6]
    pos = 7
    files = []
    for x in range(fileCount):
        name_len = data[pos]
        pos += 1
        
        filename = data[pos:pos+name_len].decode("latin-1")
        pos += name_len
        
        size = struct.unpack("<I", data[pos:pos+4])[0]
        pos += 4
        
        isAChecksum = struct.unpack("<I", data[pos:pos+4])[0]
        pos += 4
        
        files.append((filename, size, isAChecksum))
    return files, pos

def extract_files(pakfile, output_dir=None, convert=False):
    
    with open(pakfile, "rb") as f:
        data = f.read()
    if data[:2] != b"\x78\xDA":
        entries, data_start = parse_directory(data)

        print(f"Directory size: {data_start - 8}")
        print(f"Data section starts at: {hex(data_start)}")
        print(f"Found {len(entries)} files\n")
        offset = data_start
    else:
        print(f"[!] No directory found, treating entire file as data")
        entries = [(os.path.basename(pakfile)+".bin", len(data), 0)]
        offset = 0
        
    if output_dir is None:
        output_dir = os.path.splitext(pakfile)[0] + "_extracted"
    os.makedirs(output_dir, exist_ok=True)

    for filename, size, _ in entries:
        filedata = data[offset:offset+size]

        # Detect zlib
        if filedata[:2] == b"\x78\x9C":
            try:
                filedata = zlib.decompress(filedata)
                print(f"[+] Decompressed: {filename}")
            except Exception as e:
                print(f"[!] Decompression failed: {filename} ({e})")
                with open("log.txt", "a") as myfile:
                    myfile.write(f"[!] Decompression failed: {pakfile} {filename} ({e})\n")
                continue

        if convert:
            if filename.endswith(".bin"):
                if filedata[:4] == b"FWS\x00" or filedata[:4] == b"CWS\x00":
                    filename = filename[:-4] + ".swf"
            if filename.endswith(".a"):
                filename = filename[:-2] + ".swf"
                
        out_path = os.path.join(output_dir, filename)
        print(f"Extracting: {filename}, in {out_path} (size: {size} bytes)")
        with open(out_path, "wb") as out:
            out.write(filedata)

        print(f"[OK] Extracted: {filename}")
        offset += size

    print("\nDone.")

def walk_directory(output, convert=False):
    for dirpath, dnames, fnames in os.walk("./"):
        for f in fnames:
            if f.endswith(".pak"):
                extract_files(os.path.join(dirpath, f), os.path.join(output,f), convert)

if args.recursive:
    walk_directory(args.output, args.convert)
else:
    extract_files(args.pakfile, args.output, args.convert)