#! /usr/bin/env python3
## BETYBYTE'S CLIMA GAMES .PAK FILE UNPACKER
## PAK SPECIFICATION:
# - 4 bytes: "PAK\x00" magic
# - 1 byte: Unknown
# - 1 byte: file revision/version (observed values: 3-5, but most files have 3)
# - 1 byte: file count (N)
# - For each file:
#   - 1 byte: filename length (L)
#   - L bytes: filename (latin-1)
#   - 4 bytes: file size (S)
#   - 4 bytes: unknown (checksum or flags)
# - Followed by file data for each file in order

import os
import struct
from enum import Enum
import zlib
import argparse
import logging

logging.basicConfig(
    filename="unpacker.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logging.getLogger().addHandler(logging.StreamHandler())

class Mode(Enum):
    LIST = 1
    EXTRACT = 2

if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description="Unpack .pak files from BetyByte's Clima games")
    
    group = argparser.add_mutually_exclusive_group(required=True)
    group.add_argument("-l", "--list", action="store_true", help="List contents")
    group.add_argument("-x", "--extract", action="store_true", help="Extract files")
    
    argparser.add_argument("-i","--pakfile",help="Path to the .pak file to unpack")
    argparser.add_argument("-o","--output", help="Output directory (default: <pakfile>_extracted)", default=None)
    argparser.add_argument('-c','--convert', action="store_true", help="Rename known files to compatible filetype if they have the correct magic (e.g. .bin files with SWF magic will be renamed to .swf)")
    argparser.add_argument("-d", "--directory", help="Directory to search for .pak files (default: current directory)", default=".")
    argparser.add_argument("-r",'--recursive',  action="store_true", help="Recursively search for .pak files in the current directory and subdirectories")
    
    args = argparser.parse_args()
    if args.directory and args.pakfile:
        argparser.error("You cannot specify both --directory and --pakfile")
    if not args.recursive and not args.pakfile:
        argparser.error("You must specify --pakfile unless using --recursive")

def process_pak(pakfile, list_or_extract, output_dir=None, convert=False):
    def parse_directory(data) -> tuple[list[tuple[str, int, int]], int]:
        file_count = struct.unpack_from("<B", data, 0)[0]
        pos = 1
        files = []
        for _ in range(file_count):
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

    def extract_files(pakfilename, entries, data, output_dir=None, convert=False):
        offset = 0
        if output_dir is None:
            output_dir = pakfilename + "_extracted"
        os.makedirs(output_dir, exist_ok=True)

        for filename, size, _ in entries:
            
            if offset + size > len(data):
                logging.error("Corrupt PAK: file size exceeds archive bounds")
                break

            filedata = data[offset:offset+size]
            print(f"Processing: {filename} (size: {size} bytes)")
            # Detect zlib
            if filedata.startswith(b"\x78\x9C") or filedata.startswith(b"\x78\xDA"):
                try:
                    filedata = zlib.decompress(filedata)
                except zlib.error as e:
                    logging.warning(f"[!] Decompression failed: {pakfilename} {filename} ({e})")
                    continue

            if convert:
                if filename.endswith(".bin"):
                    if filedata[:3] == b"FWS" or filedata[:3] == b"CWS" or filedata[:3] == b"ZWS":
                        filename = filename[:-4] + ".swf"
                    else:
                        with open("unknown_magic.txt", "a") as myfile:
                            myfile.write(f"{pakfilename} {filename}: {filedata[:4]}\n")

                if filename.endswith(".a"):
                    filename = filename[:-2] + ".swf"
                    
            out_path = os.path.join(output_dir, filename)
            logging.info(f"Extracting: {filename}, in {out_path} (size: {size} bytes)")
            with open(out_path, "wb") as out:
                out.write(filedata)

            logging.info(f"[OK] Extracted: {filename}")
            offset += size

    HEADER_SIZE = 6

    def list_files(entries):
        for filename, size, _ in entries:
            logging.info(f"- {filename} ({size} bytes)")

    with open(pakfile, "rb") as f:
            data = f.read()

    if data[:4] != b"PAK\x00":
        if data[:2] == b"\x78\xDA":
            match Mode(list_or_extract):
                case Mode.LIST:
                    logging.info(f"Detected zlib-compressed .pak file: {pakfile}, listing as single entry")
                case Mode.EXTRACT:
                    extract_files(os.path.basename(pakfile), 
                                [[os.path.basename(pakfile)[:4]+".bin",len(data),0]], 
                                data,
                                output_dir, 
                                convert)
        else:
            print("Not a valid .pak file")
        return
    
    unknown = struct.unpack_from("<B", data, 4)[0]
    version = struct.unpack_from("<B", data, 5)[0]
    logging.info(f"PAK file Version: {version}, Unknown: {unknown}")

    entries, offset = parse_directory(data[HEADER_SIZE:])
    logging.info(f"Found {len(entries)} files in the .pak")

    match Mode(list_or_extract):
        case Mode.LIST:
            list_files(entries)
        case Mode.EXTRACT:
            extract_files(os.path.basename(pakfile), entries, data[HEADER_SIZE+offset:], output_dir, convert)

def walk_directory(directory,output, mode, convert=False):
    base = output or "output"
    for dirpath, _, fnames in os.walk(directory):
        for file in fnames:
            if file.endswith(".pak"):
                logging.info(f"\nProcessing .pak file: {os.path.join(dirpath, file)}")
                process_pak(os.path.join(dirpath, file), 
                            mode, 
                            os.path.join(base, os.path.splitext(file)[0]), 
                            convert
                            )

def main(args):
    if args.list:
        mode = Mode.LIST
    else:        
        mode = Mode.EXTRACT

    if args.recursive:
        walk_directory(args.directory,args.output, mode, args.convert)
    else:
        process_pak(args.pakfile, mode, args.output, args.convert)

if __name__ == "__main__":
    main(args)