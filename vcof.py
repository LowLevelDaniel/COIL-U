#!/usr/bin/env python3
"""
COIL Object Format (COF) Verification Tool

This script verifies that a COIL binary file conforms to the COIL 1.0.0 specification.
It checks the header structure, section headers, and basic content validity.
"""

import sys
import struct
import os

def print_hex_dump(data, start_offset=0, bytes_per_line=16):
    """Print a hexdump of the data."""
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i+bytes_per_line]
        hex_values = ' '.join(f'{b:02X}' for b in chunk)
        ascii_values = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        print(f"{start_offset+i:08X}: {hex_values:<{bytes_per_line*3}} {ascii_values}")

def validate_cof_header(data):
    """Validate COF header structure."""
    if len(data) < 32:
        print("❌ File too small to contain a valid COF header")
        return False
    
    # Read magic number
    magic = struct.unpack("<I", data[0:4])[0]
    magic_bytes = data[0:4]
    magic_ascii = ''.join(chr(b) for b in magic_bytes)
    
    print(f"Magic number: 0x{magic:08X} (ASCII: '{magic_ascii}')")
    if magic != 0x4C494F43:  # 'COIL'
        print(f"❌ Invalid magic number. Expected 0x434F494C ('COIL'), got 0x{magic:08X} ('{magic_ascii}')")
        return False
    else:
        print("✅ Magic number verified: 'COIL'")
    
    # Unpack header fields
    # struct cof_header {
    #     uint32_t magic;         // Magic number: 'COIL' (0x434F494C)
    #     uint8_t  version_major; // Major version (1 for COIL 1.0.0)
    #     uint8_t  version_minor; // Minor version (0 for COIL 1.0.0)
    #     uint8_t  version_patch; // Patch version (0 for COIL 1.0.0)
    #     uint8_t  flags;         // Global flags
    #     uint16_t target;        // Target architecture
    #     uint16_t section_count; // Number of sections
    #     uint32_t entrypoint;    // Offset to entrypoint (0 if none)
    #     uint32_t str_tab_off;   // Offset to string table
    #     uint32_t str_tab_size;  // Size of string table
    #     uint32_t sym_tab_off;   // Offset to symbol table
    #     uint32_t sym_tab_size;  // Size of symbol table
    #     uint8_t  padding[8];    // Padding to align to 32 bytes
    # };
    version_major = data[4]
    version_minor = data[5]
    version_patch = data[6]
    flags = data[7]
    target = struct.unpack("<H", data[8:10])[0]
    section_count = struct.unpack("<H", data[10:12])[0]
    entrypoint = struct.unpack("<I", data[12:16])[0]
    str_tab_off = struct.unpack("<I", data[16:20])[0]
    str_tab_size = struct.unpack("<I", data[20:24])[0]
    sym_tab_off = struct.unpack("<I", data[24:28])[0]
    sym_tab_size = struct.unpack("<I", data[28:32])[0]
    
    print(f"Version: {version_major}.{version_minor}.{version_patch}")
    print(f"Flags: 0x{flags:02X}")
    print(f"Target architecture: 0x{target:04X}")
    print(f"Section count: {section_count}")
    print(f"Entrypoint offset: 0x{entrypoint:08X}")
    print(f"String table offset: 0x{str_tab_off:08X}")
    print(f"String table size: 0x{str_tab_size:08X}")
    print(f"Symbol table offset: 0x{sym_tab_off:08X}")
    print(f"Symbol table size: 0x{sym_tab_size:08X}")
    
    # Verify version
    if version_major != 1 or version_minor != 0 or version_patch != 0:
        print(f"❌ Invalid version. Expected 1.0.0, got {version_major}.{version_minor}.{version_patch}")
        return False
    else:
        print("✅ Version verified: 1.0.0")
    
    # Verify flags
    valid_flags = 0x0F  # All valid flags: 0x01 | 0x02 | 0x04 | 0x08
    if flags & ~valid_flags:
        print(f"❌ Invalid flags. Contains undefined flags: 0x{flags & ~valid_flags:02X}")
    else:
        print("✅ Flags verified")
    
    # Verify target
    valid_targets = [0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006]
    if target not in valid_targets:
        print(f"❌ Invalid target architecture: 0x{target:04X}")
    else:
        print("✅ Target architecture verified")
    
    # Verify section count
    if section_count == 0:
        print("❌ Invalid section count: 0")
    else:
        print(f"✅ Section count verified: {section_count}")
    
    # Verify offsets are within file
    file_size = len(data)
    
    if entrypoint != 0 and entrypoint >= file_size:
        print(f"❌ Entrypoint offset (0x{entrypoint:08X}) is beyond file size (0x{file_size:08X})")
    
    if str_tab_off != 0:
        if str_tab_off >= file_size:
            print(f"❌ String table offset (0x{str_tab_off:08X}) is beyond file size (0x{file_size:08X})")
        elif str_tab_off + str_tab_size > file_size:
            print(f"❌ String table (0x{str_tab_off:08X} + 0x{str_tab_size:08X}) extends beyond file size (0x{file_size:08X})")
        else:
            print("✅ String table offset and size verified")
    
    if sym_tab_off != 0:
        if sym_tab_off >= file_size:
            print(f"❌ Symbol table offset (0x{sym_tab_off:08X}) is beyond file size (0x{file_size:08X})")
        elif sym_tab_off + sym_tab_size > file_size:
            print(f"❌ Symbol table (0x{sym_tab_off:08X} + 0x{sym_tab_size:08X}) extends beyond file size (0x{file_size:08X})")
        else:
            print("✅ Symbol table offset and size verified")
    
    return True

def validate_section_headers(data, section_count):
    """Validate section header structures."""
    if section_count == 0:
        return
    
    # Starting offset for section headers
    section_header_offset = 32  # Right after COF header
    
    for i in range(section_count):
        offset = section_header_offset + i * 36
        
        if offset + 36 > len(data):
            print(f"❌ Section header {i+1} extends beyond file size")
            return
        
        # Unpack section header fields
        # struct cof_section_header {
        #     uint32_t name_offset;   // Offset into string table for section name
        #     uint32_t type;          // Section type
        #     uint32_t flags;         // Section flags
        #     uint32_t offset;        // Offset from start of file to section data
        #     uint32_t size;          // Size of section in bytes
        #     uint32_t link;          // Index of associated section (if any)
        #     uint32_t info;          // Additional section information
        #     uint32_t alignment;     // Section alignment (power of 2)
        #     uint32_t entsize;       // Size of entries (for table sections)
        # };
        name_offset = struct.unpack("<I", data[offset:offset+4])[0]
        type_value = struct.unpack("<I", data[offset+4:offset+8])[0]
        flags = struct.unpack("<I", data[offset+8:offset+12])[0]
        section_offset = struct.unpack("<I", data[offset+12:offset+16])[0]
        size = struct.unpack("<I", data[offset+16:offset+20])[0]
        link = struct.unpack("<I", data[offset+20:offset+24])[0]
        info = struct.unpack("<I", data[offset+24:offset+28])[0]
        alignment = struct.unpack("<I", data[offset+28:offset+32])[0]
        entsize = struct.unpack("<I", data[offset+32:offset+36])[0]
        
        print(f"\nSection {i+1}:")
        print(f"  Name offset: 0x{name_offset:08X}")
        print(f"  Type: {type_value}")
        print(f"  Flags: 0x{flags:08X}")
        print(f"  Offset: 0x{section_offset:08X}")
        print(f"  Size: 0x{size:08X}")
        print(f"  Link: {link}")
        print(f"  Info: 0x{info:08X}")
        print(f"  Alignment: {alignment}")
        print(f"  Entry size: {entsize}")
        
        # Verify section type
        valid_types = list(range(11))  # 0-10
        if type_value not in valid_types:
            print(f"  ❌ Invalid section type: {type_value}")
        else:
            print(f"  ✅ Section type verified: {type_value}")
        
        # Verify section offset and size
        if section_offset >= len(data):
            print(f"  ❌ Section offset (0x{section_offset:08X}) is beyond file size (0x{len(data):08X})")
        elif section_offset + size > len(data):
            print(f"  ❌ Section (0x{section_offset:08X} + 0x{size:08X}) extends beyond file size (0x{len(data):08X})")
        else:
            print(f"  ✅ Section offset and size verified: 0x{section_offset:08X} - 0x{section_offset+size:08X}")
            
            # If this is a code section, peek at the first few bytes
            if type_value == 1:  # CODE section
                print(f"\n  Code section preview:")
                print_hex_dump(data[section_offset:section_offset+min(32, size)], section_offset)

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <cof_file>")
        sys.exit(1)
    
    cof_file = sys.argv[1]
    
    if not os.path.isfile(cof_file):
        print(f"Error: {cof_file} is not a file or does not exist")
        sys.exit(1)
    
    print(f"Analyzing file: {cof_file}")
    
    with open(cof_file, 'rb') as f:
        data = f.read()
    
    print(f"File size: {len(data)} bytes")
    print("\nHeader analysis:")
    
    # First show a hexdump of the first 64 bytes
    print("\nFile hexdump (first 64 bytes):")
    print_hex_dump(data[:min(64, len(data))])
    
    print("\nCOF Header validation:")
    if validate_cof_header(data):
        # Get section count from header
        section_count = struct.unpack("<H", data[10:12])[0]
        
        print("\nSection Header validation:")
        validate_section_headers(data, section_count)
    
    print("\nAnalysis complete.")

if __name__ == "__main__":
    main()