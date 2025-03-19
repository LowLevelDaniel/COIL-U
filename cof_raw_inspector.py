#!/usr/bin/env python3
"""
COF Raw File Inspector - Analyzes COF files without assuming a specific structure
"""

import sys
import os
import argparse
import struct

def hex_dump(data, offset=0, length=None, width=16):
    """
    Create a hex dump of the provided data.
    """
    if length is None:
        length = len(data)
    
    result = []
    for i in range(0, min(length, len(data)), width):
        chunk = data[i:i+width]
        hex_values = ' '.join(f'{b:02X}' for b in chunk)
        ascii_values = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        result.append(f"{offset+i:08X}: {hex_values:<{width*3}} {ascii_values}")
    
    return '\n'.join(result)

def analyze_potential_header(data):
    """
    Try to analyze the first 32 bytes as a potential COF header.
    """
    if len(data) < 32:
        return "File is too small to contain a valid COF header"
    
    # Extract magic number (first 4 bytes)
    magic = struct.unpack('<I', data[0:4])[0]
    magic_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[0:4])
    
    print(f"Magic number: 0x{magic:08X} (ASCII: '{magic_str}')")
    
    if magic == 0x434F494C:  # "COIL" in ASCII/hex
        print("  ✓ Magic number matches 'COIL'")
    else:
        print("  ✗ Magic number does not match 'COIL'")
    
    # Try different header formats
    
    # Format 1: Standard 32-byte header with 12 fields
    print("\nTrying standard 12-field format...")
    try:
        fields = struct.unpack('<IBBBBHHIIII4x', data[0:32])
        print("  ✓ Unpacked successfully")
        print("  Fields: ", fields)
    except Exception as e:
        print(f"  ✗ Failed: {str(e)}")
    
    # Format 2: Standard header with 11 fields (without sym_tab_size)
    print("\nTrying 11-field format...")
    try:
        fields = struct.unpack('<IBBBBHHIII8x', data[0:32])
        print("  ✓ Unpacked successfully")
        print("  Fields: ", fields)
    except Exception as e:
        print(f"  ✗ Failed: {str(e)}")
    
    # Format 3: Simpler header with fewer fields
    print("\nTrying simpler 9-field format...")
    try:
        fields = struct.unpack('<IBBBBHHII8x', data[0:32])
        print("  ✓ Unpacked successfully")
        print("  Fields: ", fields)
    except Exception as e:
        print(f"  ✗ Failed: {str(e)}")
    
    # Try parsing individual fields to see what makes sense
    print("\nBreaking down header byte by byte:")
    field_descriptions = [
        ("Magic", "I", 0, 4),
        ("Version Major", "B", 4, 1),
        ("Version Minor", "B", 5, 1),
        ("Version Patch", "B", 6, 1),
        ("Flags", "B", 7, 1),
        ("Target", "H", 8, 2),
        ("Section Count", "H", 10, 2),
        ("Entry Point", "I", 12, 4),
        ("String Table Offset", "I", 16, 4),
        ("String Table Size", "I", 20, 4),
        ("Symbol Table Offset", "I", 24, 4),
        # Remaining 4 bytes at 28-31 might be Symbol Table Size or padding
    ]
    
    for desc, fmt, offset, size in field_descriptions:
        if offset + size <= len(data):
            value = struct.unpack(f'<{fmt}', data[offset:offset+size])[0]
            print(f"  {desc}: {value} (0x{value:X}) at offset {offset}-{offset+size-1}")
    
    # Try to understand the remaining bytes
    if len(data) >= 32:
        remaining = struct.unpack('<I', data[28:32])[0]
        print(f"  Remaining 4 bytes: {remaining} (0x{remaining:X}) at offset 28-31")

def analyze_sections(data):
    """
    Try to analyze section headers after the main header.
    """
    if len(data) < 36:
        return "File is too small to contain section headers"
    
    # Extract section count from the header (assuming standard format)
    if len(data) >= 12:
        try:
            section_count = struct.unpack('<H', data[10:12])[0]
            print(f"\nSection count from header: {section_count}")
        except:
            print("\nFailed to extract section count from header")
            return
    
    # Try to interpret the bytes after the header as a section header
    if len(data) >= 68:  # 32 (header) + 36 (first section header)
        print("\nAttempting to parse first section header:")
        section_data = data[32:68]
        
        try:
            fields = struct.unpack('<IIIIIIIII', section_data)
            print("  Section header fields:", fields)
            name_offset, section_type, flags, offset, size, link, info, alignment, entsize = fields
            print(f"  Name offset: 0x{name_offset:X}")
            print(f"  Type: {section_type}")
            print(f"  Flags: 0x{flags:X}")
            print(f"  Offset: 0x{offset:X}")
            print(f"  Size: 0x{size:X}")
            print(f"  Link: {link}")
            print(f"  Info: 0x{info:X}")
            print(f"  Alignment: {alignment}")
            print(f"  Entry size: {entsize}")
            
            # Validate if offset and size are reasonable
            if offset > 0 and offset < len(data) and offset + size <= len(data):
                print("  ✓ Section offset and size appear valid")
            else:
                print("  ✗ Section offset or size out of bounds")
                
        except Exception as e:
            print(f"  ✗ Failed to parse section header: {str(e)}")

def analyze_string_table(data):
    """
    Try to find the string table in the file.
    """
    if len(data) < 24:
        return "File is too small to extract string table information"
    
    # Try to get string table offset and size from header
    try:
        str_tab_off = struct.unpack('<I', data[16:20])[0]
        str_tab_size = struct.unpack('<I', data[20:24])[0]
        
        print(f"\nString table information from header:")
        print(f"  Offset: 0x{str_tab_off:X}")
        print(f"  Size: 0x{str_tab_size:X}")
        
        if str_tab_off > 0 and str_tab_off < len(data):
            if str_tab_off + str_tab_size <= len(data):
                print("  ✓ String table appears to be within file bounds")
                
                # Extract some strings from the table
                string_table = data[str_tab_off:str_tab_off + str_tab_size]
                print("\nAttempting to extract strings from string table:")
                
                # Find null-terminated strings
                i = 0
                strings_found = 0
                while i < len(string_table) and strings_found < 10:  # Limit to 10 strings
                    if string_table[i] > 0:  # Skip null bytes
                        end = string_table.find(b'\0', i)
                        if end == -1:
                            end = len(string_table)
                        
                        if end > i:
                            s = string_table[i:end].decode('utf-8', errors='replace')
                            if len(s) > 0:
                                print(f"  String at offset 0x{str_tab_off+i:X}: '{s}'")
                                strings_found += 1
                        
                        i = end + 1
                    else:
                        i += 1
            else:
                print("  ✗ String table extends beyond file size")
        else:
            print("  ✗ Invalid string table offset")
    except Exception as e:
        print(f"  ✗ Failed to analyze string table: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="Analyze COF files at a raw level")
    parser.add_argument('file', help="The COF file to analyze")
    parser.add_argument('--dump', '-d', action='store_true', help="Dump the entire file as hex")
    parser.add_argument('--header-only', '-H', action='store_true', help="Only analyze the header")
    
    args = parser.parse_args()
    
    try:
        # Read the file
        with open(args.file, 'rb') as f:
            data = f.read()
        
        # Display file information
        file_size = len(data)
        print(f"File: {args.file}")
        print(f"Size: {file_size} bytes")
        print()
        
        # Display hex dump of the first 32 bytes (header)
        print("First 32 bytes (potential header):")
        print(hex_dump(data, 0, 32))
        print()
        
        # Analyze the potential header
        analyze_potential_header(data)
        
        if not args.header_only:
            # Try to analyze sections
            analyze_sections(data)
            
            # Try to find string table
            analyze_string_table(data)
        
        # Dump entire file if requested
        if args.dump:
            print("\nFull file hex dump:")
            print(hex_dump(data, 0, file_size))
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())