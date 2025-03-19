import struct
import sys
from enum import Enum, IntEnum
import argparse
import binascii
import string
import os

# COF magic number (COIL in ASCII)
COF_MAGIC = 0x434F494C

class SectionType(IntEnum):
    COF_SECTION_NULL = 0
    COF_SECTION_CODE = 1
    COF_SECTION_DATA = 2
    COF_SECTION_BSS = 3
    COF_SECTION_SYMTAB = 4
    COF_SECTION_STRTAB = 5
    COF_SECTION_RELA = 6
    COF_SECTION_REL = 7
    COF_SECTION_METADATA = 8
    COF_SECTION_COMMENT = 9
    COF_SECTION_DIRECTIVE = 10

class CofHeader:
    def __init__(self, data):
        # Check if there's enough data for a header
        if len(data) < 32:
            raise ValueError(f"File too small for a valid COF header. Expected at least 32 bytes, got {len(data)} bytes.")
            
        # Parse header from raw bytes
        # The COF header is 32 bytes total
        # Fix: Changed 8x padding to 4x (4 bytes) to match the 32-byte structure
        (
            self.magic,
            self.version_major,
            self.version_minor,
            self.version_patch,
            self.flags,
            self.target,
            self.section_count,
            self.entrypoint,
            self.str_tab_off,
            self.str_tab_size,
            self.sym_tab_off,
            self.sym_tab_size,
        ) = struct.unpack('<IBBBBHHIIII4x', data[:32])
        
        # Validate magic number
        if self.magic != COF_MAGIC:
            raise ValueError(f"Invalid COF file: bad magic number (expected 0x{COF_MAGIC:08X}, got 0x{self.magic:08X})")

class CofSectionHeader:
    def __init__(self, data):
        # Check if there's enough data for a section header
        if len(data) < 36:
            raise ValueError(f"Not enough data for a section header. Expected at least 36 bytes, got {len(data)} bytes.")
            
        # Parse section header from raw bytes
        (
            self.name_offset,
            self.type,
            self.flags,
            self.offset,
            self.size,
            self.link,
            self.info,
            self.alignment,
            self.entsize,
        ) = struct.unpack('<IIIIIIIII', data[:36])

class CofFile:
    def __init__(self, filename):
        try:
            with open(filename, 'rb') as f:
                self.data = f.read()
            
            # Get file size for validation
            self.file_size = len(self.data)
            
            if self.file_size < 32:
                raise ValueError(f"File too small to be a valid COF file: {self.file_size} bytes")
            
            # Parse header
            try:
                self.header = CofHeader(self.data[:32])
            except Exception as e:
                raise ValueError(f"Failed to parse COF header: {str(e)}")
            
            # Validate section count to avoid processing too many sections
            if self.header.section_count > 1000:  # Arbitrary limit to prevent excessive processing
                raise ValueError(f"Unreasonable section count: {self.header.section_count}")
            
            # Parse section headers
            self.section_headers = []
            for i in range(self.header.section_count):
                offset = 32 + i * 36  # Header size + (section index * section header size)
                
                # Check if we have enough data for this section header
                if offset + 36 > self.file_size:
                    print(f"Warning: File truncated. Expected section header at offset {offset}, but file size is only {self.file_size} bytes.")
                    break
                
                try:
                    self.section_headers.append(CofSectionHeader(self.data[offset:offset+36]))
                except Exception as e:
                    print(f"Warning: Failed to parse section header {i}: {str(e)}")
                    break
            
            # Parse string table if present
            self.string_table = None
            if (self.header.str_tab_off > 0 and 
                self.header.str_tab_size > 0 and 
                self.header.str_tab_off + self.header.str_tab_size <= self.file_size):
                self.string_table = self.data[self.header.str_tab_off:self.header.str_tab_off + self.header.str_tab_size]
            elif self.header.str_tab_off > 0:
                print(f"Warning: String table at offset {self.header.str_tab_off} with size {self.header.str_tab_size} extends beyond file size {self.file_size}")
                
        except FileNotFoundError:
            raise ValueError(f"File not found: {filename}")
        except PermissionError:
            raise ValueError(f"Permission denied: {filename}")
    
    def get_string(self, offset):
        """Get a string from the string table at the given offset."""
        if self.string_table is None:
            return "<no string table>"
        
        if offset >= len(self.string_table):
            return f"<invalid offset: {offset}>"
        
        # Find the null terminator
        end = self.string_table.find(b'\0', offset)
        if end == -1:
            return self.string_table[offset:].decode('utf-8', errors='replace')
        
        return self.string_table[offset:end].decode('utf-8', errors='replace')
    
    def get_section_name(self, section_header):
        """Get the name of a section from its header."""
        return self.get_string(section_header.name_offset)

class CofDumper:
    def __init__(self, cof):
        self.cof = cof
    
    def dump_section(self, section_idx, format='hex'):
        """Dump the contents of a section."""
        if section_idx < 0 or section_idx >= len(self.cof.section_headers):
            raise ValueError(f"Invalid section index: {section_idx}")
        
        section = self.cof.section_headers[section_idx]
        section_name = self.cof.get_section_name(section)
        
        print(f"Contents of section {section_idx} ({section_name}):")
        
        if section.size == 0:
            print("  <empty section>")
            return
        
        # Validate that the section data is within the file bounds
        if section.offset >= self.cof.file_size:
            print(f"  <section offset 0x{section.offset:X} is beyond file size 0x{self.cof.file_size:X}>")
            return
        
        # Adjust section size if it would extend beyond file
        actual_size = min(section.size, self.cof.file_size - section.offset)
        if actual_size < section.size:
            print(f"  Warning: Section extends beyond file size. Truncating from {section.size} to {actual_size} bytes.")
        
        section_data = self.cof.data[section.offset:section.offset + actual_size]
        
        if format == 'hex':
            self._dump_hex(section_data)
        elif format == 'string':
            self._dump_string(section_data)
        else:
            raise ValueError(f"Unknown dump format: {format}")
    
    def _dump_hex(self, data, bytes_per_line=16):
        """Dump data in hex format."""
        for i in range(0, len(data), bytes_per_line):
            chunk = data[i:i+bytes_per_line]
            hex_str = ' '.join(f'{b:02X}' for b in chunk)
            
            # Add padding for incomplete lines
            padding = '   ' * (bytes_per_line - len(chunk))
            
            # Create ASCII representation
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            
            print(f"  {i:08X}: {hex_str}{padding}  {ascii_str}")
    
    def _dump_string(self, data):
        """Dump data as strings."""
        i = 0
        while i < len(data):
            # Find null terminator
            end = data.find(b'\0', i)
            if end == -1:
                end = len(data)
            
            if end > i:  # Only print non-empty strings
                str_data = data[i:end]
                printable = all(c in string.printable.encode() for c in str_data)
                
                if printable and len(str_data) > 3:  # Minimum length filter to avoid noise
                    print(f"  {i:08X}: '{str_data.decode('utf-8', errors='replace')}'")
            
            i = end + 1
    
    def dump_raw(self, offset, size):
        """Dump raw data from a specific offset."""
        if offset >= len(self.cof.data):
            print(f"Offset 0x{offset:X} is beyond the file size (0x{len(self.cof.data):X})")
            return
        
        actual_size = min(size, len(self.cof.data) - offset)
        if actual_size < size:
            print(f"Warning: Requested size extends beyond file. Truncating from {size} to {actual_size} bytes.")
        
        print(f"Raw dump from offset 0x{offset:X}, size {actual_size} bytes:")
        self._dump_hex(self.cof.data[offset:offset + actual_size])

def main():
    parser = argparse.ArgumentParser(description="Dump contents of COIL Object Format (COF) file sections")
    parser.add_argument('file', help="The COF file to analyze")
    parser.add_argument('--section', '-s', type=int, help="Dump the specified section (by index)")
    parser.add_argument('--all', '-a', action='store_true', help="Dump all sections")
    parser.add_argument('--format', '-f', choices=['hex', 'string'], default='hex', help="Display format")
    parser.add_argument('--raw', '-r', action='store_true', help="Dump the raw file data (ignoring section structure)")
    parser.add_argument('--offset', '-o', type=lambda x: int(x, 0), help="Offset for raw dump (only with --raw)")
    parser.add_argument('--size', type=lambda x: int(x, 0), default=256, help="Size for raw dump (only with --raw)")
    
    args = parser.parse_args()
    
    try:
        # Display file stats
        file_stats = os.stat(args.file)
        print(f"File: {args.file}")
        print(f"Size: {file_stats.st_size} bytes")
        print()
        
        # If raw mode, create a simple dumper without parsing the COF structure
        if args.raw:
            with open(args.file, 'rb') as f:
                data = f.read()
            
            class SimpleDumper:
                def _dump_hex(self, data, bytes_per_line=16):
                    for i in range(0, len(data), bytes_per_line):
                        chunk = data[i:i+bytes_per_line]
                        hex_str = ' '.join(f'{b:02X}' for b in chunk)
                        padding = '   ' * (bytes_per_line - len(chunk))
                        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                        print(f"  {i:08X}: {hex_str}{padding}  {ascii_str}")
                        
                def dump_raw(self, data, offset, size):
                    if offset >= len(data):
                        print(f"Offset 0x{offset:X} is beyond the file size (0x{len(data):X})")
                        return
                    
                    actual_size = min(size, len(data) - offset)
                    if actual_size < size:
                        print(f"Warning: Requested size extends beyond file. Truncating from {size} to {actual_size} bytes.")
                    
                    print(f"Raw dump from offset 0x{offset:X}, size {actual_size} bytes:")
                    self._dump_hex(data[offset:offset + actual_size])
            
            dumper = SimpleDumper()
            offset = args.offset if args.offset is not None else 0
            dumper.dump_raw(data, offset, args.size)
            return 0
        
        cof = CofFile(args.file)
        dumper = CofDumper(cof)
        
        if args.section is not None:
            dumper.dump_section(args.section, args.format)
        elif args.all:
            for i in range(len(cof.section_headers)):
                dumper.dump_section(i, args.format)
                if i < len(cof.section_headers) - 1:
                    print()  # Empty line between sections
        else:
            print("Please specify a section to dump (--section), use --all to dump all sections, or use --raw to dump raw file data.")
            return 1
            
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())