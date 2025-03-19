import struct
import sys
from enum import Enum, IntEnum
import argparse
import os

# COF magic number (COIL in ASCII)
COF_MAGIC = 0x434F494C

# Enums for section types, flags, etc.
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

class CofFlags(IntEnum):
    COF_FLAG_EXECUTABLE = 1 << 0
    COF_FLAG_LINKABLE = 1 << 1
    COF_FLAG_POSITION_IND = 1 << 2
    COF_FLAG_CONTAINS_DBG = 1 << 3

class SectionFlags(IntEnum):
    COF_SEC_FLAG_WRITE = 1 << 0
    COF_SEC_FLAG_EXEC = 1 << 1
    COF_SEC_FLAG_ALLOC = 1 << 2
    COF_SEC_FLAG_MERGE = 1 << 3
    COF_SEC_FLAG_STRINGS = 1 << 4
    COF_SEC_FLAG_GROUP = 1 << 5
    COF_SEC_FLAG_TLS = 1 << 6
    COF_SEC_FLAG_COMPRESS = 1 << 7

class TargetId(IntEnum):
    TARGET_ANY = 0x0000
    TARGET_X86 = 0x0001
    TARGET_X86_64 = 0x0002
    TARGET_ARM = 0x0003
    TARGET_ARM64 = 0x0004
    TARGET_RISCV32 = 0x0005
    TARGET_RISCV64 = 0x0006

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
    
    def print_header_info(self):
        """Print information about the COF header."""
        print("COF Header Information:")
        print(f"  Magic: 0x{self.header.magic:08X} ('COIL')")
        print(f"  Version: {self.header.version_major}.{self.header.version_minor}.{self.header.version_patch}")
        
        # Print flags
        flags_str = []
        for flag in CofFlags:
            if self.header.flags & flag:
                flags_str.append(flag.name)
        
        if flags_str:
            print(f"  Flags: {' | '.join(flags_str)} (0x{self.header.flags:02X})")
        else:
            print(f"  Flags: None (0x{self.header.flags:02X})")
        
        # Print target architecture
        try:
            target_name = TargetId(self.header.target).name
        except ValueError:
            target_name = f"Unknown (0x{self.header.target:04X})"
        
        print(f"  Target: {target_name}")
        print(f"  Section Count: {self.header.section_count}")
        
        if self.header.entrypoint:
            print(f"  Entrypoint: 0x{self.header.entrypoint:08X}")
        else:
            print("  Entrypoint: None")
        
        print(f"  String Table: Offset 0x{self.header.str_tab_off:08X}, Size {self.header.str_tab_size} bytes")
        print(f"  Symbol Table: Offset 0x{self.header.sym_tab_off:08X}, Size {self.header.sym_tab_size} bytes")
    
    def print_section_info(self):
        """Print information about the sections in the COF file."""
        print("\nCOF Sections:")
        print("  Idx Name                Type                Flags  Offset     Size       Align")
        print("  --- ------------------- ------------------- ------ ---------- ---------- -----")
        
        for i, section in enumerate(self.section_headers):
            name = self.get_section_name(section)
            
            # Get type name
            try:
                type_name = SectionType(section.type).name
            except ValueError:
                type_name = f"UNKNOWN (0x{section.type:08X})"
            
            # Get flags
            flags_str = ''
            if section.flags & SectionFlags.COF_SEC_FLAG_WRITE:
                flags_str += 'W'
            if section.flags & SectionFlags.COF_SEC_FLAG_EXEC:
                flags_str += 'X'
            if section.flags & SectionFlags.COF_SEC_FLAG_ALLOC:
                flags_str += 'A'
            if section.flags & SectionFlags.COF_SEC_FLAG_MERGE:
                flags_str += 'M'
            if section.flags & SectionFlags.COF_SEC_FLAG_STRINGS:
                flags_str += 'S'
            if section.flags & SectionFlags.COF_SEC_FLAG_GROUP:
                flags_str += 'G'
            if section.flags & SectionFlags.COF_SEC_FLAG_TLS:
                flags_str += 'T'
            if section.flags & SectionFlags.COF_SEC_FLAG_COMPRESS:
                flags_str += 'C'
            
            print(f"  {i:3d} {name[:19]:<19} {type_name[:19]:<19} {flags_str:<6} 0x{section.offset:08X} 0x{section.size:08X} {1<<section.alignment if section.alignment else 0}")
    
    def print_file_diagnostics(self):
        """Print diagnostic information about the file."""
        print("\nFile Diagnostics:")
        print(f"  File Size: {self.file_size} bytes")
        print(f"  COF Header: 32 bytes")
        
        expected_section_headers_size = self.header.section_count * 36
        print(f"  Expected Section Headers: {self.header.section_count} headers × 36 bytes = {expected_section_headers_size} bytes")
        
        expected_min_size = 32 + expected_section_headers_size
        if self.file_size < expected_min_size:
            print(f"  WARNING: File size ({self.file_size}) is less than expected minimum size ({expected_min_size})")
        
        # Check for overlapping sections
        overlaps = []
        for i, sec1 in enumerate(self.section_headers):
            if sec1.offset == 0 or sec1.size == 0:
                continue
            for j, sec2 in enumerate(self.section_headers[i+1:], i+1):
                if sec2.offset == 0 or sec2.size == 0:
                    continue
                if (sec1.offset <= sec2.offset < sec1.offset + sec1.size or
                    sec2.offset <= sec1.offset < sec2.offset + sec2.size):
                    overlaps.append((i, j))
        
        if overlaps:
            print("  WARNING: Overlapping sections detected:")
            for i, j in overlaps:
                print(f"    Sections {i} and {j} overlap")
        
        # Check for sections extending beyond file size
        beyond_file = []
        for i, sec in enumerate(self.section_headers):
            if sec.offset + sec.size > self.file_size:
                beyond_file.append(i)
        
        if beyond_file:
            print("  WARNING: Sections extending beyond file size:")
            for i in beyond_file:
                sec = self.section_headers[i]
                print(f"    Section {i} (offset: 0x{sec.offset:X}, size: 0x{sec.size:X}) extends beyond file size (0x{self.file_size:X})")

def main():
    parser = argparse.ArgumentParser(description="Display information about COIL Object Format (COF) files")
    parser.add_argument('file', help="The COF file to analyze")
    parser.add_argument('--header', action='store_true', help="Display only the header information")
    parser.add_argument('--sections', action='store_true', help="Display only the section information")
    parser.add_argument('--diagnostics', '-d', action='store_true', help="Display diagnostic information about the file")
    parser.add_argument('--raw', '-r', action='store_true', help="Dump raw file information (first 32 bytes)")
    
    args = parser.parse_args()
    
    try:
        # Display file stats
        file_stats = os.stat(args.file)
        print(f"File: {args.file}")
        print(f"Size: {file_stats.st_size} bytes")
        print()
        
        # If raw mode, just dump the first 32 bytes
        if args.raw:
            with open(args.file, 'rb') as f:
                data = f.read(32)
            print("Raw file header (first 32 bytes):")
            for i in range(0, len(data), 16):
                chunk = data[i:i+16]
                hex_str = ' '.join(f'{b:02X}' for b in chunk)
                ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                print(f"  {i:04X}: {hex_str}  {ascii_str}")
            return 0
        
        cof = CofFile(args.file)
        
        if args.header or not (args.header or args.sections or args.diagnostics):
            cof.print_header_info()
        
        if args.sections or not (args.header or args.sections or args.diagnostics):
            cof.print_section_info()
        
        if args.diagnostics:
            cof.print_file_diagnostics()
            
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())