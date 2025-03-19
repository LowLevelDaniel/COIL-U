import struct
import sys
from enum import Enum, IntEnum
import argparse
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

class SectionFlags(IntEnum):
    COF_SEC_FLAG_WRITE = 1 << 0
    COF_SEC_FLAG_EXEC = 1 << 1
    COF_SEC_FLAG_ALLOC = 1 << 2
    COF_SEC_FLAG_MERGE = 1 << 3
    COF_SEC_FLAG_STRINGS = 1 << 4
    COF_SEC_FLAG_GROUP = 1 << 5
    COF_SEC_FLAG_TLS = 1 << 6
    COF_SEC_FLAG_COMPRESS = 1 << 7

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

# Instruction Set Architecture definitions
class Opcode(IntEnum):
    # No Operation (0x00)
    OP_NOP = 0x00
    
    # Control Flow (0x01 - 0x0F)
    OP_SYMB = 0x01  # Define a symbol
    OP_BR   = 0x02  # Unconditional branch to location
    OP_BRC  = 0x03  # Conditional branch to location
    OP_CALL = 0x04  # Call subroutine
    OP_RET  = 0x05  # Return from subroutine
    OP_INT  = 0x06  # Trigger interrupt
    OP_IRET = 0x07  # Return from interrupt
    OP_WFI  = 0x08  # Wait for interrupt
    OP_SYSC = 0x09  # System call
    OP_WFE  = 0x0A  # Wait for event
    OP_SEV  = 0x0B  # Send event
    OP_TRAP = 0x0C  # Software trap
    OP_HLT  = 0x0D  # Halt execution
    
    # Arithmetic Operations (0x10 - 0x1F)
    OP_ADD  = 0x10  # Addition
    OP_SUB  = 0x11  # Subtraction
    OP_MUL  = 0x12  # Multiplication
    OP_DIV  = 0x13  # Division
    OP_MOD  = 0x14  # Modulus
    OP_NEG  = 0x15  # Negation
    OP_ABS  = 0x16  # Absolute value
    OP_INC  = 0x17  # Increment
    OP_DEC  = 0x18  # Decrement
    OP_ADDC = 0x19  # Add with carry
    OP_SUBB = 0x1A  # Subtract with borrow
    OP_MULH = 0x1B  # Multiplication high bits
    
    # Bit Manipulation (0x20 - 0x2F)
    OP_AND  = 0x20  # Bitwise AND
    OP_OR   = 0x21  # Bitwise OR
    OP_XOR  = 0x22  # Bitwise XOR
    OP_NOT  = 0x23  # Bitwise NOT
    OP_SHL  = 0x24  # Shift left
    OP_SHR  = 0x25  # Shift right logical
    OP_SAR  = 0x26  # Shift right arithmetic
    OP_ROL  = 0x27  # Rotate left
    OP_ROR  = 0x28  # Rotate right
    OP_CLZ  = 0x29  # Count leading zeros
    OP_CTZ  = 0x2A  # Count trailing zeros
    OP_POPC = 0x2B  # Population count
    OP_BSWP = 0x2C  # Byte swap
    OP_BEXT = 0x2D  # Bit extraction
    OP_BINS = 0x2E  # Bit insertion
    OP_BMSK = 0x2F  # Bit mask
    
    # Comparison Operations (0x30 - 0x3F)
    OP_CMP  = 0x30  # Compare values and set flags
    OP_TEST = 0x31  # Test bits
    
    # Data Movement (0x40 - 0x4F)
    OP_MOV   = 0x40  # Move data
    OP_LOAD  = 0x41  # Load from memory
    OP_STORE = 0x42  # Store to memory
    OP_XCHG  = 0x43  # Exchange data
    OP_LEA   = 0x44  # Load effective address
    OP_MOVI  = 0x45  # Move immediate value
    OP_MOVZ  = 0x46  # Move with zero extension
    OP_MOVS  = 0x47  # Move with sign extension
    OP_LDMUL = 0x48  # Load multiple
    OP_STMUL = 0x49  # Store multiple
    OP_LDSTR = 0x4A  # Load string
    OP_STSTR = 0x4B  # Store string
    
    # Stack Operations (0x50 - 0x5F)
    OP_PUSH  = 0x50  # Push onto stack
    OP_POP   = 0x51  # Pop from stack
    OP_PUSHA = 0x52  # Push all registers
    OP_POPA  = 0x53  # Pop all registers
    OP_PUSHF = 0x54  # Push flags
    OP_POPF  = 0x55  # Pop flags
    OP_ADJSP = 0x56  # Adjust stack pointer
    
    # Variable Operations (0x60 - 0x6F)
    OP_VARCR = 0x60  # Create variable
    OP_VARDL = 0x61  # Delete variable
    OP_VARSC = 0x62  # Create variable scope
    OP_VAREND = 0x63  # End variable scope
    OP_VARGET = 0x64  # Get variable value
    OP_VARSET = 0x65  # Set variable value
    OP_VARREF = 0x66  # Get variable reference
    
    # Directives (0xD0-0xDF)
    DIR_OPCODE_VERSION   = 0xD0  # Version specification
    DIR_OPCODE_TARGET    = 0xD1  # Target architecture
    DIR_OPCODE_SECTION   = 0xD2  # Section definition
    DIR_OPCODE_SYMBOL    = 0xD3  # Symbol definition
    DIR_OPCODE_ALIGN     = 0xD4  # Alignment directive
    DIR_OPCODE_DATA      = 0xD5  # Data definition
    DIR_OPCODE_ABI       = 0xD6  # ABI definition
    DIR_OPCODE_FEATURE   = 0xD7  # Feature control
    DIR_OPCODE_OPTIMIZE  = 0xD8  # Optimization control
    DIR_OPCODE_CONDITION = 0xD9  # Conditional assembly
    DIR_OPCODE_MACRO     = 0xDA  # Macro definition
    DIR_OPCODE_INCLUDE   = 0xDB  # Include other COIL binary

class OperandQualifier(IntEnum):
    OPQUAL_IMM = 0x01  # Value is an immediate constant in the instruction
    OPQUAL_VAR = 0x02  # Value refers to a variable
    OPQUAL_REG = 0x03  # Value refers to a virtual register
    OPQUAL_MEM = 0x04  # Value refers to a memory address
    OPQUAL_LBL = 0x05  # Value refers to a label
    OPQUAL_STR = 0x06  # Value is a string literal (offset into string table)
    OPQUAL_SYM = 0x07  # Value refers to a symbol (index into symbol table)
    OPQUAL_REL = 0x08  # Value is a relative offset

class CoilType(IntEnum):
    COIL_TYPE_INT = 0x00    # expect another uint8_t value describing the width
    COIL_TYPE_UINT = 0x01   # expect another uint8_t value describing the width
    COIL_TYPE_FLOAT = 0x02  # expect another uint8_t value describing the width
    
    COIL_TYPE_VEC = 0x10    # Reserved for future use in v2.0.0
    
    COIL_TYPE_VOID = 0xF0   # Void type (no value)
    COIL_TYPE_BOOL = 0xF1   # Boolean
    COIL_TYPE_LINT = 0xF2   # The largest native integer supported
    COIL_TYPE_FINT = 0xF3   # The fastest native integer supported
    COIL_TYPE_PTR  = 0xF4   # The native pointer type
    COIL_TYPE_PARAM2 = 0xFD # Parameter type 2
    COIL_TYPE_PARAM1 = 0xFE # Parameter type 1
    COIL_TYPE_PARAM0 = 0xFF # Parameter type 0

class BranchCondition(IntEnum):
    BR_ALWAYS = 0x00  # Always branch (unconditional)
    BR_EQ     = 0x01  # Equal / Zero
    BR_NE     = 0x02  # Not equal / Not zero
    BR_LT     = 0x03  # Less than
    BR_LE     = 0x04  # Less than or equal
    BR_GT     = 0x05  # Greater than
    BR_GE     = 0x06  # Greater than or equal
    BR_CARRY  = 0x07  # Carry flag set
    BR_OFLOW  = 0x08  # Overflow flag set
    BR_SIGN   = 0x09  # Sign flag set
    BR_PARITY = 0x0A  # Parity flag set
    BR_NCARRY = 0x0B  # Carry flag not set
    BR_NOFLOW = 0x0C  # Overflow flag not set
    BR_NSIGN  = 0x0D  # Sign flag not set
    BR_NPARITY = 0x0E  # Parity flag not set

class Operand:
    def __init__(self, qualifier, type_val, data):
        self.qualifier = qualifier
        self.type = type_val
        self.data = data
    
    def __str__(self):
        if self.qualifier == OperandQualifier.OPQUAL_IMM:
            # For immediate values, format based on type
            if self.type == CoilType.COIL_TYPE_INT or self.type == CoilType.COIL_TYPE_UINT:
                width = self.data[0] if len(self.data) > 0 else 32
                if width == 8 and len(self.data) > 1:
                    value = struct.unpack('<b', self.data[1:2])[0]
                elif width == 16 and len(self.data) > 2:
                    value = struct.unpack('<h', self.data[1:3])[0] 
                elif width == 32 and len(self.data) > 4:
                    value = struct.unpack('<i', self.data[1:5])[0]
                elif width == 64 and len(self.data) > 8:
                    value = struct.unpack('<q', self.data[1:9])[0]
                else:
                    # Not enough data or non-standard width
                    if len(self.data) > 1:
                        value = int.from_bytes(self.data[1:], byteorder='little', signed=self.type == CoilType.COIL_TYPE_INT)
                    else:
                        value = 0
                return str(value)
            elif self.type == CoilType.COIL_TYPE_FLOAT:
                width = self.data[0] if len(self.data) > 0 else 32
                if width == 32 and len(self.data) > 4:
                    value = struct.unpack('<f', self.data[1:5])[0]
                elif width == 64 and len(self.data) > 8:
                    value = struct.unpack('<d', self.data[1:9])[0]
                else:
                    value = 0.0
                return str(value)
            elif self.type == CoilType.COIL_TYPE_BOOL:
                value = bool(self.data[0]) if len(self.data) > 0 else False
                return "true" if value else "false"
            else:
                # Handle other immediate types
                if len(self.data) == 0:
                    return "0"
                else:
                    return f"0x{int.from_bytes(self.data, byteorder='little'):X}"
                
        elif self.qualifier == OperandQualifier.OPQUAL_REG:
            # For registers, format as register name
            if len(self.data) < 1:
                return "R?"  # Unknown register
                
            reg_num = int.from_bytes(self.data, byteorder='little')
            
            # Try to determine register type
            if self.type == CoilType.COIL_TYPE_INT and len(self.data) > 1:
                if self.data[0] == 8:
                    reg_type = 'B'
                elif self.data[0] == 16:
                    reg_type = 'W'
                elif self.data[0] == 32:
                    reg_type = 'L'
                elif self.data[0] == 64:
                    reg_type = 'Q'
                else:
                    reg_type = '?'
            else:
                reg_type = 'Q'  # Default to 64-bit register
                
            return f"R{reg_type}{reg_num}"
            
        elif self.qualifier == OperandQualifier.OPQUAL_MEM:
            # For memory references, format as address
            if len(self.data) == 0:
                return "[?]"
                
            addr = int.from_bytes(self.data, byteorder='little')
            return f"[0x{addr:X}]"
            
        elif self.qualifier == OperandQualifier.OPQUAL_LBL:
            # For labels, format as label name or offset
            if len(self.data) == 0:
                return "label_?"
                
            offset = int.from_bytes(self.data, byteorder='little')
            return f"label_{offset:X}"
            
        elif self.qualifier == OperandQualifier.OPQUAL_SYM:
            # For symbols, format as symbol index
            if len(self.data) == 0:
                return "sym_?"
                
            sym_idx = int.from_bytes(self.data, byteorder='little')
            return f"sym_{sym_idx}"
            
        else:
            # For other qualifiers, format as raw bytes
            try:
                qual_name = OperandQualifier(self.qualifier).name
            except ValueError:
                qual_name = f"QUAL_{self.qualifier:02X}"
                
            try:
                type_name = CoilType(self.type).name
            except ValueError:
                type_name = f"TYPE_{self.type:02X}"
                
            return f"{qual_name}:{type_name}:{self.data.hex() if self.data else ''}"

class Instruction:
    def __init__(self, opcode, qualifier, operands):
        self.opcode = opcode
        self.qualifier = qualifier
        self.operands = operands
    
    def disassemble(self):
        """Convert the instruction to CEL format."""
        try:
            opcode_name = Opcode(self.opcode).name.replace('OP_', '')
        except ValueError:
            opcode_name = f"UNK_{self.opcode:02X}"
        
        operands_str = ", ".join(str(op) for op in self.operands)
        
        # Special handling for branch conditions
        if self.opcode == Opcode.OP_BRC and self.qualifier <= 0x0E:
            try:
                cond_name = BranchCondition(self.qualifier).name.replace('BR_', '')
                return f"BRC {cond_name}, {operands_str}"
            except ValueError:
                pass
        
        # Handle directives
        if 0xD0 <= self.opcode <= 0xDF:
            if self.opcode == Opcode.DIR_OPCODE_VERSION:
                if len(self.operands) >= 3:
                    return f".version {self.operands[0]}.{self.operands[1]}.{self.operands[2]}"
            # Other directive handlers could be added here
        
        # General case
        if self.qualifier != 0:
            return f"{opcode_name}.{self.qualifier:02X} {operands_str}"
        else:
            return f"{opcode_name} {operands_str}" if operands_str else f"{opcode_name}"

class CoilDisassembler:
    def __init__(self, cof):
        self.cof = cof
        self.labels = {}  # Map from offset to label name
    
    def disassemble_section(self, section_idx):
        """Disassemble an executable section."""
        if section_idx < 0 or section_idx >= len(self.cof.section_headers):
            raise ValueError(f"Invalid section index: {section_idx}")
        
        section = self.cof.section_headers[section_idx]
        section_name = self.cof.get_section_name(section)
        
        print(f"Disassembly of section {section_idx} ({section_name}):")
        
        # Check section flags for executable bit
        is_executable = section.flags & SectionFlags.COF_SEC_FLAG_EXEC
        if not is_executable:
            print(f"  Warning: Section is not marked as executable, but attempting disassembly anyway.")
        
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
        
        # First pass to identify branch targets for labels
        try:
            self._find_branch_targets(section_data)
        except Exception as e:
            print(f"  Warning: Error finding branch targets: {str(e)}")
        
        # Second pass to actually disassemble
        try:
            self._disassemble_section_data(section_data, section.offset)
        except Exception as e:
            print(f"  Error during disassembly: {str(e)}")
            # Fallback to hex dump if disassembly fails
            self._fallback_hex_dump(section_data)
    
    def _fallback_hex_dump(self, data, bytes_per_line=16):
        """Provide a hex dump when disassembly fails."""
        print("\n  Falling back to hex dump:")
        for i in range(0, len(data), bytes_per_line):
            chunk = data[i:i+bytes_per_line]
            hex_str = ' '.join(f'{b:02X}' for b in chunk)
            
            # Add padding for incomplete lines
            padding = '   ' * (bytes_per_line - len(chunk))
            
            # Create ASCII representation
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            
            print(f"  {i:08X}: {hex_str}{padding}  {ascii_str}")
    
    def _find_branch_targets(self, data):
        """Identify branch targets in the section data for label generation."""
        i = 0
        while i < len(data):
            if i + 2 >= len(data):
                break
            
            opcode = data[i]
            qualifier = data[i+1]
            operand_count = data[i+2]
            
            # Basic sanity checks
            if operand_count > 10:  # Arbitrary limit to avoid excessive processing
                i += 3
                continue
            
            i += 3  # Move past header
            
            # Check for branch instructions
            if opcode in [Opcode.OP_BR, Opcode.OP_BRC, Opcode.OP_CALL]:
                # Process each operand
                for op_idx in range(operand_count):
                    if i + 1 >= len(data):
                        break
                    
                    op_qual = data[i]
                    op_type = data[i+1]
                    
                    i += 2  # Move past operand header
                    
                    # For label operands
                    if op_qual == OperandQualifier.OPQUAL_LBL:
                        # Simple approach: assume 4-byte offset
                        if i + 3 < len(data):
                            target = int.from_bytes(data[i:i+4], byteorder='little')
                            self.labels[target] = f"label_{target:X}"
                            i += 4
                        else:
                            # Not enough data
                            i = len(data)  # Exit the loop
                            break
                    else:
                        # Skip this operand (simplified approach)
                        # Just assume a fixed size for simplicity
                        i += min(4, len(data) - i)
            else:
                # For non-branch instructions, skip all operands
                for _ in range(operand_count):
                    if i + 1 >= len(data):
                        break
                    
                    # Skip operand header
                    i += 2
                    
                    # Skip operand data (simplified approach)
                    i += min(4, len(data) - i)
    
    def _disassemble_section_data(self, data, base_offset):
        """Disassemble the section data and print it in CEL format."""
        i = 0
        while i < len(data):
            offset = base_offset + i
            
            # Check if this is a label location
            if offset in self.labels:
                print(f"{self.labels[offset]}:")
            
            # Check for enough data for an instruction header
            if i + 2 >= len(data):
                print(f"  0x{offset:08X}: <incomplete instruction>")
                break
            
            opcode = data[i]
            qualifier = data[i+1]
            operand_count = data[i+2]
            
            # Basic sanity check for operand count
            if operand_count > 10:  # Arbitrary limit to avoid excessive processing
                print(f"  0x{offset:08X}: <suspect instruction: operand count {operand_count}>")
                # Dump raw bytes for this instruction
                end = min(i + 16, len(data))
                hex_bytes = ' '.join(f'{b:02X}' for b in data[i:end])
                print(f"  Raw bytes: {hex_bytes}")
                i += 3  # Skip header and try to continue
                continue
            
            # Handle directives (0xD0-0xDF range)
            if 0xD0 <= opcode <= 0xDF:
                directive_name = "UNKNOWN"
                try:
                    directive_name = Opcode(opcode).name.replace('DIR_OPCODE_', '')
                except ValueError:
                    pass
                
                print(f"  0x{offset:08X}: .{directive_name.lower()} [qualifier=0x{qualifier:02X}, operand_count={operand_count}]")
                
                # Simple directive skip
                i += 3  # Skip directive header
                
                # For simplicity, just skip a fixed amount for directives
                if i + 1 < len(data):
                    # Try to read length if present in some directives
                    dir_len = int.from_bytes(data[i:i+2], byteorder='little') if i+1 < len(data) else 0
                    i += 2 + dir_len
                else:
                    i = len(data)  # End of data
                
                continue
            
            i += 3  # Move past instruction header
            
            operands = []
            for _ in range(operand_count):
                # Check for enough data for an operand header
                if i + 1 >= len(data):
                    break
                
                op_qual = data[i]
                op_type = data[i+1]
                
                i += 2  # Move past operand header
                
                # Calculate operand data size based on qualifier and type
                # This is a simplified approach and may need refinement for complex operand types
                if i >= len(data):
                    op_data = b''
                elif op_qual == OperandQualifier.OPQUAL_IMM:
                    # For immediate values
                    if op_type in [CoilType.COIL_TYPE_INT, CoilType.COIL_TYPE_UINT, CoilType.COIL_TYPE_FLOAT]:
                        # Get the width first
                        width_byte = data[i] if i < len(data) else 32
                        size = 1 + (width_byte // 8)  # 1 byte for width + data bytes
                        op_data = data[i:min(i+size, len(data))]
                        i += min(size, len(data) - i)
                    else:
                        # Default size for other immediate types
                        size = 4
                        op_data = data[i:min(i+size, len(data))]
                        i += min(size, len(data) - i)
                elif op_qual == OperandQualifier.OPQUAL_REG:
                    # For register references
                    size = 1
                    op_data = data[i:min(i+size, len(data))]
                    i += min(size, len(data) - i)
                else:
                    # Default size for other operand types
                    size = 4
                    op_data = data[i:min(i+size, len(data))]
                    i += min(size, len(data) - i)
                
                # Create operand object
                try:
                    operands.append(Operand(op_qual, op_type, op_data))
                except Exception as e:
                    # If operand creation fails, add a placeholder
                    print(f"  Warning: Failed to create operand: {str(e)}")
                    operands.append(Operand(op_qual, op_type, op_data))
            
            # Create and disassemble the instruction
            try:
                instr = Instruction(opcode, qualifier, operands)
                print(f"  0x{offset:08X}: {instr.disassemble()}")
            except Exception as e:
                # Fallback for errors
                op_str = f"{opcode:02X} {qualifier:02X} {operand_count:02X}"
                for op in operands:
                    op_str += f" [{op.qualifier}:{op.type}:{op.data.hex()}]"
                print(f"  0x{offset:08X}: {op_str} ; ERROR: {str(e)}")
    
    def disassemble_raw(self, offset, size):
        """Disassemble a raw portion of the file without using section information."""
        if offset >= len(self.cof.data):
            print(f"Offset 0x{offset:X} is beyond the file size (0x{len(self.cof.data):X})")
            return
        
        actual_size = min(size, len(self.cof.data) - offset)
        if actual_size < size:
            print(f"Warning: Requested size extends beyond file. Truncating from {size} to {actual_size} bytes.")
        
        print(f"Raw disassembly from offset 0x{offset:X}, size {actual_size} bytes:")
        
        # Use the same disassembly logic but just for the raw data
        data = self.cof.data[offset:offset + actual_size]
        try:
            self._find_branch_targets(data)
            self._disassemble_section_data(data, offset)
        except Exception as e:
            print(f"Error during disassembly: {str(e)}")
            self._fallback_hex_dump(data)

def main():
    parser = argparse.ArgumentParser(description="Disassemble COIL Object Format (COF) files")
    parser.add_argument('file', help="The COF file to disassemble")
    parser.add_argument('--section', '-s', type=int, help="Disassemble the specified section (by index)")
    parser.add_argument('--all', '-a', action='store_true', help="Disassemble all executable sections")
    parser.add_argument('--raw', '-r', action='store_true', help="Disassemble raw data (ignoring section structure)")
    parser.add_argument('--offset', '-o', type=lambda x: int(x, 0), default=0, help="Offset for raw disassembly (only with --raw)")
    parser.add_argument('--size', type=lambda x: int(x, 0), default=256, help="Size for raw disassembly (only with --raw)")
    parser.add_argument('--force', '-f', action='store_true', help="Force disassembly even for non-executable sections")
    
    args = parser.parse_args()
    
    try:
        # Display file stats
        file_stats = os.stat(args.file)
        print(f"File: {args.file}")
        print(f"Size: {file_stats.st_size} bytes")
        print()
        
        # If raw mode, create a simplified disassembler without parsing the COF structure
        if args.raw:
            class SimpleData:
                def __init__(self, data):
                    self.data = data
                    self.file_size = len(data)
            
            with open(args.file, 'rb') as f:
                data = f.read()
            
            simple_cof = SimpleData(data)
            disasm = CoilDisassembler(simple_cof)
            disasm.disassemble_raw(args.offset, args.size)
            return 0
        
        cof = CofFile(args.file)
        disasm = CoilDisassembler(cof)
        
        if args.section is not None:
            disasm.disassemble_section(args.section)
        elif args.all:
            # Find all executable sections (or all sections if --force)
            sections_to_disasm = []
            for i, section in enumerate(cof.section_headers):
                if args.force or (section.flags & SectionFlags.COF_SEC_FLAG_EXEC):
                    sections_to_disasm.append(i)
            
            if not sections_to_disasm:
                print("No executable sections found in the file. Use --force to disassemble non-executable sections.")
                return 0
            
            for i, section_idx in enumerate(sections_to_disasm):
                disasm.disassemble_section(section_idx)
                if i < len(sections_to_disasm) - 1:
                    print()  # Empty line between sections
        else:
            # Find the first executable section (or first section if --force)
            exec_section = None
            for i, section in enumerate(cof.section_headers):
                if args.force or (section.flags & SectionFlags.COF_SEC_FLAG_EXEC):
                    exec_section = i
                    break
            
            if exec_section is not None:
                disasm.disassemble_section(exec_section)
            else:
                print("No executable sections found in the file. Use --force to disassemble non-executable sections.")
                return 1
            
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())