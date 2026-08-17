import { Buffer } from 'buffer';

// ============================================================================
// GUID Constants - UEFI Specification
// ============================================================================

const GUIDS = {
  // PE Signature Block
  EFI_CERT_X509_GUID: [0x14, 0x1, 0x13, 0x1f, 0xf8, 0x7d, 0x11, 0xd6, 0x91, 0x4e, 0x08],
  EFI_CERT_CHAIN_GUID: [0x14, 0x2, 0x13, 0x1f, 0xf8, 0x7d, 0x11, 0xd6, 0x91, 0x4e, 0x08],
  
  // Secure Boot Keys
  EFI_PK_GUID: [0x1a, 0x2, 0x13, 0x1f, 0xf8, 0x7d, 0x11, 0xd6, 0x91, 0x4e, 0x08],
  EFI_TK_GUID: [0x1a, 0x3, 0x13, 0x1f, 0xf8, 0x7d, 0x11, 0xd6, 0x91, 0x4e, 0x08],
  EFI_EK_GUID: [0x1a, 0x4, 0x13, 0x1f, 0xf8, 0x7d, 0x11, 0xd6, 0x91, 0x4e, 0x08],
  EFI_RK_GUID: [0x1a, 0x5, 0x13, 0x1f, 0xf8, 0x7d, 0x11, 0xd6, 0x91, 0x4e, 0x08],
  
  // S3 Boot Script
  EFI_S3_BOOT_SCRIPT_GUID: [0x5a, 0x2, 0x13, 0x1f, 0xf8, 0x7d, 0x11, 0xd6, 0x91, 0x4e, 0x08],
  
  // SMM Handlers (Common Patterns)
  EFI_SMM_HANDLER_GUID: [0x5b, 0x3, 0x13, 0x1f, 0xf8, 0x7d, 0x11, 0xd6, 0x91, 0x4e, 0x08],
  
  // PE Signature Block GUIDs
  EFI_IMAGE_DATA_DIRECTORY: [0x5c, 0x4, 0x13, 0x1f, 0xf8, 0x7d, 0x11, 0xd6, 0x91, 0x4e, 0x08],
};

// ============================================================================
// Type Definitions
// ============================================================================

interface Guid {
  data: number[];
}

interface PeHeader {
  magic: number; // 0x205 or 0x206 (little/big endian)
  machine: number;
  numberOfSections: number;
  timestamp: number;
  characteristics: number;
  optionalHeaderOffset: number;
}

interface PeOptionalHeader {
  magic: number; // 0x10b or 0x107 (PE32/PE32+)
  majorLinkerVersion: number;
  majorOperatingSystemVersion: number;
  imageBase: bigint;
  sectionAlignment: number;
  fileAlignment: number;
  characteristics: number;
}

interface PeSection {
  name: string;
  virtualSize: number;
  virtualAddress: number;
  rawSize: number;
  rawDataOffset: number;
  characteristics: number;
}

interface CertificateBlock {
  guid: Guid;
  length: number;
  offset: number;
  certificateType: string;
}

interface SecureBootKey {
  type: 'PK' | 'TK' | 'EK' | 'RK';
  guid: Guid;
  length: number;
  offset: number;
  rawData: Uint8Array;
}

interface S3BootScript {
  guid: Guid;
  length: number;
  offset: number;
  rawData: Uint8Array;
}

interface SmmHandler {
  guid: Guid;
  length: number;
  offset: number;
  rawData: Uint8Array;
}

interface FirmwareAnalysisResult {
  peHeader: PeHeader | null;
  optionalHeader: PeOptionalHeader | null;
  sections: PeSection[];
  certificates: CertificateBlock[];
  secureBootKeys: SecureBootKey[];
  s3BootScripts: S3BootScript[];
  smmHandlers: SmmHandler[];
  issues: AnalysisIssue[];
}

interface AnalysisIssue {
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  message: string;
  location?: number;
  details?: any;
}

// ============================================================================
// Binary Utilities
// ============================================================================

function readUint16(buffer: Uint8Array, offset: number): number {
  return (buffer[offset] << 8) | buffer[offset + 1];
}

function readUint32(buffer: Uint8Array, offset: number): number {
  return (buffer[offset] << 24) | (buffer[offset + 1] << 16) | 
         (buffer[offset + 2] << 8) | buffer[offset + 3];
}

function readUint64(buffer: Uint8Array, offset: number): bigint {
  const high = readUint32(buffer, offset);
  const low = readUint32(buffer, offset + 4);
  return (BigInt(high) << BigInt(32)) | BigInt(low);
}

function compareGuid(guid1: Guid, guid2: Guid): boolean {
  for (let i = 0; i < 16; i++) {
    if (guid1.data[i] !== guid2.data[i]) return false;
  }
  return true;
}

function createGuid(data: number[]): Guid {
  return { data };
}

// ============================================================================
// PE Header Parsing
// ============================================================================

class PeParser {
  private buffer: Uint8Array;
  private offset: number = 0;

  constructor(buffer: Uint8Array) {
    this.buffer = buffer;
  }

  parse(): PeHeader | null {
    // Check minimum header size (48 bytes for PE32, 64 for PE32+)
    if (this.buffer.length < 64) return null;

    const magic = readUint16(this.buffer, 0);
    
    // Validate PE signature
    if (magic !== 0x205 && magic !== 0x206) {
      console.warn('Invalid PE magic number:', hex(magic));
      return null;
    }

    const header: PeHeader = {
      magic,
      machine: readUint16(this.buffer, 4),
      numberOfSections: readUint16(this.buffer, 20),
      timestamp: readUint32(this.buffer, 24),
      characteristics: readUint32(this.buffer, 28),
      optionalHeaderOffset: readUint32(this.buffer, 32) + 64, // Adjust for PE header offset
    };

    return header;
  }

  parseOptional(header: PeHeader): PeOptionalHeader | null {
    if (header.optionalHeaderOffset >= this.buffer.length) return null;

    const magic = readUint16(this.buffer, header.optionalHeaderOffset);
    
    // Validate optional header magic
    if (magic !== 0x10b && magic !== 0x107) {
      console.warn('Invalid PE32/PE32+ optional header magic:', hex(magic));
      return null;
    }

    const optional: PeOptionalHeader = {
      magic,
      majorLinkerVersion: this.buffer[header.optionalHeaderOffset + 6],
      majorOperatingSystemVersion: readUint16(this.buffer, header.optionalHeaderOffset + 8),
      imageBase: readUint64(this.buffer, header.optionalHeaderOffset + 24),
      sectionAlignment: readUint32(this.buffer, header.optionalHeaderOffset + 32),
      fileAlignment: readUint32(this.buffer, header.optionalHeaderOffset + 36),
      characteristics: readUint32(this.buffer, header.optionalHeaderOffset + 48),
    };

    return optional;
  }

  parseSections(header: PeHeader): PeSection[] {
    const sections: PeSection[] = [];
    
    // Each section header is 40 bytes
    for (let i = 0; i < header.numberOfSections && i < 96; i++) {
      const offset = header.optionalHeaderOffset + 24 + (i * 40);
      
      if (offset >= this.buffer.length) break;

      const nameLength = readUint16(this.buffer, offset);
      const virtualSize = readUint32(this.buffer, offset + 8);
      const virtualAddress = readUint32(this.buffer, offset + 12);
      const rawSize = readUint32(this.buffer, offset + 16);
      const rawDataOffset = readUint32(this.buffer, offset + 20);
      const characteristics = readUint32(this.buffer, offset + 24);

      // Pad name to 8 bytes (null-terminated)
      let name = '';
      for (let j = 0; j < Math.min(8, nameLength - 1); j++) {
        name += String.fromCharCode(this.buffer[offset + 36 + j]);
      }

      sections.push({
        name: name.trim(),
        virtualSize,
        virtualAddress,
        rawSize,
        rawDataOffset,
        characteristics,
      });
    }

    return sections;
  }

  parseCertificates(header: PeHeader): CertificateBlock[] {
    const certificates: CertificateBlock[] = [];
    
    // Look for certificate blocks in the optional header
    if (header.optionalHeaderOffset >= this.buffer.length) return certificates;

    const optional = this.parseOptional(header);
    if (!optional) return certificates;

    // Check for EFI_CERT_X509_GUID and EFI_CERT_CHAIN_GUID
    const certGuids = [GUIDS.EFI_CERT_X509_GUID, GUIDS.EFI_CERT_CHAIN_GUID];
    
    for (const guid of certGuids) {
      const offset = header.optionalHeaderOffset + 48; // After characteristics
      
      while (offset < this.buffer.length - 16) {
        const currentGuid: Guid = { data: [] };
        
        // Read GUID
        for (let i = 0; i < 16; i++) {
          currentGuid.data[i] = this.buffer[offset + i];
        }

        if (!compareGuid(currentGuid, guid)) break;

        const length = readUint32(this.buffer, offset + 16);
        
        // Validate length (reasonable range: 64-8192 bytes)
        if (length < 64 || length > 8192) {
          offset += 20;
          continue;
        }

        certificates.push({
          guid,
          length,
          offset,
          certificateType: guid === GUIDS.EFI_CERT_X509_GUID ? 'X.509' : 'Chain',
        });

        // Move to next potential block (GUID + 4 byte length)
        offset += 20;
      }
    }

    return certificates;
  }

  parseSecureBootKeys(header: PeHeader): SecureBootKey[] {
    const keys: SecureBootKey[] = [];
    
    // Look for secure boot key GUIDs in the optional header
    if (header.optionalHeaderOffset >= this.buffer.length) return keys;

    const optional = this.parseOptional(header);
    if (!optional) return keys;

    const keyGuids = [GUIDS.EFI_PK_GUID, GUIDS.EFI_TK_GUID, 
                     GUIDS.EFI_EK_GUID, GUIDS.EFI_RK_GUID];
    
    for (const guid of keyGuids) {
      const offset = header.optionalHeaderOffset + 48; // After characteristics
      
      while (offset < this.buffer.length - 16) {
        const currentGuid: Guid = { data: [] };
        
        // Read GUID
        for (let i = 0; i < 16; i++) {
          currentGuid.data[i] = this.buffer[offset + i];
        }

        if (!compareGuid(currentGuid, guid)) break;

        const length = readUint32(this.buffer, offset + 16);
        
        // Validate length (reasonable range: 64-8192 bytes)
        if (length < 64 || length > 8192) {
          offset += 20;
          continue;
        }

        keys.push({
          type: guid === GUIDS.EFI_PK_GUID ? 'PK' :
                guid === GUIDS.EFI_TK_GUID ? 'TK' :
                guid === GUIDS.EFI_EK_GUID ? 'EK' : 'RK',
          guid,
          length,
          offset,
          rawData: this.buffer.slice(offset + 20, offset + 20 + length),
        });

        // Move to next potential block (GUID + 4 byte length)
        offset += 20;
      }
    }

    return keys;
  }

  parseS3BootScripts(header: PeHeader): S3BootScript[] {
    const scripts: S3BootScript[] = [];
    
    // Look for S3 boot script GUIDs in the optional header
    if (header.optionalHeaderOffset >= this.buffer.length) return scripts;

    const optional = this.parseOptional(header);
    if (!optional) return scripts;

    let offset = header.optionalHeaderOffset + 48; // After characteristics
    
    while (offset < this.buffer.length - 16) {
      const currentGuid: Guid = { data: [] };
      
      // Read GUID
      for (let i = 0; i < 16; i++) {
        currentGuid.data[i] = this.buffer[offset + i];
      }

      if (!compareGuid(currentGuid, GUIDS.EFI_S3_BOOT_SCRIPT_GUID)) break;

      const length = readUint32(this.buffer, offset + 16);
      
      // Validate length (reasonable range: 64-8192 bytes)
      if (length < 64 || length > 8192) {
        offset += 20;
        continue;
      }

      scripts.push({
        guid,
        length,
        offset,
        rawData: this.buffer.slice(offset + 20, offset + 20 + length),
      });

      // Move to next potential block (GUID + 4 byte length)
      offset += 20;
    }

    return scripts;
  }

  parseSmmHandlers(header: PeHeader): SmmHandler[] {
    const handlers: SmmHandler[] = [];
    
    // Look for SMM handler GUIDs in the optional header
    if (header.optionalHeaderOffset >= this.buffer.length) return handlers;

    const optional = this.parseOptional(header);
    if (!optional) return handlers;

    let offset = header.optionalHeaderOffset + 48; // After characteristics
    
    while (offset < this.buffer.length - 16) {
      const currentGuid: Guid = { data: [] };
      
      // Read GUID
      for (let i = 0; i < 16; i++) {
        currentGuid.data[i] = this.buffer[offset + i];
      }

      if (!compareGuid(currentGuid, GUIDS.EFI_SMM_HANDLER_GUID)) break;

      const length = readUint32(this.buffer, offset + 16);
      
      // Validate length (reasonable range: 64-8192 bytes)
      if (length < 64 || length > 8192) {
        offset += 20;
        continue;
      }

      handlers.push({
        guid,
        length,
        offset,
        rawData: this.buffer.slice(offset + 20, offset + 20 + length),
      });

      // Move to next potential block (GUID + 4 byte length)
      offset += 20;
    }

    return handlers;
  }
}

//