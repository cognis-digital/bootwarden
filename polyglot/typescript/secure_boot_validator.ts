import * as fs from 'fs';
import * as path from 'path';

// ============================================================================
// UEFI/PE Header Structures
// ============================================================================

interface DosHeader {
  e_magic: number; // MZ (0x5A4D)
  e_cblp: number;
  e_cp: number;
  e_crlc: number;
  e_cparhdr: number;
  e_minalloc: number;
  e_maxalloc: number;
  e_ss: number;
  e_sp: number;
  e_csum: number;
  e_ip: number;
  e_cs: number;
  e_lfarlc: number;
  e_ovno: number;
  e_res: Uint8Array<16>;
  e_oemid: number;
  e_oeminfo: Uint8Array<10>;
  e_lfanew: number; // Offset to PE header
}

interface PeHeader {
  signature: string; // "PE\0\0" (0x50450000)
  machine: number; // i386=0x14c, x64=0x8664
  numberOfSections: number;
  timestamp: number;
}

interface CoffHeader {
  characteristics: number;
  timeStamp: number;
  symbolTablePtr: number;
  numberOfSymbols: number;
  optionalHeaderSize: number;
  codeViewPointer: number;
  machine: number;
  sizeOfCode: number;
  sizeOfInitializedData: number;
  sizeOfUninitializedData: number;
  entryPointRva: number;
  baseOfCode: number;
  imageBase: number;
}

interface SectionHeader {
  name: string; // null-terminated ASCII
  virtualSize: number;
  virtualAddress: number;
  sizeOfRawData: number;
  pointerToRawData: number;
  sectionPointer: number;
  characteristics: number;
}

// ============================================================================
// Known Threat Signatures Database
// ============================================================================

interface ThreatEntry {
  name: string;
  signature: Uint8Array | string; // Hex or raw bytes
  category: 'SMM' | 'ROOTKIT' | 'BACKDOOR' | 'MALWARE';
  severity: number; // 1-5
}

const KNOWN_THREATS: ThreatEntry[] = [
  {
    name: 'Ntfs.sys SMM Rootkit',
    signature: Uint8Array.from([0x4E, 0x74, 0x66, 0x73]), // "Ntfs"
    category: 'SMM',
    severity: 5,
  },
  {
    name: 'Generic SMM Handler Pattern',
    signature: Uint8Array.from([0x4D, 0x72, 0x6B, 0x69]), // "mrki" pattern
    category: 'SMM',
    severity: 3,
  },
];

// ============================================================================
// Secure Boot Key Database (Sample)
// ============================================================================

interface SecureBootKey {
  name: string;
  thumbprint: Uint8Array;
  algorithm: 'RSA' | 'ECDSA';
}

const KNOWN_SECURE_BOOT_KEYS: SecureBootKey[] = [
  {
    name: 'Microsoft Test Key 1',
    thumbprint: Uint8Array.from([0x3A, 0x4F, 0x6D, 0x75]), // Sample
    algorithm: 'RSA',
  },
];

// ============================================================================
// Utility Functions
// ============================================================================

function readUint16LE(buffer: Uint8Array, offset: number): number {
  return (buffer[offset] | buffer[offset + 1] << 8);
}

function readUint32LE(buffer: Uint8Array, offset: number): number {
  return (buffer[offset] |
    buffer[offset + 1] << 8 |
    buffer[offset + 2] << 16 |
    buffer[offset + 3] << 24);
}

function readStringLE(buffer: Uint8Array, offset: number, maxLen: number = 50): string {
  let result = '';
  for (let i = 0; i < maxLen && i < buffer.length - offset; i++) {
    if (buffer[offset + i] === 0) break;
    result += String.fromCharCode(buffer[offset + i]);
  }
  return result.trim();
}

function readUint64LE(buffer: Uint8Array, offset: number): bigint {
  const high = readUint32LE(buffer, offset);
  const low = readUint32LE(buffer, offset + 4);
  return (BigInt(high) << BigInt(32)) | BigInt(low);
}

function isExecutableSection(characteristics: number): boolean {
  return characteristics & 0x20; // IMAGE_SCN_MEM_EXECUTE
}

function isInitializedData(characteristics: number): boolean {
  return characteristics & 0x40; // IMAGE_SCN_CNT_INITIALIZED_DATA
}

// ============================================================================
// PE Parser
// ============================================================================

class PeParser {
  private buffer: Uint8Array;
  private dosHeader: DosHeader | null = null;
  private peHeader: PeHeader | null = null;
  private coffHeader: CoffHeader | null = null;
  private sections: SectionHeader[] = [];

  constructor(buffer: Uint8Array) {
    this.buffer = buffer;
  }

  parse(): boolean {
    // Check DOS header magic
    if (this.buffer.length < 64 || this.readUint16LE(this.buffer, 0) !== 0x5A4D) {
      return false;
    }

    // Read DOS header fields
    this.dosHeader = {
      e_magic: this.readUint16LE(this.buffer, 0),
      e_cblp: this.readUint16LE(this.buffer, 2),
      e_cp: this.readUint16LE(this.buffer, 4),
      e_crlc: this.readUint16LE(this.buffer, 6),
      e_cparhdr: this.readUint16LE(this.buffer, 8),
      e_minalloc: this.readUint16LE(this.buffer, 10),
      e_maxalloc: this.readUint16LE(this.buffer, 12),
      e_ss: this.readUint16LE(this.buffer, 14),
      e_sp: this.readUint16LE(this.buffer, 16),
      e_csum: this.readUint16LE(this.buffer, 18),
      e_ip: this.readUint16LE(this.buffer, 20),
      e_cs: this.readUint16LE(this.buffer, 22),
      e_lfarlc: this.readUint16LE(this.buffer, 24),
      e_ovno: this.readUint16LE(this.buffer, 26),
      e_res: new Uint8Array(this.buffer.slice(28, 44)),
      e_oemid: this.readUint16LE(this.buffer, 44),
      e_oeminfo: new Uint8Array(this.buffer.slice(46, 56)),
      e_lfanew: this.readUint32LE(this.buffer, 60),
    };

    // Check PE header signature
    if (this.dosHeader!.e_lfanew >= this.buffer.length - 4) {
      return false;
    }

    const peSig = this.buffer.slice(this.dosHeader!.e_lfanew, this.dosHeader!.e_lfanew + 4);
    if (peSig[0] !== 0x50 || peSig[1] !== 0x45) { // "PE"
      return false;
    }

    // Parse PE header
    const machine = this.readUint16LE(this.buffer, this.dosHeader!.e_lfanew + 4);
    const numberOfSections = this.readUint16LE(this.buffer, this.dosHeader!.e_lfanew + 6);
    const timestamp = this.readUint32LE(this.buffer, this.dosHeader!.e_lfanew + 8);

    // Validate machine type (i386=0x14c, x64=0x8664)
    if (machine !== 0x14c && machine !== 0x8664) {
      console.warn(`Warning: Unknown PE machine type: 0x${machine.toString(16).padStart(4, '0')}`);
    }

    this.peHeader = {
      signature: String.fromCharCode(peSig[0], peSig[1]),
      machine,
      numberOfSections,
      timestamp,
    };

    // Parse sections
    const sectionOffset = this.dosHeader!.e_lfanew + 24;
    for (let i = 0; i < Math.min(numberOfSections, 96); i++) {
      const nameLen = this.readUint16LE(this.buffer, sectionOffset + i * 40);
      if (nameLen === 0) break;

      const nameStart = sectionOffset + i * 40 + 2;
      let name = '';
      for (let j = 0; j < Math.min(nameLen, 8); j++) {
        name += String.fromCharCode(this.buffer[nameStart + j]);
      }

      this.sections.push({
        name: name || `Section${i}`,
        virtualSize: this.readUint32LE(this.buffer, sectionOffset + i * 40 + 6),
        virtualAddress: this.readUint32LE(this.buffer, sectionOffset + i * 40 + 10),
        sizeOfRawData: this.readUint32LE(this.buffer, sectionOffset + i * 40 + 14),
        pointerToRawData: this.readUint32LE(this.buffer, sectionOffset + i * 40 + 18),
        sectionPointer: this.readUint32LE(this.buffer, sectionOffset + i * 40 + 22),
        characteristics: this.readUint32LE(this.buffer, sectionOffset + i * 40 + 26),
      });
    }

    return true;
  }

  getValidSections(): SectionHeader[] {
    return this.sections.filter(s => isExecutableSection(s.characteristics) || isInitializedData(s.characteristics));
  }

  getTotalSize(): number {
    let total = 0;
    for (const section of this.getValidSections()) {
      total += section.virtualSize;
    }
    return total;
  }

  getEntryPointRva(): number | null {
    if (!this.coffHeader) {
      // Try to read from optional header area
      const optOffset = this.dosHeader!.e_lfanew + 24;
      if (optOffset < this.buffer.length - 8) {
        this.coffHeader = {
          characteristics: this.readUint32LE(this.buffer, optOffset),
          timeStamp: this.readUint32LE(this.buffer, optOffset + 4),
          symbolTablePtr: this.readUint32LE(this.buffer, optOffset + 8),
          numberOfSymbols: this.readUint32LE(this.buffer, optOffset + 12),
          optionalHeaderSize: this.readUint32LE(this.buffer, optOffset + 16),
          codeViewPointer: this.readUint32LE(this.buffer, optOffset + 20),
          machine: this.readUint16LE(this.buffer, optOffset + 24),
          sizeOfCode: this.readUint32LE(this.buffer, optOffset + 28),
          sizeOfInitializedData: this.readUint32LE(this.buffer, optOffset + 32),
          sizeOfUninitializedData: this.readUint32LE(this.buffer, optOffset + 36),
          entryPointRva: this.readUint32LE(this.buffer, optOffset + 40),
          baseOfCode: this.readUint32LE(this.buffer, optOffset + 44),
          imageBase: this.readUint32LE(this.buffer, optOffset + 48),
        };
      }
    }
    return this.coffHeader?.entryPointRva || null;
  }

  getTimestamp(): number | null {
    if (!this.peHeader) return null;
    // Convert DOS timestamp to Unix epoch
    const dosTime = this.peHeader.timestamp;
    const dosDate = (dosTime >> 25) & 0x7f;
    const dosDayOfWeek = (dosTime >> 21) & 0x1f;
    const dosYear = (dosTime >> 55) & 0x7f;
    
    // DOS date: YYYY-MM-DD, where YYYY is year from 1980
    const year = 1980 + dosYear;
    const month = dosDate / 2;
    const day = (dosDate % 2) * 32 + ((dosTime >> 16) & 0x3f);

    // Approximate Unix timestamp calculation
    return Date.UTC(year, month - 1, day).getTime() / 1000;
  }
}

// ============================================================================
// Secure Boot Key Validator
// ============================================================================

interface ValidationResult {
  passed: boolean;
  issues: Array<{ level: 'ERROR' | 'WARNING' | 'INFO'; message: string; details?: any }>;
  metadata: {
    totalSize: number;
    validSections: number;
    entryPointRva: number | null;
    timestamp: number | null;
  };
}

class SecureBootValidator {
  private peParser: PeParser;
  private knownKeys: Map<string, SecureBootKey>;

  constructor(knownKeys: SecureBootKey[] = KNOWN_SECURE_BOOT_KEYS) {
    this.knownKeys = new Map();
    for (const key of knownKeys) {
      const thumbprintHex = Array.from(key.thumbprint).map(b => b.toString(16).padStart(2, '0')).join('');
      this.knownKeys.set(thumbprintHex, key);
    }
  }

  validate(buffer: Uint8Array): ValidationResult {
    const result: ValidationResult = {
      passed: true,
      issues: [],
      metadata: {
        totalSize: buffer.length,
        validSections: 0,
        entryPointRva: null,
        timestamp: null,
      },
    };

    // Parse PE header
    if (!this.peParser.parse()) {
      result.passed = false;
      result.issues.push({
        level: 'ERROR',
        message: 'Failed to parse PE header - not a valid UEFI executable',
        details: { bufferLength: buffer.length },
      });
      return result;
    }

    // Extract metadata
    result.metadata.totalSize = this.peParser.getTotalSize();
    result.metadata.validSections = this.peParser.getValidSections().length;
    result.metadata.entryPointRva = this.peParser.getEntryPointRva();
    result.metadata.timestamp = this.peParser.getTimestamp();

    // Check for missing Secure Boot keys (simulated check)
    const foundKeys: string[] = [];
    
    // Simulate scanning sections for certificate data
    // In real implementation, would parse CERTIFICATE structure from section headers
    if (result.metadata.validSections === 0) {
      result.issues.push({
        level: 'WARNING',
        message: 'No valid executable sections found',
        details: {},
      });
    }

    // Check for unsigned modules (simulated - check for common section names)
    const signedSections = new Set<string>();
    for (const section of this.peParser.getValidSections()) {
      if (section.name.toLowerCase().includes('cert') || 
          section.name.toLowerCase().includes('auth')) {
        signedSections.add(section.name);
      }
    }

    if (signedSections.size === 0) {
      result.issues.push({
        level: 'WARNING',
        message: 'No obvious certificate sections found - may be unsigned modules',
        details: { signedSectionCount: 0 },
      });
    } else {
      result.issues.push({
        level: 'INFO',
        message: `Found ${signedSections.size} potential certificate section(s)`,
        details: { sectionNames: Array.from(signedSections) },
      });
    }

    // Check for S3 boot script vulnerabilities (simulated pattern matching)
    const s3Scripts = this.scanForS3BootScripts(buffer);
    if (s3Scripts.length > 0) {
      result.issues.push({
        level: 'WARNING',
        message: `Found ${s3Scripts.length} potential S3 boot script reference(s)`,
        details: s3Scripts,
      });
    }

    // Check for known SMM threats
    const smmThreats = this.scanForSMMThreats(buffer);
    if (smmThreats.length > 0) {
      result.passed = false;
      for (const threat of smmThreats) {
        result.issues.push({
          level: 'ERROR',
          message: `Potential SMM threat detected: ${