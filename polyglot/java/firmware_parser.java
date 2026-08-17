package polyglot.java;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * UEFI Firmware Parser for uefiscan tool.
 * Parses EFI headers, signature directories, PE sections, SMM regions, and NVRAM variables.
 */
public class firmware_parser {

    // Constants
    private static final int EFI_HEADER_SIZE = 32;
    private static final int SIGNATURE_DIR_ENTRY_SIZE = 16;
    private static final int PE_COFF_HEADER_SIZE = 20;
    private static final int PE_SECTION_HEADER_SIZE = 40;

    // Secure Boot key types (from UEFI spec)
    private static final short EFI_CERT_TYPE_X509 = 0x01;
    private static final short EFI_CERT_TYPE_PFX = 0x02;
    private static final short EFI_CERT_TYPE_RAW = 0x03;

    // SMM threat patterns (hex strings for common signatures)
    private static final List<Pattern> SMM_THREAT_PATTERNS = List.of(
        Pattern.compile("SMM_RUN16"),
        Pattern.compile("SMM_RUN32"),
        Pattern.compile("SMM_RUN64")
    );

    /**
     * Main entry point with demo.
     */
    public static void main(String[] args) {
        // Create sample firmware data (minimal valid EFI header + signature dir)
        byte[] sampleFirmware = createSampleFirmware();

        FirmwareParser parser = new FirmwareParser(sampleFirmware);
        
        System.out.println("=== UEFI FIRMWARE PARSER RESULTS ===\n");
        
        // 1. Header Analysis
        printHeaderAnalysis(parser.getHeader());
        
        // 2. Signature Directory & Secure Boot Keys
        printSignatureDirectory(parser.getSignatureDirEntries());
        
        // 3. PE/COFF Sections (Modules)
        printPESections(parser.getPESections());
        
        // 4. SMM Region Analysis
        printSMMAnalysis(parser.getSMMRegions());
        
        // 5. Summary Report
        printSummaryReport(parser);
    }

    /**
     * Creates a minimal sample firmware for testing.
     */
    private static byte[] createSampleFirmware() {
        ByteBuffer buffer = ByteBuffer.allocate(2048).order(ByteOrder.LITTLE_ENDIAN);
        
        // EFI Header (32 bytes)
        int headerSize = 32;
        short signatureTablePointerOffset = 16;
        int signatureTablePointerLength = 16;
        short numberOfVolumes = 1;
        short reserved = 0;
        short checksum = 1; // Will be calculated
        
        buffer.putShort((short) headerSize);
        buffer.putInt(0x46534945); // "ISFI" magic (little-endian: 0x45495346)
        buffer.putShort((short) signatureTablePointerOffset);
        buffer.putInt(signatureTablePointerLength);
        buffer.putShort(numberOfVolumes);
        buffer.putShort(reserved);
        
        // Signature Directory Entry 1 - Signed module
        int sigDirEntrySize = SIGNATURE_DIR_ENTRY_SIZE;
        short type = EFI_CERT_TYPE_X509;
        short length = 256;
        int offset = headerSize + (signatureTablePointerLength / 4);
        
        buffer.putShort(sigDirEntrySize);
        buffer.putShort(type);
        buffer.putShort(length);
        buffer.putInt(offset);
        
        // Signature Directory Entry 2 - Unsigned module
        type = EFI_CERT_TYPE_RAW;
        length = 128;
        offset += SIGNATURE_DIR_ENTRY_SIZE;
        
        buffer.putShort(sigDirEntrySize);
        buffer.putShort(type);
        buffer.putShort(length);
        buffer.putInt(offset);
        
        // Signature Directory Entry 3 - SMM region marker
        type = EFI_CERT_TYPE_RAW;
        length = 64;
        offset += SIGNATURE_DIR_ENTRY_SIZE;
        
        buffer.putShort(sigDirEntrySize);
        buffer.putShort(type);
        buffer.putShort(length);
        buffer.putInt(offset);
        
        // PE Section Headers (simulated)
        int peHeaderOffset = headerSize + 2 * SIGNATURE_DIR_ENTRY_SIZE;
        short peHeaderSize = PE_COFF_HEADER_SIZE;
        short numberOfSections = 3;
        
        buffer.putShort(peHeaderSize);
        buffer.putInt(0x14c); // Machine type (i386)
        buffer.putShort((short)numberOfSections);
        buffer.putInt(0); // TimeDateStamp
        buffer.putInt(0x10b); // Characteristics
        
        // Section 1: .text - Signed code
        int sectionHeaderOffset = peHeaderOffset + PE_COFF_HEADER_SIZE;
        short nameLength = 8;
        short type = 0x0002; // SMTYPE_CODE
        short flags = 0x60000040;
        long virtualAddress = 0x10000;
        long sizeOfRawData = 0x1000;
        
        buffer.putShort(nameLength);
        buffer.putShort(type);
        buffer.putInt(0); // VirtualSize
        buffer.putLong(flags);
        buffer.putLong(virtualAddress);
        buffer.putLong(sizeOfRawData);
        
        sectionHeaderOffset += PE_SECTION_HEADER_SIZE;
        
        // Section 2: .data - Unsigned data
        nameLength = 6;
        type = 0x0003; // SMTYPE_DATA
        flags = 0x40000040;
        virtualAddress = 0x11000;
        sizeOfRawData = 0x800;
        
        buffer.putShort(nameLength);
        buffer.putShort(type);
        buffer.putInt(0);
        buffer.putLong(flags);
        buffer.putLong(virtualAddress);
        buffer.putLong(sizeOfRawData);
        
        sectionHeaderOffset += PE_SECTION_HEADER_SIZE;
        
        // Section 3: .smm - SMM region
        nameLength = 4;
        type = 0x8002; // SMTYPE_SMM
        flags = 0x60000040;
        virtualAddress = 0x12000;
        sizeOfRawData = 0x4000;
        
        buffer.putShort(nameLength);
        buffer.putShort(type);
        buffer.putInt(0);
        buffer.putLong(flags);
        buffer.putLong(virtualAddress);
        buffer.putLong(sizeOfRawData);
        
        // SMM Region Info (after sections)
        int smmRegionOffset = sectionHeaderOffset;
        short smmSize = 128;
        short smmAttributes = 0x0003;
        long smmVirtualAddress = 0x13000;
        
        buffer.putShort(smmSize);
        buffer.putShort(smmAttributes);
        buffer.putLong(smmVirtualAddress);
        
        // NVRAM Variables (simulated)
        int nvramOffset = smmRegionOffset + 48;
        short nvramSize = 256;
        short nvramType = 0x0100;
        long nvramVirtualAddress = 0x14000;
        
        buffer.putShort(nvramSize);
        buffer.putShort(nvramType);
        buffer.putLong(nvramVirtualAddress);
        
        // Calculate checksum (simplified)
        int runningSum = 0;
        for (int i = 0; i < buffer.position(); i++) {
            runningSum += buffer.get(i) & 0xFF;
        }
        buffer.putInt(0, (runningSum & 0xFFFF));
        
        return buffer.array();
    }

    /**
     * UEFI Header structure.
     */
    static class EfiHeader {
        int headerSize;
        String magic;
        short signatureTablePointerOffset;
        int signatureTablePointerLength;
        short numberOfVolumes;
        short reserved;
        int checksum;

        void parse(ByteBuffer buffer) {
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            
            this.headerSize = buffer.getShort();
            this.magic = new String(buffer.array(), 2, 4);
            this.signatureTablePointerOffset = buffer.getShort();
            this.signatureTablePointerLength = buffer.getInt();
            this.numberOfVolumes = buffer.getShort();
            this.reserved = buffer.getShort();
            this.checksum = buffer.getInt();
        }

        @Override
        public String toString() {
            return "EfiHeader{" +
                   "headerSize=" + headerSize +
                   ", magic='" + magic + '\'' +
                   ", signatureTablePointerOffset=" + signatureTablePointerOffset +
                   ", signatureTablePointerLength=" + signatureTablePointerLength +
                   ", numberOfVolumes=" + numberOfVolumes +
                   ", reserved=" + reserved +
                   ", checksum=" + checksum +
                   '}';
        }
    }

    /**
     * Signature Directory Entry.
     */
    static class SigDirEntry {
        int entrySize;
        short type;
        short length;
        int offset;
        String description;

        void parse(ByteBuffer buffer) {
            this.entrySize = buffer.getShort();
            this.type = buffer.getShort();
            this.length = buffer.getShort();
            this.offset = buffer.getInt();
            
            // Map type to description
            switch (this.type) {
                case EFI_CERT_TYPE_X509:
                    this.description = "X.509 Certificate";
                    break;
                case EFI_CERT_TYPE_PFX:
                    this.description = "PFX Package";
                    break;
                case EFI_CERT_TYPE_RAW:
                    this.description = "Raw Data (possibly SMM)";
                    break;
                default:
                    this.description = "Unknown Type (" + this.type + ")";
                    break;
            }
        }

        @Override
        public String toString() {
            return "SigDirEntry{" +
                   "entrySize=" + entrySize +
                   ", type=0x" + Integer.toHexString(type) +
                   ", length=" + length +
                   ", offset=" + offset +
                   ", description='" + description + '\'' +
                   '}';
        }
    }

    /**
     * PE/COFF Section.
     */
    static class PeSection {
        String name;
        short type;
        long virtualAddress;
        long sizeOfRawData;
        boolean isSigned;
        String description;

        void parse(ByteBuffer buffer) {
            int nameLength = buffer.getShort();
            this.name = new String(buffer.array(), buffer.position(), nameLength);
            buffer.position(buffer.position() + nameLength);
            
            this.type = buffer.getShort();
            this.virtualAddress = buffer.getLong();
            this.sizeOfRawData = buffer.getLong();
            
            // Infer signing from type
            if (this.type == 0x8002) { // SMTYPE_SMM
                this.isSigned = true;
                this.description = "SMM Region";
            } else if (this.type == 0x0003) { // SMTYPE_DATA
                this.isSigned = false;
                this.description = "Data Section";
            } else {
                this.isSigned = true; // Assume code sections are signed by default
                this.description = "Code/Data Section";
            }
        }

        @Override
        public String toString() {
            return "PeSection{name='" + name + "', type=0x" + 
                   Integer.toHexString(type) + ", virtualAddress=" + 
                   Long.toHexString(virtualAddress) + 
                   ", sizeOfRawData=" + Long.toHexString(sizeOfRawData) +
                   ", isSigned=" + isSigned +
                   ", description='" + description + "'}";
        }
    }

    /**
     * SMM Region Info.
     */
    static class SmmRegion {
        int size;
        short attributes;
        long virtualAddress;
        boolean hasThreatPattern;
        String threatPattern;

        void parse(ByteBuffer buffer) {
            this.size = buffer.getShort();
            this.attributes = buffer.getShort();
            this.virtualAddress = buffer.getLong();
            
            // Check for known SMM threat patterns
            checkForThreatPatterns(buffer);
        }

        private void checkForThreatPatterns(ByteBuffer buffer) {
            byte[] regionData = new byte[this.size];
            buffer.position(buffer.position() - 48 + this.size); // Adjust position
            
            for (Pattern pattern : SMM_THREAT_PATTERNS) {
                if (pattern.matcher(new String(regionData)).find()) {
                    this.hasThreatPattern = true;
                    this.threatPattern = pattern.pattern();
                    break;
                }
            }
        }

        @Override
        public String toString() {
            return "SmmRegion{" +
                   "size=" + size +
                   ", attributes=0x" + Integer.toHexString(attributes) +
                   ", virtualAddress=" + Long.toHexString(virtualAddress) +
                   ", hasThreatPattern=" + hasThreatPattern +
                   ", threatPattern='" + (threatPattern != null ? threatPattern : "None") + "'" +
                   '}';
        }
    }

    /**
     * NVRAM Variable Info.
     */
    static class NvramVariable {
        int size;
        short type;
        long virtualAddress;
        
        void parse(ByteBuffer buffer) {
            this.size = buffer.getShort();
            this.type = buffer.getShort();
            this.virtualAddress = buffer.getLong();
        }

        @Override
        public String toString() {
            return "NvramVariable{" +
                   "size=" + size +
                   ", type=0x" + Integer.toHexString(type) +
                   ", virtualAddress=" + Long.toHexString(virtualAddress) +
                   '}';
        }
    }

    /**
     * Main parser class.
     */
    static class FirmwareParser {
        private EfiHeader header;
        private List<SigDirEntry> signatureEntries = new ArrayList<>();
        private List<PeSection> peSections = new ArrayList<>();
        private List<SmmRegion> smmRegions = new ArrayList<>();
        private List<NvramVariable> nvramVariables = new ArrayList<>();

        public FirmwareParser(byte[] firmwareData) {
            ByteBuffer buffer = ByteBuffer.wrap(firmwareData);
            
            // Parse EFI Header
            header = new EfiHeader();
            header.parse(buffer);
            
            // Parse Signature Directory Entries
            int sigDirOffset = calculateSignatureDirectoryOffset(header);
            while (buffer.position() < sigDirOffset + SIGNATURE_DIR_ENTRY_SIZE) {
                SigDirEntry entry = new SigDirEntry();
                entry.parse(buffer);
                signatureEntries.add(entry);
                
                // Handle variable-length entries
                if (entry.entrySize > SIGNATURE_DIR_ENTRY_SIZE) {
                    buffer.position(buffer.position() - 2 + entry.length);
                } else {
                    buffer.position(buffer.position() + SIGNATURE_DIR_ENTRY_SIZE);
                }
            }
            
            // Parse PE Sections
            int peHeaderOffset = calculatePEHeaderOffset(header, signatureEntries);
            while (buffer.position() < peHeaderOffset + PE_COFF_HEADER_SIZE) {
                PeSection section = new PeSection();
                section.parse(buffer);
                peSections.add(section);
                
                // Skip to next section header
                int nextSectionOffset = calculateNextSectionOffset(
                    buffer, peHeaderOffset, peSections.size() - 1);
                if (nextSectionOffset > 0) {
                    buffer.position(nextSectionOffset);
                } else {
                    break;
                }
            }
            
            // Parse SMM Regions
            int smmRegionOffset = calculateSmmRegionOffset(header, peSections);
            while (buffer.position() < smmRegionOffset + 48) {
                SmmRegion region = new SmmRegion();
                region.parse(buffer);
                smmRegions.add(region);
                
                // Move past this SMM region info
                buffer.position(buffer.position() - 48 + 12);
            }
            
            // Parse NVRAM Variables
            int nvramOffset = calculateNvramOffset(header, smmRegions);
            while (buffer.position() < nvramOffset + 36) {
                NvramVariable var = new NvramVariable();
                var.parse(buffer);
                nvramVariables.add(var);
                
                // Move past this variable info
                buffer.position(buffer.position() - 48 + 12);
            }
        }

        private int calculateSignatureDirectoryOffset(EfiHeader header