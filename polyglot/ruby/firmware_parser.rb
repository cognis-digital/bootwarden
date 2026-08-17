require 'digest/md5'
require 'digest/sha1'

module UefiScan
  module FirmwareParser
    # PE/COFF Constants
    IMAGE_DOS_SIGNATURE = "\x4D\x5A"
    IMAGE_PE_SIGNATURE = "\x00\x00\x02\x0E"
    
    # Common UEFI GUIDs (16 bytes each)
    GUID_SYSTEM = [0x98, 0xc7, 0x3b, 0x01, 0x98, 0xd6, 0x4f, 0x2a, 
                   0xa6, 0x5e, 0x9d, 0x1e, 0xf5, 0x85, 0x6c, 0x07]
    GUID_SMM = [0x88, 0x6a, 0xe3, 0x01, 0x4f, 0x2b, 0x4d, 0xa6, 
                 0xb9, 0x5e, 0x9c, 0x2f, 0x1a, 0xe8, 0x73, 0x05]
    GUID_S3_BOOT = [0x4d, 0x6b, 0x3e, 0x01, 0x4c, 0x29, 0x4a, 0xa5, 
                     0xc8, 0x5d, 0x9b, 0x3f, 0x2b, 0xe7, 0x84, 0x16]
    
    # Section flags for identification
    IMAGE_SCN_CNT_CODE = 0x40000000
    IMAGE_SCN_CNT_INITIALIZED_DATA = 0x20000000
    
    class << self
      def parse_firmware(data)
        return { error: "Empty or invalid data" } unless data && data.length > 64
        
        dos_header = DOSHeader.new(data)
        return { error: "Invalid DOS header" } unless dos_header.valid?
        
        pe_offset = dos_header.pe_offset
        pe_header = PEHeader.new(data, pe_offset)
        return { error: "Invalid PE signature at #{pe_offset}" } unless pe_header.valid?
        
        sections = []
        num_sections = pe_header.num_sections
        
        # Parse all sections
        (0...num_sections).each do |i|
          offset = pe_offset + 64 + (i * 40)
          section_data = data[offset, 40]
          
          name = [section_data[12], section_data[13]].pack('C*')
          next if name.empty? || name == "\x00\x00"
          
          sections << Section.new(
            name: name,
            virtual_size: read_uint32(section_data, 16),
            raw_size: read_uint32(section_data, 20),
            vaddr: read_uint32(section_data, 24),
            rva: read_uint32(section_data, 28),
            offset: read_uint32(section_data, 32)
          )
        end
        
        { dos_header: dos_header, pe_header: pe_header, sections: sections }
      rescue StandardError => e
        { error: "Parsing failed: #{e.message}" }
      end
      
      def check_secure_boot_keys(sections, known_keys = {})
        results = []
        
        # Known Secure Boot keys (simplified - real impl would have more)
        default_keys = {
          Microsoft_1_0: GUID_SYSTEM,
          Microsoft_2_0: [0x98, 0xc7, 0x3b, 0x01, 0x98, 0xd6, 0x4f, 0x2a, 
                         0xa6, 0x5e, 0x9d, 0x1e, 0xf5, 0x85, 0x6c, 0x07],
          Microsoft_3_0: [0x98, 0xc7, 0x3b, 0x02, 0x98, 0xd6, 0x4f, 0x2a, 
                         0xa6, 0x5e, 0x9d, 0x1e, 0xf5, 0x85, 0x6c, 0x07]
        }
        
        all_keys = default_keys.merge(known_keys)
        
        # Check each section against known keys
        sections.each do |section|
          next unless section.virtual_size > 0
          
          data_offset = section.vaddr + section.rva
          if data_offset < 16 && data_offset >= 0
            guid_bytes = [data[data_offset, 16].bytes]
            
            all_keys.keys.each do |key_name|
              key_guid = all_keys[key_name]
              next unless key_guid.is_a?(Array) || key_guid.respond_to?(:to_a)
              
              if guid_bytes.flatten.size >= 16
                match = guid_bytes.flatten[0..15].bytes == key_guid.to_a[0..15]
                
                results << {
                  section: section.name,
                  key_name: key_name,
                  matched: match,
                  offset: data_offset
                }
              end
            end
          end
        end
        
        # Summary
        total = sections.count { |s| s.virtual_size > 0 }
        found_keys = results.select { |r| r[:matched] }.count
        missing_keys = all_keys.keys - 
                       (results.select { |r| r[:matched] }.map { |r| r[:key_name] })
        
        { total_sections: total, found_keys: found_keys, missing_keys: missing_keys }
      rescue StandardError => e
        { error: "Key check failed: #{e.message}" }
      end
      
      def find_smm_modules(sections)
        results = []
        
        # SMM header signature is 0x5E at offset 0x1C of the section header
        sections.each do |section|
          next unless section.virtual_size > 0
          
          data_offset = section.vaddr + section.rva
          if data_offset < 28 && data_offset >= 0
            sig_byte = [data[data_offset, 1].bytes]
            
            if sig_byte.flatten[0] == 0x5E
              # Found SMM module header
              results << {
                name: section.name,
                offset: data_offset,
                signature: "\x5E",
                type: "SMM"
              }
            end
          end
        end
        
        results
      rescue StandardError => e
        [{ error: "SMM scan failed: #{e.message}" }]
      end
      
      def extract_s3_scripts(sections)
        results = []
        
        # S3 boot scripts are typically in sections with GUID_S3_BOOT
        sections.each do |section|
          next unless section.virtual_size > 0
          
          data_offset = section.vaddr + section.rva
          if data_offset < 16 && data_offset >= 0
            guid_bytes = [data[data_offset, 16].bytes]
            
            if guid_bytes.flatten.size >= 16
              match = guid_bytes.flatten[0..15].bytes == GUID_S3_BOOT.to_a[0..15]
              
              results << {
                name: section.name,
                matched_s3_guid: match,
                offset: data_offset,
                size: section.virtual_size
              } if match
            end
          end
        end
        
        # Also check for common S3 script names in sections
        s3_script_names = ["S3Boot", "S3Resume", "S3Script", "SleepScript"]
        
        sections.each do |section|
          next unless section.virtual_size > 0
          
          name_lower = section.name.downcase.strip
          if s3_script_names.any? { |n| name_lower.include?(n) }
            results << {
              name: section.name,
              detected_by_name: true,
              offset: section.offset,
              size: section.virtual_size
            }
          end
        end
        
        results.uniq
      rescue StandardError => e
        [{ error: "S3 script extraction failed: #{e.message}" }]
      end
      
      def check_unsigned_modules(sections)
        # Check for modules without proper signatures
        unsigned = []
        
        sections.each do |section|
          next unless section.virtual_size > 0
          
          data_offset = section.vaddr + section.rva
          if data_offset < 16 && data_offset >= 0
            guid_bytes = [data[data_offset, 16].bytes]
            
            # Check against known signed GUIDs
            known_signed_guids = [GUID_SYSTEM, GUID_SMM, GUID_S3_BOOT]
            
            is_known = known_signed_guids.any? do |guid|
              guid_bytes.flatten[0..15].bytes == guid.to_a[0..15]
            end
            
            unless is_known
              # Could be unsigned or unknown - flag for review
              unsigned << {
                name: section.name,
                offset: data_offset,
                size: section.virtual_size,
                likely_unsigned: true
              }
            end
          end
        end
        
        unsigned
      rescue StandardError => e
        [{ error: "Unsigned module check failed: #{e.message}" }]
      end
      
      private
      
      def read_uint32(data, offset)
        bytes = [data[offset], data[offset + 1], 
                 data[offset + 2], data[offset + 3]]
        (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]
      rescue StandardError => e
        0
      end
      
      def read_uint16(data, offset)
        bytes = [data[offset], data[offset + 1]]
        (bytes[0] << 8) | bytes[1]
      rescue StandardError => e
        0
      end
    end
    
    # DOS Header structure
    class DOSHeader
      def initialize(data)
        @data = data
        @pe_offset = nil
      end
      
      def valid?
        return false unless @data && @data.length >= 64
        
        signature = [@data[0], @data[1]].pack('C*')
        return false if signature != IMAGE_DOS_SIGNATURE
        
        # DOS header is always at offset 0
        @pe_offset = read_uint32(@data, 0x3C)
        
        # PE header should be within reasonable bounds
        return false if @pe_offset > @data.length - 64 || @pe_offset < 16
        
        true
      rescue StandardError => e
        false
      end
      
      def pe_offset
        @pe_offset
      end
      
      private
      
      def read_uint32(data, offset)
        bytes = [data[offset], data[offset + 1], 
                 data[offset + 2], data[offset + 3]]
        (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]
      rescue StandardError => e
        0
      end
    end
    
    # PE Header structure
    class PEHeader
      def initialize(data, offset)
        @data = data
        @offset = offset
        @num_sections = nil
      end
      
      def valid?
        return false unless @data && @data.length > @offset + 64
        
        signature = [@data[@offset], @data[@offset+1], 
                    @data[@offset+2], @data[@offset+3]].pack('C*')
        
        return false if signature != IMAGE_PE_SIGNATURE
        
        # Read number of sections (at offset 0x28 within PE header)
        num_sections = read_uint16(@data, @offset + 0x28)
        @num_sections = num_sections
        
        true
      rescue StandardError => e
        false
      end
      
      def num_sections
        @num_sections || 0
      end
      
      private
      
      def read_uint32(data, offset)
        bytes = [data[offset], data[offset + 1], 
                 data[offset + 2], data[offset + 3]]
        (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]
      rescue StandardError => e
        0
      end
      
      def read_uint16(data, offset)
        bytes = [data[offset], data[offset + 1]]
        (bytes[0] << 8) | bytes[1]
      rescue StandardError => e
        0
      end
    end
    
    # Section structure
    class Section
      attr_reader :name, :virtual_size, :raw_size, :vaddr, :rva, :offset
      
      def initialize(name:, virtual_size: 0, raw_size: 0, vaddr: 0, rva: 0, offset: 0)
        @name = name
        @virtual_size = virtual_size
        @raw_size = raw_size
        @vaddr = vaddr
        @rva = rva
        @offset = offset
      end
    end
  end
end

# === Demo / Entry Point ===
if __FILE__ == $0
  require 'tempfile'
  
  # Create a sample PE file for testing
  def create_sample_pe_file
    dos_header = "\x4D\x5A" + "SamplePEFile" * 28 + "\x00\x00"
    
    pe_offset = 64
    
    pe_header = "\x00\x00\x02\x0E" + # PE signature
                "\x14\x00" +          # Machine (i386)
                "\x0A\x00" +          # Number of sections
                "\x00\x00\x00\x00" +  # Time stamp
                "\x0C\x00\x00\x00" +  # Pointer to symbol table
                "\x02\x00\x00\x00" +  # Number of symbols
                "\x14\x00\x00\x00" +  # Size of optional header
                "\x02\x00"            # Characteristics
                
    sections = []
    section_count = 3
    
    (0...section_count).each do |i|
      name = i == 0 ? "\x54\x65\x73\x74" : "\x00\x00" # "Test" or empty
      
      if i == 0
        # First section: SMM module with signature
        guid_bytes = GUID_SMM + [0, 0]
        sig_byte = "\x5E"
        
        sections << name + 
                    "\x14\x00" +       # Virtual size (20)
                    "\x14\x00" +       # Raw size (20)
                    "\x00\x00\x00\x00" + # Vaddr
                    "\x00\x00\x00\x00" + # RVA
                    "\x64\x00\x00\x00"