package secureboot

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// PE Header Constants
const (
	PE_Signature       = 0x4550 // "PE\0\0"
	COFF_SIGNATURE     = 0x464F4F43 // "FOOF"
	MACHINE_I386       = 0x14c
	MACHINE_AMD64      = 0x8664
	MACHINE_ARM        = 0x1C0A
	SZ_DIR_ENTRY       = 24
)

// PE Header structures
type PEHeader struct {
	Signature     [2]byte
	COFF          COFFHeader
	Optional      OptionalHeader
}

type COFFHeader struct {
	Machine         uint16
	NumberOfSections uint16
	TimeStamp       uint32
	PointerToSymbolTable uint32
	NumberOfSymbols  uint32
	SizeOfOptionalHeader uint2
	Characteristics   uint2
}

type OptionalHeader struct {
	Magic          uint16
	MajorLinkerVer  uint8
	MinorLinkerVer  uint8
	SizeOfCode      uint32
	TimeDateStamp   uint32
}

// Certificate structures for Secure Boot
type CertChain struct {
	Certificates []x509.Certificate
	SignatureAlgorithm string
	PublicKeySize int
}

type SecureBootState struct {
	State         string
	Version       uint16
	Mode          uint8 // 0=Disabled, 1=On, 2=Setup, 3=Test
	KeysLoaded    bool
	Certificates  []CertChain
	LastError     error
}

// S3 Boot Script structures
type S3BootScript struct {
	Version       string
	FilePath      string
	Entries       []S3Entry
	Vulnerabilities []string
}

type S3Entry struct {
	Type    uint8
	Offset  uint32
	Size    uint32
	Name    string
}

// SMM Threat structures
type SMMDetection struct {
	RegionStart   uint64
	RegionSize    uint64
	Modules       []SMMSegment
	KnownThreats  map[string]bool
	Suspicious    bool
}

type SMMSegment struct {
	Name     string
	BaseAddr uint64
	Size     uint64
	Type     uint8 // 0=Data, 1=Code, 2=Stack, 3=Heap
}

// Scanner configuration
type Config struct {
	TrustedKeysDir    string
	S3ScriptPaths      []string
	SMMRegionSize      uint64
	MinCertChainLen    int
	Timeout            context.DeadlineFunc
}

var defaultConfig = Config{
	TrustedKeysDir:   "./keys",
	S3ScriptPaths:    []string{"$FV\\S3BootScript.bin"},
	SMMRegionSize:    0x10000, // 64KB default SMM region
	MinCertChainLen:  2,
}

// Scanner holds state during a scan run
type Scanner struct {
	config       Config
	mu            sync.Mutex
	state        SecureBootState
	s3Script      S3BootScript
	smm           SMMDetection
	results       map[string]interface{}
}

func NewScanner(cfg *Config) *Scanner {
	if cfg == nil {
		cfg = &defaultConfig
	}
	return &Scanner{
		config:  *cfg,
		state:   SecureBootState{},
		s3Script: S3BootScript{},
		smm:     SMMDetection{KnownThreats: make(map[string]bool)},
		results: make(map[string]interface{}),
	}
}

// Scan performs the complete secure boot validation
func (s *Scanner) Scan(ctx context.Context, firmwarePath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.validatePEHeader(firmwarePath); err != nil {
		return fmt.Errorf("PE header: %w", err)
	}

	if err := s.verifySecureBootKeys(ctx, firmwarePath); err != nil {
		return fmt.Errorf("secure boot keys: %w", err)
	}

	if err := s.parseS3Script(firmwarePath); err != nil {
		return fmt.Errorf("S3 script: %w", err)
	}

	if err := s.analyzeSMMDomains(ctx, firmwarePath); err != nil {
		return fmt.Errorf("SMM analysis: %w", err)
	}

	s.state.LastError = nil
	return nil
}

// validatePEHeader checks the PE header structure and basic metadata
func (s *Scanner) validatePEHeader(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	header := make([]byte, 64)
	if _, err := io.ReadFull(f, header); err != nil {
		return fmt.Errorf("read header: %w", err)
	}

	// Check PE signature
	if !bytes.Equal(header[0:2], []byte{0x50, 0x45}) {
		s.state.State = "Unknown"
		s.state.LastError = fmt.Errorf("invalid PE signature")
		return s.state.LastError
	}

	// Parse COFF header
	s.parseCOFFHeader(header)

	// Check machine type for architecture validation
	machine := binary.LittleEndian.Uint16(header[20:22])
	switch machine {
	case MACHINE_I386, MACHINE_AMD64, MACHINE_ARM:
		s.results["Architecture"] = fmt.Sprintf("Valid (%s)", s.archName(machine))
	default:
		s.state.State = "UnknownArch"
		s.state.LastError = fmt.Errorf("unknown PE machine type: 0x%x", machine)
	}

	return nil
}

func (s *Scanner) parseCOFFHeader(header []byte) {
	offset := 24 // After PE signature and DOS header
	
	c coff := &s.parseCOFFHeader(header[offset:])
	
	s.state.State = "Valid"
	s.state.Version = binary.LittleEndian.Uint16(header[30:32])

	// Check for minimal certificate chain requirements
	if len(c.Certificates) < s.config.MinCertChainLen {
		s.state.State = "WeakChain"
	}

	return nil
}

func (s *Scanner) archName(machine uint16) string {
	switch machine {
	case MACHINE_I386:
		return "x86_32"
	case MACHINE_AMD64:
		return "x86_64"
	case MACHINE_ARM:
		return "ARM"
	default:
		return fmt.Sprintf("Unknown(0x%x)", machine)
	}
}

// verifySecureBootKeys validates the Secure Boot certificate chain
func (s *Scanner) verifySecureBootKeys(ctx context.Context, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	// Read the entire firmware for certificate extraction
	data, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("read data: %w", err)
	}

	// Parse certificates from PE20+ format (Secure Boot 2.0+)
	certs, err := s.extractPE20Certificates(data)
	if err == nil && len(certs) > 0 {
		s.state.Certificates = certs
		s.results["CertificateCount"] = len(certs)

		// Validate each certificate against trusted keys
		for i, cert := range certs {
			valid := s.validateCertChain(cert, i+1)
			if !valid {
				s.state.State = "InvalidCert"
				s.state.LastError = fmt.Errorf("certificate %d: invalid chain", i+1)
			}
		}

		if len(certs) >= s.config.MinCertChainLen && s.state.State == "Valid" {
			s.results["SecureBootStatus"] = "Enabled (Valid Chain)"
		} else if len(certs) > 0 {
			s.results["SecureBootStatus"] = fmt.Sprintf("Partial (%d certs)", len(certs))
		} else {
			s.state.State = "Disabled"
			s.results["SecureBootStatus"] = "Not Found or Disabled"
		}
	}

	return s.state.LastError
}

func (s *Scanner) extractPE20Certificates(data []byte) ([]CertChain, error) {
	var certs []CertChain
	
	// PE2.0+ certificates are stored in a specific format after the optional header
	offset := 64 // Start after PE and COFF headers
	
	for offset < len(data)-100 {
		// Look for certificate signature marker
		if bytes.Equal(data[offset:offset+4], []byte{0x53, 0x49, 0x47, 0x4E}) { // "SIGN"
			certData := data[offset:]
			
			// Parse X.509 certificate from DER format
			if cert, err := s.parseX509DER(certData); err == nil && cert != nil {
				certs = append(certs, CertChain{
					Certificates: []x509.Certificate{*cert},
					SignatureAlgorithm: "RSA-SHA256", // Common for PE2.0+
					PublicKeySize: 2048,
				})
			}
			
			offset += 100 // Move past this certificate block
		} else {
			offset++
		}
	}

	return certs, nil
}

func (s *Scanner) parseX509DER(derData []byte) (*x509.Certificate, error) {
	if len(derData) < 128 { // Minimum X.509 certificate size
		return nil, fmt.Errorf("certificate too small")
	}

	// Parse DER-encoded X.509 certificate
	cert, err := x509.ParseCertificate(derData)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func (s *Scanner) validateCertChain(cert x509.Certificate, index int) bool {
	// Check certificate validity period
	now := time.Now()
	if !cert.NotBefore.Before(now) && !cert.NotAfter.After(now) {
		return false
	}

	// Check for common Secure Boot key identifiers
	keyID := s.extractKeyIdentifier(cert.PublicKey)
	
	// Verify against known trusted root keys (simplified check)
	trustedRoots := map[string]bool{
		"Microsoft Root Certificate Authority": true,
		"Dell Trusted Platform Module": true,
	}

	if _, exists := trustedRoots[keyID]; !exists {
		return false
	}

	return true
}

func (s *Scanner) extractKeyIdentifier(pubKey interface{}) string {
	switch pub := pubKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", pub.Size()*8)
	case *ecdsa.PublicKey:
		return "ECDSA"
	default:
		return "Unknown"
	}
}

// parseS3Script parses the S3 boot script for vulnerabilities
func (s *Scanner) parseS3Script(path string) error {
	s.s3Script = S3BootScript{
		Version: "1.0",
		FilePath: path,
		Entries: []S3Entry{},
	}

	// Read and parse S3 boot script binary format
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open S3 script: %w", err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("read S3 data: %w", err)
	}

	// Parse S3 boot script entries (simplified format)
	offset := 0
	for offset < len(data)-SZ_DIR_ENTRY {
		entry := &S3Entry{}
		
		// Entry type and flags
		entry.Type = data[offset]
		offset++
		
		// Offset within firmware
		binary.Read(bytes.NewReader(data[offset:offset+4]), binary.LittleEndian, &entry.Offset)
		offset += 4
		
		// Size of the entry
		binary.Read(bytes.NewReader(data[offset:offset+4]), binary.LittleEndian, &entry.Size)
		offset += 4

		if entry.Type == 0x01 { // Code segment
			entry.Name = "Code"
		} else if entry.Type == 0x02 { // Data segment
			entry.Name = "Data"
		} else if entry.Type == 0xFF { // End marker
			break
		}

		s.s3Script.Entries = append(s.s3Script.Entries, *entry)
		
		// Check for known vulnerable patterns in code segments
		if entry.Type == 0x01 && s.checkCodeSegmentVulnerabilities(entry.Offset, entry.Size, data) {
			s.s3Script.Vulnerabilities = append(s.s3Script.Vulnerabilities, 
				fmt.Sprintf("Potential S3 vulnerability at offset 0x%x", entry.Offset))
		}

		offset += SZ_DIR_ENTRY
	}

	return nil
}

func (s *Scanner) checkCodeSegmentVulnerabilities(offset uint32, size uint32, data []byte) bool {
	if offset+size > uint32(len(data)) {
		return false
	}

	code := data[offset:offset+size]

	// Check for common S3 vulnerability patterns
	patterns := map[string]bool{
		"Stack overflow risk": bytes.Contains(code, []byte{0x6A, 0x48, 0x59}), // PUSH offset, PUSH 0x48, PUSH 0x59
		"Uninitialized pointer": bytes.Contains(code, []byte{0x31, 0xC0}),     // XOR EAX, EAX (clear register)
		"Hardcoded address": bytes.Contains(code, []byte{0xB8, 0x00, 0x00, 0x00, 0x00}), // MOV EAX, 0
	}

	for pattern, found := range patterns {
		if found {
			return true
		}
	}

	return false
}

// analyzeSMMDomains analyzes SMM regions for known threats
func (s *Scanner) analyzeSMMDomains(ctx context.Context, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("read data: %w", err)
	}

	// Find SMM region boundaries (simplified detection)
	smmRegionStart := s.findSMMRegion(data)
	
	if smmRegionStart == 0 {
		s.smm.RegionStart = 0
		s.results["SMMDetection"] = "Not Found"
		return nil
	}

	s.smm.RegionStart = smmRegionStart
	s.smm.RegionSize = s.config.SMMRegionSize
	
	// Analyze SMM code for known threats
	if err := s.scanSMMCode(data, smmRegionStart); err != nil {
		return fmt.Errorf("scan SMM: %w", err)
	}

	return nil
}

func (s *Scanner) findSMMRegion(data []byte) uint64 {
	// Look for common SMM region markers
	markers := map[string]uint32{
		"SMM_CODE": 0x534D4D5F, // "SMM_" prefix
		"SMRAM_BASE": 0x534D5241, // "SMRA" for SMRAM base
	}

	for offset := 0; offset < len(data)-4; offset++ {
		if binary.LittleEndian.Uint32(data[offset:offset+4]) == 0x534D4D5F {
			return uint64(offset)
		}
	}

	// Fallback: assume SMM region starts at known offset for common firmware
	return 0x10000 // Typical SMM base address
}

func (s *Scanner) scanSMMCode(data []byte, startOffset uint64) error {
	if startOffset >= uint64(len(data)) {
		return nil
	}

	code := data[startOffset:]

	// Check for known SMM threat signatures
	threatSignatures := map[string]uint32{
		"Threat: