package libelfmaster

import (
	"bytes"
	"debug/elf"
	"fmt"
	"reflect"
	"strconv"
	"testing"
	"unsafe"
)

const (
	TESTBIN_HELLOWORLD_INTEL64            = "./test_bins/helloworld-intel64"
	TESTBIN_HELLOWORLD_INTEL32            = "./test_bins/helloworld-intel32"
	TESTBIN_HELLOWORLD_INTEL64_STATIC     = "./test_bins/helloworld-intel64-static"
	TESTBIN_HELLOWORLD_INTEL32_STATIC     = "./test_bins/helloworld-intel32-static"
	TESTBIN_HELLOWORLD_INTEL64_STATIC_PIE = "./test_bins/helloworld-intel64-static-pie"
	TESTBIN_HELLOWORLD_INTEL32_STATIC_PIE = "./test_bins/helloworld-intel32-static-pie"
	TESTBIN_HELLOWORLD_INTEL64_NO_SYMTAB  = "./test_bins/helloworld-intel64-no-symtab"
	TESTBIN_HELLOWORLD_INTEL32_NO_SYMTAB  = "./test_bins/helloworld-intel32-no-symtab"
	TESTBIN_HELLOWORLD_INTEL64_NO_DYNSYM  = "./test_bins/helloworld-intel64-no-dynsym"
	TESTBIN_HELLOWORLD_INTEL32_NO_DYNSYM  = "./test_bins/helloworld-intel32-no-dynsym"
	TESTBIN_HELLOWORLD_ARM64              = "./test_bins/helloworld-arm64"
)

type checkError uint32

const (
	lookForNil   checkError = 1
	lookForError checkError = 2
)

type elfOpenObjectCases struct {
	path string
	want checkError
}

var elfOpenTests = []elfOpenObjectCases{
	{"/bin/ls", lookForNil},
	{"/dev/random", lookForError},
	{"/bin/cat", lookForNil},
}

func TestElfOpenObject(t *testing.T) {
	for _, test := range elfOpenTests {
		var obj ElfObj
		got := obj.ElfOpenObject(test.path, ELF_LOAD_F_FORENSICS)
		switch {
		case test.want == lookForNil:
			if got != nil {
				t.Errorf("got %v wanted nil", got)
			}

		case test.want == lookForError:
			wt := "*errors.errorString"
			if rt := reflect.TypeOf(got).String(); rt != wt {
				t.Errorf("got return type %s wanted %s", rt, wt)
			}
		}
	}
}

type genericCase struct {
	path string
	want string
}

var elfArchTests = []genericCase{
	{TESTBIN_HELLOWORLD_INTEL32, "i386"},
	{TESTBIN_HELLOWORLD_INTEL64, "x64"},
	{TESTBIN_HELLOWORLD_ARM64, "unsupported"},
}

func TestElfArch(t *testing.T) {
	for _, test := range elfArchTests {
		var obj ElfObj
		if err := obj.ElfOpenObject(test.path, ELF_LOAD_F_FORENSICS); err != nil {
			t.Errorf("ElfOpenObject() failed while testing ElfArch()")
		}

		got := obj.ElfArch()
		if got != test.want {
			t.Errorf("TestElfArch(): got %s and wanted %s", got, test.want)
		}
	}
}

var elfClassTests = []genericCase{
	{TESTBIN_HELLOWORLD_INTEL64, "elfclass64"},
	{TESTBIN_HELLOWORLD_INTEL32, "elfclass32"},
}

func TestElfClass(t *testing.T) {
	for _, test := range elfClassTests {
		var obj ElfObj
		if err := obj.ElfOpenObject(test.path, ELF_LOAD_F_FORENSICS); err != nil {
			t.Errorf("ElfOpenObject() failed while testing ElfClass()")
		}

		got := obj.ElfClass()
		if got != test.want {
			t.Errorf("TestElfClass(): got %s and wanted %s", got, test.want)
		}
	}
}

var elfLinkTypeTests = []genericCase{
	{TESTBIN_HELLOWORLD_INTEL32, "dynamic"},
	{TESTBIN_HELLOWORLD_INTEL64, "dynamic"},
	{TESTBIN_HELLOWORLD_INTEL32_STATIC_PIE, "static-pie"},
	{TESTBIN_HELLOWORLD_INTEL64_STATIC_PIE, "static-pie"},
	{TESTBIN_HELLOWORLD_INTEL32_STATIC, "static"},
	{TESTBIN_HELLOWORLD_INTEL64_STATIC, "static"},
}

func TestElfLinkingType(t *testing.T) {
	for _, test := range elfLinkTypeTests {
		var obj ElfObj
		if err := obj.ElfOpenObject(test.path, ELF_LOAD_F_FORENSICS); err != nil {
			t.Errorf("ElfOpenObject() failed while testing ElfLinkingType()")
		}

		got := obj.ElfLinkingType()
		if got != test.want {
			t.Errorf("TestElfLinkingType(): got %s and wanted %s for file %s", got, test.want, test.path)
		}
	}
}

var elfMachineTests = []genericCase{
	{TESTBIN_HELLOWORLD_INTEL32, "EM_386"},
	{TESTBIN_HELLOWORLD_INTEL64, "EM_X86_64"},
	{TESTBIN_HELLOWORLD_ARM64, "EM_AARCH64"},
}

func TestElfMachine(t *testing.T) {
	for _, test := range elfMachineTests {
		var obj ElfObj
		if err := obj.ElfOpenObject(test.path, ELF_LOAD_F_FORENSICS); err != nil {
			t.Errorf("ElfOpenObject() failed while testing ElfMachine()")
		}

		got := elf.Machine(obj.ElfMachine()).String()
		if got != test.want {
			t.Errorf("TestElfMachine(): got %s and wanted %s for file %s", got, test.want, test.path)
		}
	}
}

var elfInterpreterPathTests = []genericCase{
	{TESTBIN_HELLOWORLD_INTEL32, "/lib/ld-linux.so.2"},
	{TESTBIN_HELLOWORLD_INTEL64, "/lib64/ld-linux-x86-64.so.2"},
	{TESTBIN_HELLOWORLD_INTEL32_STATIC, ""},
	{TESTBIN_HELLOWORLD_INTEL64_STATIC, ""},
	{TESTBIN_HELLOWORLD_INTEL32_STATIC_PIE, ""},
	{TESTBIN_HELLOWORLD_INTEL64_STATIC_PIE, ""},
	{TESTBIN_HELLOWORLD_ARM64, ""},
}

func TestElfInterpreterPath(t *testing.T) {
	for _, test := range elfInterpreterPathTests {
		var obj ElfObj
		if err := obj.ElfOpenObject(test.path, ELF_LOAD_F_FORENSICS); err != nil {
			t.Errorf("ElfOpenObject() failed while testing ElfInterpreterPath()")
		}

		got, _ := obj.ElfInterpreterPath()
		if got != test.want {
			t.Errorf("TestElfInterpreterPath(): got %s and wanted %s for file %s", got,
				test.want, test.path)
		}
	}
}

var elfEhdrSizeTests = []genericCase{
	{TESTBIN_HELLOWORLD_INTEL32, "52"},
	{TESTBIN_HELLOWORLD_INTEL64, "64"},
	{TESTBIN_HELLOWORLD_INTEL32_STATIC, "52"},
	{TESTBIN_HELLOWORLD_INTEL64_STATIC, "64"},
	{TESTBIN_HELLOWORLD_INTEL32_STATIC_PIE, "52"},
	{TESTBIN_HELLOWORLD_INTEL64_STATIC_PIE, "64"},
	{TESTBIN_HELLOWORLD_ARM64, "64"},
}

func TestElfEhdrSize(t *testing.T) {
	for _, test := range elfEhdrSizeTests {
		var obj ElfObj
		if err := obj.ElfOpenObject(test.path, ELF_LOAD_F_FORENSICS); err != nil {
			t.Errorf("ElfOpenObject() failed while testing ElfEhdrSize()")
		}

		got := obj.ElfEhdrSize()
		if strconv.FormatUint(uint64(got), 10) != test.want {
			t.Errorf("TestElfEhdrSize(): got %d and wanted %s for file %s", got, test.want, test.path)
		}
	}
}

var elfPhdrTableSizeTests = []genericCase{
	{TESTBIN_HELLOWORLD_INTEL32, "384"},
	{TESTBIN_HELLOWORLD_INTEL64, "728"},
	{TESTBIN_HELLOWORLD_INTEL32_STATIC, "288"},
	{TESTBIN_HELLOWORLD_INTEL64_STATIC, "560"},
	{TESTBIN_HELLOWORLD_INTEL32_STATIC_PIE, "352"},
	{TESTBIN_HELLOWORLD_INTEL64_STATIC_PIE, "672"},
	{TESTBIN_HELLOWORLD_ARM64, "392"},
}

func TestElfPhdrTableSize(t *testing.T) {
	for _, test := range elfPhdrTableSizeTests {
		var obj ElfObj
		if err := obj.ElfOpenObject(test.path, ELF_LOAD_F_FORENSICS); err != nil {
			t.Errorf("ElfOpenObject() failed while testing ElfPhdrTableSize()")
		}

		got := strconv.FormatUint(uint64(obj.ElfPhdrTableSize()), 10)
		if got != test.want {
			t.Errorf("TestElfPhdrTableSize(): got %s and wanted %s for file %s",
				got, test.want, test.path)
		}
	}
}

/*
libelfmaster officially doesn't support ARM so the last test will fail.
We want to support ARM ultimately. TODO fix this issue for ARM.
*/
var elfDataFileszTests = []genericCase{
	{TESTBIN_HELLOWORLD_INTEL32, "0x128"},
	{TESTBIN_HELLOWORLD_INTEL64, "0x248"},
	{TESTBIN_HELLOWORLD_INTEL32_STATIC, "0x360c"},
	{TESTBIN_HELLOWORLD_INTEL64_STATIC, "0x5ad8"},
	{TESTBIN_HELLOWORLD_INTEL32_STATIC_PIE, "0x36ec"},
	{TESTBIN_HELLOWORLD_INTEL64_STATIC_PIE, "0x5c78"},
	//	genericCase{TESTBIN_HELLOWORLD_ARM64, "0x17ea0"},
}

func TestElfDataFilesz(t *testing.T) {
	for _, test := range elfDataFileszTests {
		var obj ElfObj
		if err := obj.ElfOpenObject(test.path, ELF_LOAD_F_FORENSICS); err != nil {
			t.Errorf("ElfOpenObject() failed while testing ElfDataFilesz()")
		}

		got := "0x" + strconv.FormatUint(obj.ElfDataFilesz(), 16)
		if got != test.want {
			t.Errorf("TestElfDataFilesz(): got %s and wanted %s for file %s",
				got, test.want, test.path)
		}
	}
}

var elfEntryPointTests = []genericCase{
	{TESTBIN_HELLOWORLD_INTEL32, "0x1060"},
	{TESTBIN_HELLOWORLD_INTEL64, "0x1040"},
	{TESTBIN_HELLOWORLD_INTEL32_STATIC, "0x8049510"},
	{TESTBIN_HELLOWORLD_INTEL64_STATIC, "0x4014e0"},
	{TESTBIN_HELLOWORLD_INTEL32_STATIC_PIE, "0x3510"},
	{TESTBIN_HELLOWORLD_INTEL64_STATIC_PIE, "0x95a0"},
	{TESTBIN_HELLOWORLD_ARM64, "0x6d100"},
}

func TestElfEntryPoint(t *testing.T) {
	for _, test := range elfEntryPointTests {
		var obj ElfObj
		if err := obj.ElfOpenObject(test.path, ELF_LOAD_F_FORENSICS); err != nil {
			t.Errorf("ElfOpenObject() failed while testing ElfEntryPoint()")
		}

		got := "0x" + strconv.FormatUint(obj.ElfEntryPoint(), 16)
		if got != test.want {
			t.Errorf("TestElfEntryPoint(): got %s and wanted %s for file %s",
				got, test.want, test.path)
		}
	}
}

var elfTypeTests = []genericCase{
	{TESTBIN_HELLOWORLD_INTEL32, "ET_DYN"},
	{TESTBIN_HELLOWORLD_INTEL64, "ET_DYN"},
	{TESTBIN_HELLOWORLD_INTEL32_STATIC, "ET_EXEC"},
	{TESTBIN_HELLOWORLD_INTEL64_STATIC, "ET_EXEC"},
	{TESTBIN_HELLOWORLD_INTEL32_STATIC_PIE, "ET_DYN"},
	{TESTBIN_HELLOWORLD_INTEL64_STATIC_PIE, "ET_DYN"},
	{TESTBIN_HELLOWORLD_ARM64, "ET_EXEC"},
}

func TestElfType(t *testing.T) {
	for _, test := range elfTypeTests {
		var obj ElfObj
		if err := obj.ElfOpenObject(test.path, ELF_LOAD_F_FORENSICS); err != nil {
			t.Errorf("ElfOpenObject() failed while testing ElfType()")
		}

		got := elf.Type(obj.ElfType()).String()
		if got != test.want {
			t.Errorf("TestElfType(): got %s and wanted %s for file %s",
				got, test.want, test.path)
		}
	}
}

var elfSizeTests = []genericCase{
	{TESTBIN_HELLOWORLD_INTEL32, "0x4bf4"},
	{TESTBIN_HELLOWORLD_INTEL64, "0x5050"},
	{TESTBIN_HELLOWORLD_INTEL32_STATIC, "0xb9abc"},
	{TESTBIN_HELLOWORLD_INTEL64_STATIC, "0xbef38"},
	{TESTBIN_HELLOWORLD_INTEL32_STATIC_PIE, "0xbfa7c"},
	{TESTBIN_HELLOWORLD_INTEL64_STATIC_PIE, "0xc9b20"},
	{TESTBIN_HELLOWORLD_ARM64, "0x1bcc53"},
}

func TestElfSize(t *testing.T) {
	for _, test := range elfSizeTests {
		var obj ElfObj
		if err := obj.ElfOpenObject(test.path, ELF_LOAD_F_FORENSICS); err != nil {
			t.Errorf("ElfOpenObject() failed while testing ElfSize()")
		}

		got := "0x" + strconv.FormatUint(obj.ElfSize(), 16)
		if got != test.want {
			t.Errorf("TestElfSize(): got %s and wanted %s for file %s",
				got, test.want, test.path)
		}
	}
}

type elfOffsetPointerSliceCases struct {
	path   string
	offset uint64
	want   []byte
}

var elfOffsetPointerSliceTests = []elfOffsetPointerSliceCases{
	{TESTBIN_HELLOWORLD_INTEL32, 0x0, []byte{0x7f, 0x45, 0x4c, 0x46}},
	{TESTBIN_HELLOWORLD_INTEL64, 0x5030, []byte{0x76, 0x01, 0x00, 0x00}},
	{TESTBIN_HELLOWORLD_INTEL32_STATIC, 0x0b9a80, []byte{0x48, 0x71}},
	{TESTBIN_HELLOWORLD_INTEL64_STATIC, 0x0bee50, []byte{0xb4, 0xac}},
	{TESTBIN_HELLOWORLD_ARM64, 0x001bcc30, []byte{0x2e, 0x73, 0x74, 0x72}},
}

func TestElfOffsetPointerSlice(t *testing.T) {
	for _, test := range elfOffsetPointerSliceTests {
		var obj ElfObj
		if err := obj.ElfOpenObject(test.path, ELF_LOAD_F_FORENSICS); err != nil {
			t.Errorf("ElfOpenObject() failed while testing TestElfOffsetPointerSlice()")
			continue
		}

		got, err := obj.ElfOffsetPointerSlice(test.offset, uint64(len(test.want)))
		if err != nil {
			s := fmt.Sprintf("TestElfOffsetPointerSlice() fail on file %s\n%s", test.path, err.Error())
			t.Errorf(s)
			continue
		}

		if bytes.Compare(got, test.want) != 0 {
			t.Errorf("TestElfOffsetPointerSlice() want 0x%x got 0x%x", test.want, got)
		}
	}
}

var ElfOffsetPointerTests = []string{
	TESTBIN_HELLOWORLD_INTEL32,
	TESTBIN_HELLOWORLD_INTEL64,
	TESTBIN_HELLOWORLD_INTEL32_STATIC,
	TESTBIN_HELLOWORLD_INTEL64_STATIC,
	TESTBIN_HELLOWORLD_ARM64,
}

func TestElfOffsetPointer(t *testing.T) {
	for _, testBinPath := range ElfOffsetPointerTests {
		var obj ElfObj
		if err := obj.ElfOpenObject(testBinPath, ELF_LOAD_F_FORENSICS); err != nil {
			t.Errorf("ElfOpenObject() failed while testing TestElfOffsetPointer()")
			continue
		}

		p := (*byte)(obj.ElfOffsetPointer(0))
		hasMagic := bytes.Compare(unsafe.Slice(p, 4), []byte{0x7F, 0x45, 0x4c, 0x46}) == 0
		if !hasMagic {
			s := fmt.Sprintf("TestElfOffsetPointer(): no ELF_MAGIC in %s", testBinPath)
			t.Errorf(s)
		}
	}
}

type elfTabCountCases struct {
	path      string
	wantCount uint64
	wantRet   bool
}

var elfSymTabCountTests = []elfTabCountCases{
	{TESTBIN_HELLOWORLD_INTEL64, 37, true},
	{TESTBIN_HELLOWORLD_INTEL64_NO_SYMTAB, 0, false},
	{TESTBIN_HELLOWORLD_INTEL32, 41, true},
	{TESTBIN_HELLOWORLD_INTEL32_NO_SYMTAB, 0, false},
}

func TestElfSymTabCount(t *testing.T) {
	for _, test := range elfSymTabCountTests {
		var obj ElfObj
		if err := obj.ElfOpenObject(test.path, ELF_LOAD_F_FORENSICS); err != nil {
			t.Errorf("ElfOpenObject() failed while testing ElfSymtabCount()")
		}

		var gotCount uint64
		if gotRet := obj.ElfSymTabCount(&gotCount); gotRet != test.wantRet {
			t.Errorf("TestElfSymtabCount(): returned %v and wanted %v", gotRet, test.wantRet)

		}

		if gotCount != test.wantCount && !test.wantRet {
			t.Errorf("TestElfSymtabCount(): count %d and wanted %d for file %s", gotCount, test.wantCount,
				test.path)
		}
	}
}

var elfDynSymTabCountTests = []elfTabCountCases{
	{TESTBIN_HELLOWORLD_INTEL64, 7, true},
	{TESTBIN_HELLOWORLD_INTEL64_NO_DYNSYM, 0, false},
	{TESTBIN_HELLOWORLD_INTEL32, 8, true},
	{TESTBIN_HELLOWORLD_INTEL32_NO_DYNSYM, 0, false},
}

func TestElfDynSymTabCount(t *testing.T) {
	for _, test := range elfDynSymTabCountTests {
		var obj ElfObj
		if err := obj.ElfOpenObject(test.path, ELF_LOAD_F_FORENSICS); err != nil {
			t.Errorf("ElfOpenObject() failed while testing ElfDynSymCount()")
		}

		var gotCount uint64
		if gotRet := obj.ElfDynSymTabCount(&gotCount); gotRet != test.wantRet {
			t.Errorf("TestElfDynSymCount(): returned %v and wanted %v", gotRet, test.wantRet)

		}

		if gotCount != test.wantCount && !test.wantRet {
			t.Errorf("TestElfDynSymCount(): count %d and wanted %d for file %s", gotCount, test.wantCount,
				test.path)
		}
	}
}

var elfSymbolByNameTests = map[string]ElfSymbol{
	TESTBIN_HELLOWORLD_INTEL64:           {"_init", 0x1000, 0, 12, uint8(elf.STB_GLOBAL), uint8(elf.STT_FUNC), uint8(elf.STV_HIDDEN)},
	TESTBIN_HELLOWORLD_INTEL32:           {"main", 0x118d, 60, 14, uint8(elf.STB_GLOBAL), uint8(elf.STT_FUNC), uint8(elf.STV_DEFAULT)},
	TESTBIN_HELLOWORLD_INTEL32_NO_DYNSYM: {"__bss_start", 0x080ee278, 0, 24, uint8(elf.STB_GLOBAL), uint8(elf.STT_NOTYPE), uint8(elf.STV_DEFAULT)},
	TESTBIN_HELLOWORLD_ARM64:             {"path..inittask", 0x1219e0, 48, 9, uint8(elf.STB_GLOBAL), uint8(elf.STT_OBJECT), uint8(elf.STV_DEFAULT)},
}

func TestElfSymbolByName(t *testing.T) {
	for path, wantSymbol := range elfSymbolByNameTests {
		var gotSymbol ElfSymbol
		var obj ElfObj

		if err := obj.ElfOpenObject(path, ELF_LOAD_F_FORENSICS); err != nil {
			t.Errorf("ElfOpenObject() failed while testing ElfSymbolByNameTests()")
			continue
		}
		switch b := obj.ElfSymbolByName(wantSymbol.Name, &gotSymbol); b {
		case true:
			if wantSymbol != gotSymbol {
				t.Errorf("TestElfSymbolByName(): got %+v wanted %+v", gotSymbol, wantSymbol)
			}
		default:
			t.Errorf("TestElfSymbolByName(): Returned false, for symbol %s in binary %s", wantSymbol.Name, path)
		}
		obj.ElfCloseObject()
	}
}

var elfSymbolByIndexTests = map[uint32]map[string]ElfSymbol{
	36:   {TESTBIN_HELLOWORLD_INTEL64: elfSymbolByNameTests[TESTBIN_HELLOWORLD_INTEL64]},
	2061: {TESTBIN_HELLOWORLD_ARM64: elfSymbolByNameTests[TESTBIN_HELLOWORLD_ARM64]},
	1969: {TESTBIN_HELLOWORLD_INTEL32_NO_DYNSYM: elfSymbolByNameTests[TESTBIN_HELLOWORLD_INTEL32_NO_DYNSYM]},
}

func TestElfSymbolByIndex(t *testing.T) {
	for wantIndex, pathSymbolMap := range elfSymbolByIndexTests {
		for path, wantSymbol := range pathSymbolMap {
			var gotSymbol ElfSymbol
			var obj ElfObj

			if err := obj.ElfOpenObject(path, ELF_LOAD_F_FORENSICS); err != nil {
				t.Errorf("ElfOpenObject() failed while testing ElfSymbolByIndex()")
				continue
			}

			switch b := obj.ElfSymbolByIndex(wantIndex, &gotSymbol, elf.SHT_SYMTAB); b {
			case true:
				if wantSymbol != gotSymbol {
					t.Errorf("TestElfSymbolByIndex(): got %+v wanted %+v for index %d in binary %s", gotSymbol, wantSymbol, wantIndex, path)
				}
			default:
				t.Errorf("TestElfSymbolByIndex(): Returned false, for index num %d in binary %s", wantIndex, path)
			}
			obj.ElfCloseObject()
		}
	}
}

var elfSymbolByRangeTests = map[string]map[uint64]ElfSymbol{
	TESTBIN_HELLOWORLD_INTEL64: {0x1040: {"_start", 0x1040, 38, 14, uint8(elf.STB_GLOBAL), uint8(elf.STT_FUNC), uint8(elf.STV_DEFAULT)}},
}

func TestElfSymbolByRange(t *testing.T) {
	for path, valuesSymbols := range elfSymbolByRangeTests {
		var obj ElfObj
		if err := obj.ElfOpenObject(path, ELF_LOAD_F_FORENSICS); err != nil {
			t.Errorf("ElfOpenObject() failed while testing ElfSymbolByRange()")
			continue
		}

		for addr, wantSymbol := range valuesSymbols {
			var gotSymbol ElfSymbol
			switch b := obj.ElfSymbolByRange(addr, &gotSymbol); b {
			case true:
				if wantSymbol != gotSymbol {
					t.Errorf("TestElfSymbolByRange(): got %+v and wanted %+v for addr 0x%x for binary %s", gotSymbol, wantSymbol, addr, path)
				}
			default:
				t.Errorf("TestElfSymbolByRange(): Returned false for addr 0x%x in binary %s", addr, path)
			}
		}
		obj.ElfCloseObject()
	}
}

var elfSymbolByValueLookupTests = map[string]map[uint64]ElfSymbol{
	TESTBIN_HELLOWORLD_INTEL64: {0x1040: {"_start", 0x1040, 38, 14, uint8(elf.STB_GLOBAL), uint8(elf.STT_FUNC), uint8(elf.STV_DEFAULT)},
		0x1139: {"main", 0x1139, 31, 14, uint8(elf.STB_GLOBAL), uint8(elf.STT_FUNC), uint8(elf.STV_DEFAULT)},
		0x1158: {"_fini", 0x1158, 0, 15, uint8(elf.STB_GLOBAL), uint8(elf.STT_FUNC), uint8(elf.STV_HIDDEN)},
	},

	TESTBIN_HELLOWORLD_INTEL32: {0x10a0: {"deregister_tm_clones", 0x10a0, 0, 14, uint8(elf.STB_LOCAL), uint8(elf.STT_FUNC), uint8(elf.STV_DEFAULT)},
		0x1000: {"_init", 0x1000, 0, 12, uint8(elf.STB_GLOBAL), uint8(elf.STT_FUNC), uint8(elf.STV_HIDDEN)},
		0x4010: {"__TMC_END__", 0x4010, 0, 24, uint8(elf.STB_GLOBAL), uint8(elf.STT_OBJECT), uint8(elf.STV_HIDDEN)},
	},
}

func TestElfSymbolByValueLookup(t *testing.T) {
	for path, valuesSymbols := range elfSymbolByValueLookupTests {
		var obj ElfObj
		if err := obj.ElfOpenObject(path, ELF_LOAD_F_FORENSICS); err != nil {
			t.Errorf("ElfOpenObject() failed while testing ElfSymbolByValueLookup()")
			continue
		}

		for addr, wantSymbol := range valuesSymbols {
			var gotSymbol ElfSymbol
			switch b := obj.ElfSymbolByValueLookup(addr, &gotSymbol); b {
			case true:
				if wantSymbol != gotSymbol {
					t.Errorf("TestElfSymbolByValueLookup(): got %+v and wanted %+v for addr 0x%x for binary %s", gotSymbol, wantSymbol, addr, path)
				}
			default:
				t.Errorf("TestElfSymbolByValueLookup(): Returned false for addr 0x%x in binary %s", addr, path)
			}
		}
		obj.ElfCloseObject()
	}
}

var elfPltEntryByNameTests = map[string]ElfPlt{
	TESTBIN_HELLOWORLD_INTEL64: {"printf", 0x1030},
	TESTBIN_HELLOWORLD_INTEL32: {"printf", 0x1050},
}

func TestElfPltEntryByName(t *testing.T) {
	for path, wantPltEntry := range elfPltEntryByNameTests {
		var gotPltEntry ElfPlt
		var obj ElfObj

		if err := obj.ElfOpenObject(path, ELF_LOAD_F_FORENSICS); err != nil {
			t.Errorf("ElfOpenObject() failed while testing ElfPltEntryByName()")
			continue
		}

		switch b := obj.ElfPltByName(wantPltEntry.SymName, &gotPltEntry); b {
		case true:
			if wantPltEntry != gotPltEntry {
				t.Errorf("TestElfPltEntryByName(): got %+v wanted %+v in %s ", gotPltEntry, wantPltEntry, path)
			}
		default:
			t.Errorf("TestElfPltEntryByName(): Returned %v did not find plt entry for symbol %s in binary %s", b, wantPltEntry.SymName, path)
		}
		obj.ElfCloseObject()
	}
}

var elfSectionByNameTests = map[string]map[string]ElfSection{
	TESTBIN_HELLOWORLD_INTEL64: {
		".text":     {".text", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), 0x10, 0, 0x1040, 0x1040, 0x118},
		".plt":      {".plt", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), 0x10, 0x10, 0x1020, 0x1020, 0x20},
		".rela.dyn": {".rela.dyn", uint32(elf.SHT_RELA), 6, 0, uint64(elf.SHF_ALLOC), 8, 0x18, 0x558, 0x558, 0xc0},
	},

	TESTBIN_HELLOWORLD_INTEL32: {
		".text":    {".text", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), 0x10, 0, 0x1060, 0x1060, 0x16d},
		".plt":     {".plt", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), 0x10, 4, 0x1030, 0x1030, 0x30},
		".rel.dyn": {".rel.dyn", uint32(elf.SHT_REL), 6, 0, uint64(elf.SHF_ALLOC), 4, 8, 0x3d8, 0x3d8, 0x40},
	},
}

func TestElfSectionByName(t *testing.T) {
	for path, sections := range elfSectionByNameTests {
		var obj ElfObj
		if err := obj.ElfOpenObject(path, ELF_LOAD_F_FORENSICS); err != nil {
			t.Errorf("ElfOpenObject() failed while testing ElfSectionByName()")
			continue
		}

		for sName, wantSection := range sections {
			var gotSection ElfSection
			switch b := obj.ElfSectionByName(sName, &gotSection); b {
			case true:
				if gotSection != wantSection {
					t.Errorf("TestElfSectionByName(): got %+v and wanted %+v for %s binary.", gotSection, wantSection, path)
					continue
				}
			default:
				t.Errorf("TestElfSectionByName(): Returned %v, could not find section %+v in %s binary", b, wantSection, path)
			}
		}
		obj.ElfCloseObject()
	}
	return
}

var elfSectionByIndexTests = map[string]map[uint32]ElfSection{
	TESTBIN_HELLOWORLD_INTEL64: {14: {".text", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), 0x10, 0, 0x1040, 0x1040, 0x118},
		13: {".plt", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), 0x10, 0x10, 0x1020, 0x1020, 0x20},
		10: {".rela.dyn", uint32(elf.SHT_RELA), 6, 0, uint64(elf.SHF_ALLOC), 8, 0x18, 0x558, 0x558, 0xc0}},
	TESTBIN_HELLOWORLD_INTEL32: {14: {".text", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), 0x10, 0, 0x1060, 0x1060, 0x16d},
		13: {".plt", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), 0x10, 4, 0x1030, 0x1030, 0x30},
		10: {".rel.dyn", uint32(elf.SHT_REL), 6, 0, uint64(elf.SHF_ALLOC), 4, 8, 0x3d8, 0x3d8, 0x40},
	},
}

func TestElfSectionByIndex(t *testing.T) {
	for path, sections := range elfSectionByIndexTests {
		var obj ElfObj
		if err := obj.ElfOpenObject(path, ELF_LOAD_F_FORENSICS); err != nil {
			t.Errorf("ElfOpenObject() failed while testing ElfSectionByIndex()")
			continue
		}
		for sIndex, wantSection := range sections {
			var gotSection ElfSection
			switch b := obj.ElfSectionByIndex(sIndex, &gotSection); b {
			case true:
				if gotSection != wantSection {
					t.Errorf("TestElfSectionByIndex(): got %+v wanted %+v in binary %s", gotSection, wantSection, path)
				}
			default:
				t.Errorf("TestElfSectionByIndex(): Returned false for index %d in binary %s", sIndex, path)
			}
		}
		obj.ElfCloseObject()
	}
}

var elfSectionIndexByNameTests = map[string]map[string]uint64{
	TESTBIN_HELLOWORLD_INTEL64: {".interp": 1, ".note.ABI-tag": 4, ".rela.dyn": 10, ".rela.plt": 11, ".init": 12, ".text": 14},
	TESTBIN_HELLOWORLD_INTEL32: {".gnu.version": 8, ".rel.plt": 11, ".text": 14, ".comment": 26, ".debug_info": 28, ".debug_str": 31},
}

func TestElfSectionIndexByName(t *testing.T) {
	for path, sectionIndex := range elfSectionIndexByNameTests {
		var obj ElfObj
		if err := obj.ElfOpenObject(path, ELF_LOAD_F_FORENSICS); err != nil {
			t.Errorf("ElfOpenObject() failed while testing ElfSectionIndexByName()")
			continue
		}

		for sName, wantIndex := range sectionIndex {
			var gotIndex uint64
			switch b := obj.ElfSectionIndexByName(sName, &gotIndex); b {
			case true:
				if gotIndex != wantIndex {
					t.Errorf("TestElfSectionIndexByName(): got index %d wanted %d for section %s in binary %s.", gotIndex, wantIndex, sName, path)
				}
			default:
				t.Errorf("TestElfSectionByIndex(): Returned false for index %d in binary %s.", wantIndex, path)
			}
		}
		obj.ElfCloseObject()
	}
}

const SHF_RO_AFTER_INIT = 0x00200000

var elfSectionsArrayTest = map[string][]ElfSection{
	TESTBIN_HELLOWORLD_INTEL64: {{"", uint32(elf.SHT_NULL), 0, 0, 0, 0, 0, 0, 0, 0},
		{".interp", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC), 1, 0, 0x318, 0x318, 0x1c},
		{".note.gnu.property", uint32(elf.SHT_NOTE), 0, 0, uint64(elf.SHF_ALLOC), 8, 0, 0x338, 0x338, 0x40},
		{".note.gnu.build-id", uint32(elf.SHT_NOTE), 0, 0, uint64(elf.SHF_ALLOC), 4, 0, 0x378, 0x378, 0x24},
		{".note.ABI-tag", uint32(elf.SHT_NOTE), 0, 0, uint64(elf.SHF_ALLOC), 4, 0, 0x39c, 0x39c, 0x20},
		{".gnu.hash", uint32(elf.SHT_GNU_HASH), 6, 0, uint64(elf.SHF_ALLOC), 8, 0, 0x3c0, 0x3c0, 0x1c},
		{".dynsym", uint32(elf.SHT_DYNSYM), 7, 1, uint64(elf.SHF_ALLOC), 8, 0x18, 0x3e0, 0x3e0, 0xa8},
		{".dynstr", uint32(elf.SHT_STRTAB), 0, 0, uint64(elf.SHF_ALLOC), 1, 0, 0x488, 0x488, 0x8f},
		{".gnu.version", uint32(elf.SHT_GNU_VERSYM), 6, 0, uint64(elf.SHF_ALLOC), 2, 2, 0x518, 0x518, 0xe},
		{".gnu.version_r", uint32(elf.SHT_GNU_VERNEED), 7, 1, uint64(elf.SHF_ALLOC), 8, 0, 0x528, 0x528, 0x30},
		{".rela.dyn", uint32(elf.SHT_RELA), 6, 0, uint64(elf.SHF_ALLOC), 8, 0x18, 0x558, 0x558, 0xc0},
		{".rela.plt", uint32(elf.SHT_RELA), 6, 23, uint64(elf.SHF_ALLOC | elf.SHF_INFO_LINK), 8, 0x18, 0x618, 0x618, 0x18},
		{".init", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), 4, 0, 0x1000, 0x1000, 0x1b},
		{".plt", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), 16, 0x10, 0x1020, 0x1020, 0x20},
		{".text", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), 16, 0, 0x1040, 0x1040, 0x118},
		{".fini", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), 4, 0, 0x1158, 0x1158, 0xd},
		{".rodata", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC), 8, 0, 0x2000, 0x2000, 0x27},
		{".eh_frame_hdr", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC), 4, 0, 0x2028, 0x2028, 0x24},
		{".eh_frame", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC), 8, 0, 0x2050, 0x2050, 0x7c},
		{".init_array", uint32(elf.SHT_INIT_ARRAY), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_WRITE), 8, 8, 0x2dd0, 0x3dd0, 0x8},
		{".fini_array", uint32(elf.SHT_FINI_ARRAY), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_WRITE), 8, 8, 0x2dd8, 0x3dd8, 0x8},
		{".dynamic", uint32(elf.SHT_DYNAMIC), 7, 0, uint64(elf.SHF_ALLOC | elf.SHF_WRITE), 8, 0x10, 0x2de0, 0x3de0, 0x1e0},
		{".got", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_WRITE), 8, 8, 0x2fc0, 0x3fc0, 0x28},
		{".got.plt", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_WRITE), 8, 8, 0x2fe8, 0x3fe8, 0x20},
		{".data", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_WRITE), 8, 0, 0x3008, 0x4008, 0x10},
		{".bss", uint32(elf.SHT_NOBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_WRITE), 1, 0, 0x3018, 0x4018, 0x8},
		{".comment", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_STRINGS | elf.SHF_MERGE), 1, 1, 0x3018, 0x0, 0x12},
		{".debug_aranges", uint32(elf.SHT_PROGBITS), 0, 0, 0, 16, 0, 0x3030, 0x0, 0xf0},
		{".debug_info", uint32(elf.SHT_PROGBITS), 0, 0, 0, 1, 0, 0x3120, 0x0, 0x594},
		{".debug_abbrev", uint32(elf.SHT_PROGBITS), 0, 0, 0, 1, 0, 0x36b4, 0x0, 0x1a5},
		{".debug_line", uint32(elf.SHT_PROGBITS), 0, 0, 0, 1, 0, 0x3859, 0x0, 0x1da},
		{".debug_str", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_STRINGS | elf.SHF_MERGE), 1, 1, 0x3a33, 0x0, 0x47a},
		{".debug_line_str", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_STRINGS | elf.SHF_MERGE), 1, 1, 0x3ead, 0x0, 0x13e},
		{".debug_rnglists", uint32(elf.SHT_PROGBITS), 0, 0, 0, 1, 0, 0x3feb, 0x0, 0x42},
		{".symtab", uint32(elf.SHT_SYMTAB), 35, 19, 0, 8, 0x18, 0x4030, 0x0, 0x378},
		{".strtab", uint32(elf.SHT_STRTAB), 0, 0, 0, 1, 0, 0x43a8, 0x0, 0x1ec},
		{".shstrtab", uint32(elf.SHT_STRTAB), 0, 0, 0, 1, 0, 0x4594, 0x0, 0x176},
	},
	TESTBIN_HELLOWORLD_INTEL32: {{"", uint32(elf.SHT_NULL), 0, 0, 0, 0, 0, 0, 0, 0},
		{".interp", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC), 1, 0, 0x1b4, 0x1b4, 0x13},
		{".note.gnu.build-id", uint32(elf.SHT_NOTE), 0, 0, uint64(elf.SHF_ALLOC), 4, 0, 0x1c8, 0x1c8, 0x24},
		{".note.gnu.property", uint32(elf.SHT_NOTE), 0, 0, uint64(elf.SHF_ALLOC), 4, 0, 0x1ec, 0x1ec, 0x34},
		{".note.ABI-tag", uint32(elf.SHT_NOTE), 0, 0, uint64(elf.SHF_ALLOC), 4, 0, 0x220, 0x220, 0x20},
		{".gnu.hash", uint32(elf.SHT_GNU_HASH), 6, 0, uint64(elf.SHF_ALLOC), 4, 4, 0x240, 0x240, 0x20},
		{".dynsym", uint32(elf.SHT_DYNSYM), 7, 1, uint64(elf.SHF_ALLOC), 4, 0x10, 0x260, 0x260, 0x80},
		{".dynstr", uint32(elf.SHT_STRTAB), 0, 0, uint64(elf.SHF_ALLOC), 1, 0, 0x2e0, 0x2e0, 0xa8},
		{".gnu.version", uint32(elf.SHT_GNU_VERSYM), 6, 0, uint64(elf.SHF_ALLOC), 2, 2, 0x388, 0x388, 0x10},
		{".gnu.version_r", uint32(elf.SHT_GNU_VERNEED), 7, 1, uint64(elf.SHF_ALLOC), 4, 0, 0x398, 0x398, 0x40},
		{".rel.dyn", uint32(elf.SHT_REL), 6, 0, uint64(elf.SHF_ALLOC), 4, 8, 0x3d8, 0x3d8, 0x40},
		{".rel.plt", uint32(elf.SHT_REL), 6, 23, uint64(elf.SHF_ALLOC | elf.SHF_INFO_LINK), 4, 8, 0x418, 0x418, 0x10},
		{".init", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), 4, 0, 0x1000, 0x1000, 0x24},
		{".plt", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), 16, 4, 0x1030, 0x1030, 0x30},
		{".text", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), 16, 0, 0x1060, 0x1060, 0x16d},
		{".fini", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), 4, 0, 0x11d0, 0x11d0, 0x18},
		{".rodata", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC), 4, 0, 0x2000, 0x2000, 0x27},
		{".eh_frame_hdr", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC), 4, 0, 0x2028, 0x2028, 0x2c},
		{".eh_frame", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC), 4, 0, 0x2054, 0x2054, 0x9c},
		{".init_array", uint32(elf.SHT_INIT_ARRAY), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_WRITE), 4, 4, 0x2ee8, 0x3ee8, 0x4},
		{".fini_array", uint32(elf.SHT_FINI_ARRAY), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_WRITE), 4, 4, 0x2eec, 0x3eec, 0x4},
		{".dynamic", uint32(elf.SHT_DYNAMIC), 7, 0, uint64(elf.SHF_ALLOC | elf.SHF_WRITE), 4, 8, 0x2ef0, 0x3ef0, 0xf0},
		{".got", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_WRITE), 4, 4, 0x2fe0, 0x3fe0, 0x14},
		{".got.plt", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_WRITE), 4, 4, 0x2ff4, 0x3ff4, 0x14},
		{".data", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_WRITE), 4, 0, 0x3008, 0x4008, 0x8},
		{".bss", uint32(elf.SHT_NOBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_WRITE), 1, 0, 0x3010, 0x4010, 0x4},
		{".comment", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_STRINGS | elf.SHF_MERGE), 1, 1, 0x3010, 0x0, 0x12},
		{".debug_aranges", uint32(elf.SHT_PROGBITS), 0, 0, 0, 8, 0, 0x3028, 0x0, 0xa8},
		{".debug_info", uint32(elf.SHT_PROGBITS), 0, 0, 0, 1, 0, 0x30d0, 0x0, 0x581},
		{".debug_abbrev", uint32(elf.SHT_PROGBITS), 0, 0, 0, 1, 0, 0x3651, 0x0, 0x1b2},
		{".debug_line", uint32(elf.SHT_PROGBITS), 0, 0, 0, 1, 0, 0x3803, 0x0, 0x1e1},
		{".debug_str", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_STRINGS | elf.SHF_MERGE), 1, 1, 0x39e4, 0x0, 0x499},
		{".debug_line_str", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_STRINGS | elf.SHF_MERGE), 1, 1, 0x3e7d, 0x0, 0x13c},
		{".debug_rnglists", uint32(elf.SHT_PROGBITS), 0, 0, 0, 1, 0, 0x3fb9, 0x0, 0x38},
		{".symtab", uint32(elf.SHT_SYMTAB), 35, 19, 0, 4, 0x10, 0x3ff4, 0x0, 0x290},
		{".strtab", uint32(elf.SHT_STRTAB), 0, 0, 0, 1, 0, 0x4284, 0x0, 0x233},
		{".shstrtab", uint32(elf.SHT_STRTAB), 0, 0, 0, 1, 0, 0x44b7, 0x0, 0x174},
	},
	TESTBIN_HELLOWORLD_INTEL64_NO_DYNSYM: {{"", uint32(elf.SHT_NULL), 0, 0, 0, 0, 0, 0, 0, 0},
		{".note.gnu.property", uint32(elf.SHT_NOTE), 0, 0, uint64(elf.SHF_ALLOC), 8, 0, 0x270, 0x400270, 0x40},
		{".note.gnu.build-id", uint32(elf.SHT_NOTE), 0, 0, uint64(elf.SHF_ALLOC), 4, 0, 0x2b0, 0x4002b0, 0x24},
		{".note.ABI-tag", uint32(elf.SHT_NOTE), 0, 0, uint64(elf.SHF_ALLOC), 4, 0, 0x2d4, 0x4002d4, 0x20},
		{".rela.plt", uint32(elf.SHT_RELA), 36, 20, uint64(elf.SHF_ALLOC | elf.SHF_INFO_LINK), 8, 0x18, 0x2f8, 0x4002f8, 0x240},
		{".init", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), 4, 0, 0x1000, 0x401000, 0x1b},
		{".plt", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), 8, 0, 0x1020, 0x401020, 0x90},
		{".text", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), 64, 0, 0x10c0, 0x4010c0, 0x79183},
		{"__libc_freeres_fn", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), 16, 0, 0x7a250, 0x47a250, 0xab8},
		{".fini", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_EXECINSTR), 4, 0, 0x7ad08, 0x47ad08, 0xd},
		{".rodata", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC), 32, 0, 0x7b000, 0x47b000, 0x1bc34},
		{".stapsdt.base", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC), 1, 0, 0x96c34, 0x496c34, 0x1},
		{".eh_frame", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC), 8, 0, 0x96c38, 0x496c38, 0xb280},
		{".gcc_except_table", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC), 1, 0, 0xa1eb8, 0x4a1eb8, 0xf6},
		{".tdata", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_WRITE | elf.SHF_TLS), 8, 0, 0xa2778, 0x4a2778, 0x18},
		{".tbss", uint32(elf.SHT_NOBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_WRITE | elf.SHF_TLS), 8, 0, 0xa2790, 0x4a2790, 0x48},
		{".init_array", uint32(elf.SHT_INIT_ARRAY), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_WRITE), 8, 8, 0xa2790, 0x4a2790, 0x8},
		{".fini_array", uint32(elf.SHT_FINI_ARRAY), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_WRITE), 8, 8, 0xa2798, 0x4a2798, 0x8},
		{".data.rel.ro", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_WRITE), 32, 0, 0xa27a0, 0x4a27a0, 0x3768},
		{".got", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_WRITE), 8, 0, 0xa5f08, 0x4a5f08, 0xd8},
		{".got.plt", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_WRITE), 8, 8, 0xa5fe8, 0x4a5fe8, 0xa8},
		{".data", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_WRITE), 32, 0, 0xa60a0, 0x4a60a0, 0x19f8},
		{"__libc_subfreeres", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_WRITE | SHF_RO_AFTER_INIT), 8, 0, 0xa7a98, 0x4a7a98, 0x48},
		{"__libc_IO_vtables", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_WRITE), 32, 0, 0xa7ae0, 0x4a7ae0, 0x768},
		{"__libc_atexit", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_WRITE | SHF_RO_AFTER_INIT), 8, 0, 0xa8248, 0x4a8248, 0x8},
		{".bss", uint32(elf.SHT_NOBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_WRITE), 32, 0, 0xa8250, 0x4a8260, 0x5800},
		{"__libc_freeres_ptrs", uint32(elf.SHT_NOBITS), 0, 0, uint64(elf.SHF_ALLOC | elf.SHF_WRITE), 8, 0, 0xa8250, 0x4ada60, 0x20},
		{".comment", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_STRINGS | elf.SHF_MERGE), 1, 1, 0xa8250, 0x0, 0x12},
		{".note.stapsdt", uint32(elf.SHT_NOTE), 0, 0, 0, 4, 0, 0xa8264, 0x0, 0x14d8},
		{".debug_aranges", uint32(elf.SHT_PROGBITS), 0, 0, 0, 16, 0, 0xa9740, 0x0, 0x120},
		{".debug_info", uint32(elf.SHT_PROGBITS), 0, 0, 0, 1, 0, 0xa9860, 0x0, 0x997},
		{".debug_abbrev", uint32(elf.SHT_PROGBITS), 0, 0, 0, 1, 0, 0xaa1f7, 0x0, 0x28f},
		{".debug_line", uint32(elf.SHT_PROGBITS), 0, 0, 0, 1, 0, 0xaa486, 0x0, 0x24f},
		{".debug_str", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_STRINGS | elf.SHF_MERGE), 1, 1, 0xaa6d5, 0x0, 0x492},
		{".debug_line_str", uint32(elf.SHT_PROGBITS), 0, 0, uint64(elf.SHF_STRINGS | elf.SHF_MERGE), 1, 1, 0xaab67, 0x0, 0x14d},
		{".debug_rnglists", uint32(elf.SHT_PROGBITS), 0, 0, 0, 1, 0, 0xaacb4, 0x0, 0x42},
		{".symtab", uint32(elf.SHT_SYMTAB), 37, 783, 0, 8, 0x18, 0xaacf8, 0x0, 0xc210},
		{".strtab", uint32(elf.SHT_STRTAB), 0, 0, 0, 1, 0, 0xb6f08, 0x0, 0x74b4},
		{".shstrtab", uint32(elf.SHT_STRTAB), 0, 0, 0, 1, 0, 0xbe3bc, 0x0, 0x1b7},
	},
}

func TestElfSectionsArray(t *testing.T) {
	for path, wantSectionsArray := range elfSectionsArrayTest {
		var obj ElfObj
		if err := obj.ElfOpenObject(path, ELF_LOAD_F_FORENSICS); err != nil {
			t.Errorf("ElfOpenObject() failed while testing ElfSectionIndexByName()")
			continue
		}
		gotSectionsArray := obj.ElfSectionsArray()
		var failMsg string

		gLen := len(gotSectionsArray)
		wLen := len(wantSectionsArray)

		if gLen != wLen {
			failMsg = fmt.Sprintf("gotSectionsArray length %d => and wantSectionsArray length %d", gLen, wLen)
		} else {
			for i := range gotSectionsArray {
				if gotSectionsArray[i] != wantSectionsArray[i] {
					failMsg = fmt.Sprintf("%+v != %+v", gotSectionsArray[i], wantSectionsArray[i])
					break
				}
			}
		}

		if failMsg != "" {
			t.Errorf("TestElfSectionsArray(): \"%s\" in bin %s", failMsg, path)
		}

		obj.ElfCloseObject()
	}
}

var elfSegmentByIndexTests = map[string]map[uint64]ElfSegment{
	TESTBIN_HELLOWORLD_INTEL64: {
		0:  {uint32(elf.PT_PHDR), uint32(elf.PF_R), 0x40, 0x40, 0x40, 0x2d8, 0x2d8, 0x8, 0},
		1:  {uint32(elf.PT_INTERP), uint32(elf.PF_R), 0x318, 0x318, 0x318, 0x1c, 0x1c, 0x1, 1},
		2:  {uint32(elf.PT_LOAD), uint32(elf.PF_R), 0x0, 0x0, 0x0, 0x630, 0x630, 0x1000, 2},
		3:  {uint32(elf.PT_LOAD), uint32(elf.PF_R | elf.PF_X), 0x1000, 0x1000, 0x1000, 0x165, 0x165, 0x1000, 3},
		4:  {uint32(elf.PT_LOAD), uint32(elf.PF_R), 0x2000, 0x2000, 0x2000, 0xcc, 0xcc, 0x1000, 4},
		5:  {uint32(elf.PT_LOAD), uint32(elf.PF_R | elf.PF_W), 0x2dd0, 0x3dd0, 0x3dd0, 0x248, 0x250, 0x1000, 5},
		6:  {uint32(elf.PT_DYNAMIC), uint32(elf.PF_R | elf.PF_W), 0x2de0, 0x3de0, 0x3de0, 0x1e0, 0x1e0, 0x8, 6},
		7:  {uint32(elf.PT_NOTE), uint32(elf.PF_R), 0x338, 0x338, 0x338, 0x40, 0x40, 0x8, 7},
		8:  {uint32(elf.PT_NOTE), uint32(elf.PF_R), 0x378, 0x378, 0x378, 0x44, 0x44, 0x4, 8},
		9:  {uint32(elf.PT_GNU_PROPERTY), uint32(elf.PF_R), 0x338, 0x338, 0x338, 0x40, 0x40, 0x8, 9},
		10: {uint32(elf.PT_GNU_EH_FRAME), uint32(elf.PF_R), 0x2028, 0x2028, 0x2028, 0x24, 0x24, 0x4, 10},
		11: {uint32(elf.PT_GNU_STACK), uint32(elf.PF_R | elf.PF_W), 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 11},
		12: {uint32(elf.PT_GNU_RELRO), uint32(elf.PF_R), 0x2dd0, 0x3dd0, 0x3dd0, 0x230, 0x230, 0x1, 12},
	},

	TESTBIN_HELLOWORLD_INTEL32: {0: {uint32(elf.PT_PHDR), uint32(elf.PF_R), 0x34, 0x34, 0x34, 0x180, 0x180, 0x4, 0},
		1:  {uint32(elf.PT_INTERP), uint32(elf.PF_R), 0x1b4, 0x1b4, 0x1b4, 0x13, 0x13, 0x1, 1},
		2:  {uint32(elf.PT_LOAD), uint32(elf.PF_R), 0x0, 0x0, 0x0, 0x428, 0x428, 0x1000, 2},
		3:  {uint32(elf.PT_LOAD), uint32(elf.PF_R | elf.PF_X), 0x1000, 0x1000, 0x1000, 0x1e8, 0x1e8, 0x1000, 3},
		4:  {uint32(elf.PT_LOAD), uint32(elf.PF_R), 0x2000, 0x2000, 0x2000, 0xf0, 0xf0, 0x1000, 4},
		5:  {uint32(elf.PT_LOAD), uint32(elf.PF_R | elf.PF_W), 0x2ee8, 0x3ee8, 0x3ee8, 0x128, 0x12c, 0x1000, 5},
		6:  {uint32(elf.PT_DYNAMIC), uint32(elf.PF_R | elf.PF_W), 0x2ef0, 0x3ef0, 0x3ef0, 0xf0, 0xf0, 0x4, 6},
		7:  {uint32(elf.PT_NOTE), uint32(elf.PF_R), 0x1c8, 0x1c8, 0x1c8, 0x78, 0x78, 0x4, 7},
		8:  {uint32(elf.PT_GNU_PROPERTY), uint32(elf.PF_R), 0x1ec, 0x1ec, 0x1ec, 0x34, 0x34, 0x4, 8},
		9:  {uint32(elf.PT_GNU_EH_FRAME), uint32(elf.PF_R), 0x2028, 0x2028, 0x2028, 0x2c, 0x2c, 0x4, 9},
		10: {uint32(elf.PT_GNU_STACK), uint32(elf.PF_R | elf.PF_W), 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 10},
		11: {uint32(elf.PT_GNU_RELRO), uint32(elf.PF_R), 0x2ee8, 0x3ee8, 0x3ee8, 0x118, 0x118, 0x1, 11},
	},
}

func TestElfSegmentByIndex(t *testing.T) {
	for path, indexSegmentsMap := range elfSegmentByIndexTests {
		var obj ElfObj
		if err := obj.ElfOpenObject(path, ELF_LOAD_F_FORENSICS); err != nil {
			t.Errorf("ElfOpenObject() failed while testing ElfSegmentByIndex()")
			continue
		}

		for sIndex, wantSegment := range indexSegmentsMap {
			var gotSegment ElfSegment
			switch b := obj.ElfSegmentByIndex(sIndex, &gotSegment); b {
			case true:
				if gotSegment != wantSegment {
					t.Errorf("TestElfSegmentByIndex(): got segment %+v and wanted segment %+v in binary %s", gotSegment, wantSegment, path)
				}
			default:
				t.Errorf("TestElfSegmentByIndex(): ElfSegmentsByIndex() return false for index %d in binary %s", sIndex, path)
			}
		}
		obj.ElfCloseObject()
	}
}

func TestElfSegmentArray(t *testing.T) {
	for path, indexSegmentsMap := range elfSegmentByIndexTests {
		var obj ElfObj
		if err := obj.ElfOpenObject(path, ELF_LOAD_F_FORENSICS); err != nil {
			t.Errorf("ElfOpenObject() failed while testing ElfSegmentArray()")
			continue
		}

		gotArray := obj.ElfSegmentsArray()
		for i := range gotArray {
			if gotArray[i] != indexSegmentsMap[uint64(i)] {
				t.Errorf("TestElfSegmentArray(): gotArray[%d] %+v != wantArray[%d] %+v", i, gotArray[i], i, indexSegmentsMap[uint64(i)])
			}
		}
		obj.ElfCloseObject()
	}
}
