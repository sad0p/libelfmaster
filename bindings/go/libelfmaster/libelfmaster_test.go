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
