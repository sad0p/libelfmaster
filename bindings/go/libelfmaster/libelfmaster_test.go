package libelfmaster

import (
	"debug/elf"
	"reflect"
	"strconv"
	"testing"
	"unsafe"
	"bytes"
	"fmt"
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
	elfOpenObjectCases{"/bin/ls", lookForNil},
	elfOpenObjectCases{"/dev/random", lookForError},
	elfOpenObjectCases{"/bin/cat", lookForNil},
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
	genericCase{"./test_bins/helloworld-intel32", "i386"},
	genericCase{"./test_bins/helloworld-intel64", "x64"},
	genericCase{"./test_bins/helloworld-arm64", "unsupported"},
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
	genericCase{"./test_bins/helloworld-intel64", "elfclass64"},
	genericCase{"./test_bins/helloworld-intel32", "elfclass32"},
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
	genericCase{"./test_bins/helloworld-intel32", "dynamic"},
	genericCase{"./test_bins/helloworld-intel64", "dynamic"},
	genericCase{"./test_bins/helloworld-intel32-static-pie", "static-pie"},
	genericCase{"./test_bins/helloworld-intel64-static-pie", "static-pie"},
	genericCase{"./test_bins/helloworld-intel32-static", "static"},
	genericCase{"./test_bins/helloworld-intel64-static", "static"},
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
	genericCase{"./test_bins/helloworld-intel32", "EM_386"},
	genericCase{"./test_bins/helloworld-intel64", "EM_X86_64"},
	genericCase{"./test_bins/helloworld-arm64", "EM_AARCH64"},
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
	genericCase{"./test_bins/helloworld-intel32", "/lib/ld-linux.so.2"},
	genericCase{"./test_bins/helloworld-intel64", "/lib64/ld-linux-x86-64.so.2"},
	genericCase{"./test_bins/helloworld-intel32-static", ""},
	genericCase{"./test_bins/helloworld-intel64-static", ""},
	genericCase{"./test_bins/helloworld-intel32-static-pie", ""},
	genericCase{"./test_bins/helloworld-intel64-static-pie", ""},
	genericCase{"./test_bins/helloworld-arm64", ""},
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
	genericCase{"./test_bins/helloworld-intel32", "52"},
	genericCase{"./test_bins/helloworld-intel64", "64"},
	genericCase{"./test_bins/helloworld-intel32-static", "52"},
	genericCase{"./test_bins/helloworld-intel64-static", "64"},
	genericCase{"./test_bins/helloworld-intel32-static-pie", "52"},
	genericCase{"./test_bins/helloworld-intel64-static-pie", "64"},
	genericCase{"./test_bins/helloworld-arm64", "64"},
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
	genericCase{"./test_bins/helloworld-intel32", "384"},
	genericCase{"./test_bins/helloworld-intel64", "728"},
	genericCase{"./test_bins/helloworld-intel32-static", "288"},
	genericCase{"./test_bins/helloworld-intel64-static", "560"},
	genericCase{"./test_bins/helloworld-intel32-static-pie", "352"},
	genericCase{"./test_bins/helloworld-intel64-static-pie", "672"},
	genericCase{"./test_bins/helloworld-arm64", "392"},
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
	genericCase{"./test_bins/helloworld-intel32", "0x128"},
	genericCase{"./test_bins/helloworld-intel64", "0x248"},
	genericCase{"./test_bins/helloworld-intel32-static", "0x360c"},
	genericCase{"./test_bins/helloworld-intel64-static", "0x5ad8"},
	genericCase{"./test_bins/helloworld-intel32-static-pie", "0x36ec"},
	genericCase{"./test_bins/helloworld-intel64-static-pie", "0x5c78"},
//	genericCase{"./test_bins/helloworld-arm64", "0x17ea0"},
}

func TestElfDataFilesz(t *testing.T) {
	for _, test := range elfDataFileszTests {
		var obj ElfObj
		if err := obj.ElfOpenObject(test.path, ELF_LOAD_F_FORENSICS); err != nil {
			t.Errorf("ElfOpenObject() failed while testing ElfDataFilesz()")
		}
		
		got := "0x" + strconv.FormatUint(uint64(obj.ElfDataFilesz()), 16)
		if got != test.want {
			t.Errorf("TestElfDataFilesz(): got %s and wanted %s for file %s",
			got, test.want, test.path)
		}
	}
}

var elfEntryPointTests = []genericCase{
	genericCase{"./test_bins/helloworld-intel32", "0x1060"},
	genericCase{"./test_bins/helloworld-intel64", "0x1040"},
	genericCase{"./test_bins/helloworld-intel32-static", "0x8049510"},
	genericCase{"./test_bins/helloworld-intel64-static", "0x4014e0"},
	genericCase{"./test_bins/helloworld-intel32-static-pie", "0x3510"},
	genericCase{"./test_bins/helloworld-intel64-static-pie", "0x95a0"},
	genericCase{"./test_bins/helloworld-arm64", "0x6d100"},
}

func TestElfEntryPoint(t *testing.T) {
	for _, test := range elfEntryPointTests {
		var obj ElfObj
		if err := obj.ElfOpenObject(test.path, ELF_LOAD_F_FORENSICS); err != nil {
			t.Errorf("ElfOpenObject() failed while testing ElfEntryPoint()")
		}
		
		got := "0x" + strconv.FormatUint(uint64(obj.ElfEntryPoint()), 16)
		if got != test.want {
			t.Errorf("TestElfEntryPoint(): got %s and wanted %s for file %s",
			got, test.want, test.path)
		}
	}
}

var elfTypeTests = []genericCase{
	genericCase{"./test_bins/helloworld-intel32", "ET_DYN"},
	genericCase{"./test_bins/helloworld-intel64", "ET_DYN"},
	genericCase{"./test_bins/helloworld-intel32-static", "ET_EXEC"},
	genericCase{"./test_bins/helloworld-intel64-static", "ET_EXEC"},
	genericCase{"./test_bins/helloworld-intel32-static-pie", "ET_DYN"},
	genericCase{"./test_bins/helloworld-intel64-static-pie", "ET_DYN"},
	genericCase{"./test_bins/helloworld-arm64", "ET_EXEC"},
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
	genericCase{"./test_bins/helloworld-intel32", "0x4bf4"},
	genericCase{"./test_bins/helloworld-intel64", "0x5050"},
	genericCase{"./test_bins/helloworld-intel32-static", "0xb9abc"},
	genericCase{"./test_bins/helloworld-intel64-static", "0xbef38"},
	genericCase{"./test_bins/helloworld-intel32-static-pie", "0xbfa7c"},
	genericCase{"./test_bins/helloworld-intel64-static-pie", "0xc9b20"},
	genericCase{"./test_bins/helloworld-arm64", "0x1bcc53"},
}

func TestElfSize(t *testing.T) {
	for _, test := range elfSizeTests {
		var obj ElfObj
		if err := obj.ElfOpenObject(test.path, ELF_LOAD_F_FORENSICS); err != nil {
			t.Errorf("ElfOpenObject() failed while testing ElfSize()")
		}
		
		got := "0x" + strconv.FormatUint(uint64(obj.ElfSize()), 16)
		if got != test.want {
			t.Errorf("TestElfSize(): got %s and wanted %s for file %s",
			got, test.want, test.path)
		}
	}
}

type elfOffsetPointerSliceCases struct{
	path string
	offset uint64
	want []byte
}

var elfOffsetPointerSliceTests = []elfOffsetPointerSliceCases {
	{"./test_bins/helloworld-intel32", 0x0, []byte{0x7f, 0x45, 0x4c, 0x46}},
	{"./test_bins/helloworld-intel64", 0x5030, []byte{0x76, 0x01, 0x00, 0x00}},
	{"./test_bins/helloworld-intel32-static", 0x0b9a80, []byte{0x48, 0x71}},
	{"./test_bins/helloworld-intel64-static", 0x0bee50, []byte{0xb4, 0xac}},
	{"./test_bins/helloworld-arm64",0x001bcc30, []byte{0x2e, 0x73, 0x74, 0x72}},
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

var ElfOffsetPointerTests = []string {
	"./test_bins/helloworld-intel32",
	"./test_bins/helloworld-intel64",
	"./test_bins/helloworld-intel32-static",
	"./test_bins/helloworld-intel64-static",
	"./test_bins/helloworld-arm64",
}

func TestElfOffsetPointer(t *testing.T) {
	for _, testBinPath := range ElfOffsetPointerTests {
		var obj ElfObj	
		if err := obj.ElfOpenObject(testBinPath, ELF_LOAD_F_FORENSICS); err != nil {
			t.Errorf("ElfOpenObject() failed while testing TestElfOffsetPointer()")
			continue
		}
		
		p := (* byte)(obj.ElfOffsetPointer(0))
		hasMagic := bytes.Compare(unsafe.Slice(p, 4), []byte{0x7F, 0x45, 0x4c, 0x46}) == 0
		if !hasMagic {
			s := fmt.Sprintf("TestElfOffsetPointer(): no ELF_MAGIC in %s", testBinPath)
			t.Errorf(s)
		}
	}
}
