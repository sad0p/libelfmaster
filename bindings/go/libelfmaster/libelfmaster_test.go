package libelfmaster

import (
	"debug/elf"
	"reflect"
	"testing"
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

type elfArchCases struct {
	path string
	want string
}

var elfArchTests = []elfArchCases{
	elfArchCases{"./test_bins/helloworld-intel32", "i386"},
	elfArchCases{"./test_bins/helloworld-intel64", "x64"},
	elfArchCases{"./test_bins/helloworld-arm64", "unsupported"},
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

type elfClassCases struct {
	path string
	want string
}

var elfClassTests = []elfClassCases{
	elfClassCases{"./test_bins/helloworld-intel64", "elfclass64"},
	elfClassCases{"./test_bins/helloworld-intel32", "elfclass32"},
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

type elfLinkTypeCases struct {
	path string
	want string
}

var elfLinkTypeTests = []elfLinkTypeCases{
	elfLinkTypeCases{"./test_bins/helloworld-intel32", "dynamic"},
	elfLinkTypeCases{"./test_bins/helloworld-intel64", "dynamic"},
	elfLinkTypeCases{"./test_bins/helloworld-intel32-static-pie", "static-pie"},
	elfLinkTypeCases{"./test_bins/helloworld-intel64-static-pie", "static-pie"},
	elfLinkTypeCases{"./test_bins/helloworld-intel32-static", "static"},
	elfLinkTypeCases{"./test_bins/helloworld-intel64-static", "static"},
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

type elfMachineCase struct {
	path string
	want string
}

var elfMachineTests = []elfMachineCase{
	elfMachineCase{"./test_bins/helloworld-intel32", "EM_386"},
	elfMachineCase{"./test_bins/helloworld-intel64", "EM_X86_64"},
	elfMachineCase{"./test_bins/helloworld-arm64", "EM_AARCH64"},
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


type genericCase struct {
	path string
	want string
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
			t.Errorf("ElfOpenObject() failed while testing ElfMachine()")
		}
		
		got, _ := obj.ElfInterpreterPath()
		if got != test.want {
			t.Errorf("TestElfMachine(): got %s and wanted %s for file %s", got, test.want, test.path)
		}
	}
}
