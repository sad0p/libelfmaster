package libelfmaster

import (
	"errors"
	"unsafe"
	"fmt"
)

/*
#cgo CFLAGS: -I /opt/elfmaster/include
#cgo LDFLAGS: -L /opt/elfmaster/lib -lelfmaster
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <sys/types.h>
#include <search.h>
#include <sys/time.h>
#include "libelfmaster.h"

int elf_open_object_w(const char *path, elfobj_t *obj, uint64_t flags, elf_error_t *error)
{
	return (int)elf_open_object(path, obj, flags, error);
}

int elf_arch_w(elfobj_t *obj)
{
	return (int)elf_arch(obj);

}

int elf_class_w(elfobj_t *obj)
{
	return (int)elf_class(obj);
}

int elf_linking_type_w(elfobj_t *obj)
{
	return (int)elf_linking_type(obj);
}
*/
import "C"

type ElfObj struct {
	obj      C.elfobj_t
	errorMsg C.elf_error_t
}

const (
	ELF_LOAD_F_STRICT    uint64 = uint64(C.ELF_LOAD_F_STRICT)
	ELF_LOAD_F_SMART     uint64 = uint64(C.ELF_LOAD_F_SMART)
	ELF_LOAD_F_FORENSICS uint64 = uint64(C.ELF_LOAD_F_FORENSICS)
	ELF_LOAD_F_MODIFY    uint64 = uint64(C.ELF_LOAD_F_MODIFY)
	ELF_LOAD_F_ULEXEC    uint64 = uint64(C.ELF_LOAD_F_ULEXEC)
	ELF_LOAD_F_MAP_WRITE uint64 = uint64(C.ELF_LOAD_F_MAP_WRITE)
	ELF_LOAD_F_LXC_MODE  uint64 = uint64(C.ELF_LOAD_F_LXC_MODE)
)

func (o *ElfObj) ElfOpenObject(path string, flags uint64) error {
	t := C.CString(path)
	defer C.free(unsafe.Pointer(t))

	r := int(C.elf_open_object_w(t, &o.obj, C.uint64_t(flags), &o.errorMsg))

	switch r {
	case 1:
		return nil
	default:
		e := C.GoString(C.elf_error_msg(&o.errorMsg))
		return errors.New(e)
	}
}

func (o *ElfObj) ElfCloseObject() {
	C.elf_close_object(&o.obj)
}

/*
	Possible portability issue.
	A change in enum order in the src can potentially break the implementation.
	TODO: Figure out a more portable solution ElfArch(), ElfClass()
*/

func (o *ElfObj) ElfArch() string {
	switch v := int(C.elf_arch_w(&o.obj)); v {
	case 0:
		return "i386"
	case 1:
		return "x64"
	default:
		return "unsupported"
	}
}

func (o *ElfObj) ElfClass() string {
	switch v := int(C.elf_class_w(&o.obj)); v {
	case 0:
		return "elfclass64"
	default:
		return "elfclass32"
	}
}

func (o *ElfObj) ElfLinkingType() string {
	switch v := int(C.elf_linking_type_w(&o.obj)); v {
	case 0:
		return "dynamic"
	case 1:
		return "static"
	case 2:
		return "static-pie"
	default:
		return "undefined"
	}
}

func (o *ElfObj) ElfMachine() uint16 {
	return uint16(C.elf_machine(&o.obj))
}

func (o *ElfObj) ElfInterpreterPath() (string, error) {
	switch v := C.GoString(C.elf_interpreter_path(&o.obj)); len(v) {
	case 0:
		return "", errors.New("No interpreter string present")
	default:
		return v, nil
	}
}

func (o *ElfObj) ElfEhdrSize() uint16 {
	return uint16(C.elf_ehdr_size(&o.obj))
}

func (o *ElfObj) ElfPhdrTableSize() uint16 {
	return uint16(C.elf_phdr_table_size(&o.obj))
}

func (o *ElfObj) ElfDataFilesz() uint64 {
	return uint64(C.elf_data_filesz(&o.obj))
}

func (o *ElfObj) ElfEntryPoint() uint64 {
	return uint64(C.elf_entry_point(&o.obj))
}

func (o *ElfObj) ElfType() uint32 {
	return uint32(C.elf_type(&o.obj))
}

func (o *ElfObj) ElfSize() uint64 {
	return uint64(C.elf_size(&o.obj))
}

func (o *ElfObj) ElfOffsetPointerSlice(off uint64, length uint64) ([]byte, error) {
	if m := off + length; o.ElfSize() < m {
		s := fmt.Sprintf("ElfSize() < m => %d < %d", o.ElfSize(), m)
		return nil, errors.New(s)
	}else {
		p := (* byte)(unsafe.Pointer(C.elf_offset_pointer(&o.obj, C.uint64_t(off))))
		return unsafe.Slice(p, length), nil		
	}
}

func (o *ElfObj) ElfOffsetPointer(off uint64) unsafe.Pointer {
	return unsafe.Pointer(C.elf_offset_pointer(&o.obj, C.uint64_t(off)))
}
