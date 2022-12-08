package libelfmaster

import (
	"errors"
	"unsafe"
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
	v := int(C.elf_arch_w(&o.obj))
	switch v {
	case 0:
		return "i386"
	case 1:
		return "x64"
	default:
		return "unsupported"
	}
}

func (o *ElfObj) ElfClass() string {
	v := int(C.elf_class_w(&o.obj))
	switch v {
	case 0:
		return "elfclass64"
	default:
		return "elfclass32"
	}
}

func (o *ElfObj) ElfLinkingType() string {
	v := int(C.elf_linking_type_w(&o.obj))
	switch v {
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
