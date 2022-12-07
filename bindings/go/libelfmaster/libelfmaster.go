package libelfmaster

// #cgo CFLAGS: -I /opt/elfmaster/include
// #cgo LDFLAGS: -L /opt/elfmaster/lib -lelfmaster
// #define _GNU_SOURCE
// #include <stdio.h>
// #include <stdlib.h>
// #include <elf.h>
// #include <sys/types.h>
// #include <search.h>
// #include <sys/time.h>
// #include "libelfmaster.h"
// int elf_open_object_w(const char *path, elfobj_t *obj, uint64_t flags, elf_error_t *error) {
//     return (int)elf_open_object(path, obj, flags, error);
// }
import "C"
import "unsafe"
import "errors"

type ElfObj struct {
	obj C.elfobj_t
	errorMsg C.elf_error_t
}

const(
	ELF_LOAD_F_STRICT 	uint64 = uint64(C.ELF_LOAD_F_STRICT)
	ELF_LOAD_F_SMART        uint64 = uint64(C.ELF_LOAD_F_SMART) 
	ELF_LOAD_F_FORENSICS 	uint64 = uint64(C.ELF_LOAD_F_FORENSICS)
	ELF_LOAD_F_MODIFY       uint64 = uint64(C.ELF_LOAD_F_MODIFY)
	ELF_LOAD_F_ULEXEC       uint64 = uint64(C.ELF_LOAD_F_ULEXEC)
	ELF_LOAD_F_MAP_WRITE	uint64 = uint64(C.ELF_LOAD_F_MAP_WRITE)
	ELF_LOAD_F_LXC_MODE	uint64 = uint64(C.ELF_LOAD_F_LXC_MODE)
)

func ElfOpenObject(path string, o *ElfObj, flags uint64) error {
	t := C.CString(path)
	defer C.free(unsafe.Pointer(t))

	r := int(C.elf_open_object_w(t, &o.obj, C.uint64_t(flags), &o.errorMsg))
		
	switch(r) {
	case 1:
		return nil
	default:
		e := C.GoString(C.elf_error_msg(&o.errorMsg)) 
		return errors.New(e)
	}
}


