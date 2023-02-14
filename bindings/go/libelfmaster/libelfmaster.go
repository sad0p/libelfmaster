package libelfmaster

import (
	"debug/elf"
	"errors"
	"fmt"
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

int elf_symtab_count_w(elfobj_t *obj, uint64_t *count)
{
	return (int)elf_symtab_count(obj, count);
}

int elf_dynsym_count_w(elfobj_t *obj, uint64_t *count)
{
	return (int)elf_dynsym_count(obj, count);
}

int elf_symbol_by_name_w(elfobj_t *obj, const char *name, struct elf_symbol *symbol)
{
	return (int)elf_symbol_by_name(obj, name, symbol);
}

int elf_symbol_by_index_w(elfobj_t *obj, unsigned int index, struct elf_symbol *symbol, const uint32_t which)
{
	return (int)elf_symbol_by_index(obj, index, symbol, (const int)which);
}

int elf_symbol_by_range_w(elfobj_t *obj, uint64_t addr, struct elf_symbol *symbol)
{
	return (int)elf_symbol_by_range(obj, addr, symbol);
}

int elf_symbol_by_value_lookup_w(elfobj_t *obj, uint64_t addr, struct elf_symbol *symbol)
{
	return (int)elf_symbol_by_value_lookup(obj, addr, symbol);
}

int elf_plt_by_name_w(elfobj_t *obj, const char *name, struct elf_plt *entry)
{
	return (int)elf_plt_by_name(obj, name, entry);
}

int elf_section_by_name_w(elfobj_t *obj, const char *name, struct elf_section *entry)
{
	return (int)elf_section_by_name(obj, name, entry);
}

int elf_section_by_index_w(elfobj_t *obj, unsigned int index, struct elf_section *entry)
{
	return (int)elf_section_by_index(obj, index, entry);
}

int elf_section_index_by_name_w(elfobj_t *obj, const char *name, uint64_t *index) {
	return (int)elf_section_index_by_name(obj, name, index);
}

int elf_segment_by_index_w(elfobj_t *obj, uint64_t index, struct elf_segment *segment)
{
	return (int)elf_segment_by_index(obj, index, segment);
}

*/
import "C"

type ElfObj struct {
	obj      C.elfobj_t
	errorMsg C.elf_error_t
}

type ElfSymbol struct {
	Name       string
	Value      uint64
	Size       uint64
	ShNdx      uint16
	Bind       uint8
	Type       uint8
	Visibility uint8
}

type ElfPlt struct {
	SymName string
	Addr    uint64
}

type ElfSection struct {
	Name    string
	Type    uint32
	Link    uint32
	Info    uint32
	Flags   uint64
	Align   uint64
	Entsize uint64
	Offset  uint64
	Address uint64
	Size    uint64
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
	} else {
		p := (*byte)(unsafe.Pointer(C.elf_offset_pointer(&o.obj, C.uint64_t(off))))
		return unsafe.Slice(p, length), nil
	}
}

func (o *ElfObj) ElfOffsetPointer(off uint64) unsafe.Pointer {
	return unsafe.Pointer(C.elf_offset_pointer(&o.obj, C.uint64_t(off)))
}

func intToBool(i int) (ret bool) {
	switch i {
	case 1:
		ret = true
	default:
		ret = false
	}
	return
}

func (o *ElfObj) ElfSymTabCount(count *uint64) (ret bool) {
	var localCount C.uint64_t
	ret = intToBool(int(C.elf_symtab_count_w(&o.obj, &localCount)))
	if ret {
		*count = uint64(localCount)
	}
	return
}

func (o *ElfObj) ElfDynSymTabCount(count *uint64) (ret bool) {
	var localCount C.uint64_t
	ret = intToBool(int(C.elf_dynsym_count_w(&o.obj, &localCount)))

	if ret {
		*count = uint64(localCount)
	}
	return
}

func (o *ElfObj) ElfDtagCount() (count uint64) {
	count = uint64(C.elf_dtag_count(&o.obj))
	return
}

func convertElfSymbol(from *C.struct_elf_symbol, to *ElfSymbol) {
	to.Name = C.GoString(from.name)
	to.Value = uint64(from.value)
	to.Size = uint64(from.size)
	to.ShNdx = uint16(from.shndx)
	to.Bind = uint8(from.bind)
	to.Type = uint8(from._type)
	to.Visibility = uint8(from.visibility)
}

func (o *ElfObj) ElfSymbolByName(name string, symbol *ElfSymbol) (ret bool) {
	var localSymbol C.struct_elf_symbol
	n := C.CString(name)

	defer C.free(unsafe.Pointer(n))

	ret = intToBool(int(C.elf_symbol_by_name_w(&o.obj, n, &localSymbol)))
	if ret {
		convertElfSymbol(&localSymbol, symbol)
	}
	return
}

func (o *ElfObj) ElfSymbolByIndex(index uint32, symbol *ElfSymbol, tableType elf.SectionType) (ret bool) {
	var localSymbol C.struct_elf_symbol
	which := uint32(tableType)

	ret = intToBool(int(C.elf_symbol_by_index_w(&o.obj, C.uint32_t(index), &localSymbol, C.uint32_t(which))))
	if ret {
		convertElfSymbol(&localSymbol, symbol)
	}
	return
}

func (o *ElfObj) ElfSymbolByRange(addr uint64, symbol *ElfSymbol) (ret bool) {
	ret = o.ElfSymbolByValue(addr, symbol)
	return
}

func (o *ElfObj) ElfSymbolByValue(addr uint64, symbol *ElfSymbol) (ret bool) {
	var localSymbol C.struct_elf_symbol

	ret = intToBool(int(C.elf_symbol_by_range_w(&o.obj, C.uint64_t(addr), &localSymbol)))
	if ret {
		convertElfSymbol(&localSymbol, symbol)
	}
	return
}

func (o *ElfObj) ElfSymbolByValueLookup(addr uint64, symbol *ElfSymbol) (ret bool) {
	var localSymbol C.struct_elf_symbol

	ret = intToBool(int(C.elf_symbol_by_value_lookup_w(&o.obj, C.uint64_t(addr), &localSymbol)))
	if ret {
		convertElfSymbol(&localSymbol, symbol)
	}
	return
}

func (o *ElfObj) ElfPltByName(name string, pltEntry *ElfPlt) (ret bool) {
	var localPlt C.struct_elf_plt
	n := C.CString(name)

	defer C.free(unsafe.Pointer(n))

	ret = intToBool(int(C.elf_plt_by_name_w(&o.obj, n, &localPlt)))
	if ret {
		pltEntry.SymName = C.GoString(localPlt.symname)
		pltEntry.Addr = uint64(localPlt.addr)
	}
	return
}

func convertElfSection(from *C.struct_elf_section, to *ElfSection) {
	to.Name = C.GoString(from.name)
	to.Type = uint32(from._type)
	to.Link = uint32(from.link)
	to.Info = uint32(from.info)
	to.Flags = uint64(from.flags)
	to.Align = uint64(from.align)
	to.Entsize = uint64(from.entsize)
	to.Offset = uint64(from.offset)
	to.Address = uint64(from.address)
	to.Size = uint64(from.size)
}

func (o *ElfObj) ElfSectionByName(name string, section *ElfSection) (ret bool) {
	var localSection C.struct_elf_section
	n := C.CString(name)

	defer C.free(unsafe.Pointer(n))

	ret = intToBool(int(C.elf_section_by_name_w(&o.obj, n, &localSection)))
	if ret {
		convertElfSection(&localSection, section)
	}
	return
}

func (o *ElfObj) ElfSectionByIndex(index uint32, section *ElfSection) (ret bool) {
	var localSection C.struct_elf_section
	ret = intToBool(int(C.elf_section_by_index_w(&o.obj, C.uint32_t(index), &localSection)))
	if ret {
		convertElfSection(&localSection, section)
	}
	return
}

func (o *ElfObj) ElfSectionIndexByName(name string, index *uint64) (ret bool) {
	var localIndex C.uint64_t

	n := C.CString(name)
	defer C.free(unsafe.Pointer(n))

	ret = intToBool(int(C.elf_section_index_by_name_w(&o.obj, n, &localIndex)))
	if ret {
		*index = uint64(localIndex)
	}
	return
}

/*
	Instead of elf_section_iterator_init() and elf_section_interator_next(), we just return an array of all sections.
	This avoids breaking cgo rules around memory allocation between Go Pointers and C pointers.
*/

func (o *ElfObj) ElfSectionsArray() (sectionsArray []ElfSection) {
	var sNdx uint32
	for {
		var section ElfSection
		if ok := o.ElfSectionByIndex(sNdx, &section); !ok {
			break
		}
		sectionsArray = append(sectionsArray, section)
		sNdx++
	}
	return
}

type ElfSegment struct {
	Type     uint32
	Flags    uint32
	Offset   uint64
	PAddress uint64
	VAddress uint64
	Filesz   uint64
	Memsz    uint64
	Align    uint64
	Index    uint32
}

func convertElfSegment(from *C.struct_elf_segment, to *ElfSegment) {
	to.Type = uint32(from._type)
	to.Flags = uint32(from.flags)
	to.Offset = uint64(from.offset)
	to.PAddress = uint64(from.paddr)
	to.VAddress = uint64(from.vaddr)
	to.Filesz = uint64(from.filesz)
	to.Memsz = uint64(from.memsz)
	to.Align = uint64(from.align)
	to.Index = uint32(from.index)
}

func (o *ElfObj) ElfSegmentByIndex(index uint64, segment *ElfSegment) (ret bool) {
	var localSegment C.struct_elf_segment
	ret = intToBool(int(C.elf_segment_by_index_w(&o.obj, C.uint64_t(index), &localSegment)))

	if ret {
		convertElfSegment(&localSegment, segment)
	}
	return
}

func (o *ElfObj) ElfSegmentsArray() (segArray []ElfSegment) {
	var segNdx uint64

	for {
		var segment ElfSegment
		if ok := o.ElfSegmentByIndex(segNdx, &segment); !ok {
			break
		}
		segArray = append(segArray, segment)
		segNdx++
	}
	return
}
