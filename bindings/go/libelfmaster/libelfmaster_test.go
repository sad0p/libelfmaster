package libelfmaster

import(
	"testing"
	"reflect"
)


type checkError uint32

const(
	 lookForNil   checkError = 1
	 lookForError checkError = 2
)

type elfOpenObjectCases struct{
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
		got := ElfOpenObject(test.path, &obj, ELF_LOAD_F_FORENSICS)
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

