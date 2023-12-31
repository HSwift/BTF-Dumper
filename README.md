# BTF-Dumper
A tool to convert BTF information to json

## Usage

```
Usage of ./main:
  -as-map
        export the types containing child elements (struct,union,enum) as a map
  -dereference
        skip qualifiers and typedefs
  -target string
        export specific target types, split by ',', eg: 'struct:a_name,b_name'
  -verbose
        display working progress

./main [target]
  target: the ELF file to be processed
```

## generate BTF

### compile with BTF information

```shell
gcc -gbtf source.c
```

### convert DWARF to BTF
Normally, the debugging information generated by gcc is in DWARF format, which we can convert to BTF using the following command

```shell
pahole ./elf-wth-debug-info -J
```

## example

1. create source.c

```c
typedef struct {
    int v1;
    short v2;
    char v3;
} Foo;

void bar(Foo* foo) { }

int main(){}
```

2. compile and dump types

```shell
gcc -gbtf source.c -o example
btf-dumper ./example
```

3. check example.json

```json
[
  {
    "type_name": "void"
  },
  {
    "type_name": "struct",
    "size": 8,
    "name": "",
    "members": [
      {
        "name": "v1",
        "type": 2,
        "offset": 0,
        "bit_field_size": 0,
        "size": 4
      },
      {
        "name": "v2",
        "type": 3,
        "offset": 4,
        "bit_field_size": 0,
        "size": 2
      },
      {
        "name": "v3",
        "type": 4,
        "offset": 6,
        "bit_field_size": 0,
        "size": 1
      }
    ]
  },
  {
    "type_name": "int",
    "name": "int",
    "size": 4,
    "encoding": "signed"
  },
  {
    "type_name": "int",
    "name": "short int",
    "size": 2,
    "encoding": "signed"
  },
  {
    "type_name": "int",
    "name": "char",
    "size": 1,
    "encoding": "signed"
  },
  {
    "type_name": "typedef",
    "name": "Foo",
    "type": 1
  },
  {
    "type_name": "funcproto",
    "return": 2,
    "params": []
  },
  {
    "type_name": "funcproto",
    "return": 0,
    "params": [
      {
        "name": "foo",
        "type": 8
      }
    ]
  },
  {
    "type_name": "pointer",
    "target_type": 5
  },
  {
    "type_name": "func",
    "name": "main",
    "type": 6,
    "linkage": "global"
  },
  {
    "type_name": "func",
    "name": "bar",
    "type": 7,
    "linkage": "global"
  }
]
```