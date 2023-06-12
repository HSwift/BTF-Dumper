package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/cilium/ebpf/btf"
	"os"
	"reflect"
	"strings"
)

var reader *btf.Spec
var targetTypes = flag.String("target", "", "export specific target types, split by ',', eg: 'struct:a_name,b_name'")
var isDereference = flag.Bool("dereference", false, "skip qualifiers and typedefs")
var isAsMap = flag.Bool("as-map", false, "export the types containing child elements (struct,union,enum) as a map")
var isVerbose = flag.Bool("verbose", false, "display working progress")
var fileName string
var btfFile *os.File

func main() {
	var err error
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\n%s [target]\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "  target: the ELF file to be processed")
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		return
	}
	fileName = flag.Arg(0)
	btfFile, err = os.Open(fileName)
	defer btfFile.Close()
	if err != nil {
		panic(err)
	}
	reader, err = btf.LoadSpecFromReader(btfFile)
	if err != nil {
		panic(err)
	}
	if *targetTypes == "" {
		types := ReadAllBTFType()
		DumpAll(types)
	} else {
		targets := strings.Split(*targetTypes, ",")
		types := WalkForTargetTypes(targets)
		DumpAll(types)
	}
}

func NameToBTFType(name string) btf.Type {
	name = strings.TrimSpace(name)
	switch name {
	case "void":
		return &btf.Void{}
	case "int":
		return &btf.Int{}
	case "pointer":
		return &btf.Pointer{}
	case "array":
		return &btf.Array{}
	case "struct":
		return &btf.Struct{}
	case "union":
		return &btf.Union{}
	case "enum":
		return &btf.Enum{}
	case "fwd":
		return &btf.Fwd{}
	case "typedef":
		return &btf.Typedef{}
	case "volatile":
		return &btf.Volatile{}
	case "restrict":
		return &btf.Restrict{}
	case "func":
		return &btf.Func{}
	case "funcproto":
		return &btf.FuncProto{}
	case "var":
		return &btf.Var{}
	case "Datasec":
		return &btf.Datasec{}
	case "Float":
		return &btf.Float{}
	default:
		panic("type must be one of void, int, pointer, array, struct, union, enum, fwd, typedef, volatile, restrict, func, funcproto, var, Datasec, Float")
	}
}

func DumpAll(types interface{}) {
	outputFile, err := os.Create(fileName + ".json")
	if err != nil {
		panic(err)
	}
	output, err := json.Marshal(types)
	if err != nil {
		panic(err)
	}
	outputFile.Write(output)
	outputFile.Close()
}

func WalkForTargetTypes(targetTypes []string) map[uint32]BTFType {
	results := make(map[uint32]BTFType, 0)
	queue := make([]uint32, 0)
	for _, name := range targetTypes {
		var found btf.Type
		name = strings.TrimSpace(name)
		a, b, success := strings.Cut(name, ":")
		if success {
			found = NameToBTFType(a)
			if err := reader.TypeByName(b, &found); err != nil {
				panic(err)
			}
		} else {
			var err error
			found, err = reader.AnyTypeByName(name)
			if err != nil {
				panic(err)
			}
		}
		foundID, _ := reader.TypeID(found)
		queue = append(queue, uint32(foundID))
	}
	for len(queue) != 0 {
		i := queue[0]
		queue = queue[1:]
		currentType, _ := reader.TypeByID(btf.TypeID(i))
		convertedType := BTFTypeParser(currentType)
		results[i] = convertedType
		deps := convertedType.GetDependencies()
		for _, dep := range deps {
			if _, ok := results[dep]; !ok {
				queue = append(queue, dep)
			}
		}
	}
	return results
}

func ReadAllBTFType() []BTFType {
	iter := reader.Iterate()
	types := make([]BTFType, 0)
	for iter.Next() {
		btfType := BTFTypeParser(iter.Type)
		if btfType != nil {
			types = append(types, btfType)
		}
	}
	return types
}

func GetTypeID(t btf.Type) uint32 {
	if *isDereference {
		t = btf.UnderlyingType(t)
		id, _ := reader.TypeID(t)
		return uint32(id)
	} else {
		id, _ := reader.TypeID(t)
		return uint32(id)
	}
}

type BTFType interface {
	GetTypeName() string
	GetDependencies() []uint32
}

func BTFTypeParser(t btf.Type) BTFType {
	if *isVerbose {
		typeName := reflect.TypeOf(t).Elem().Name()
		typeID, _ := reader.TypeID(t)
		fmt.Printf("[%d] %s: %s\n", typeID, typeName, t.TypeName())
	}
	switch btfType := t.(type) {
	case *btf.Void:
		return BTFVoidParser(btfType)
	case *btf.Int:
		return BTFIntParser(btfType)
	case *btf.Pointer:
		return BTFPointerParser(btfType)
	case *btf.Array:
		return BTFArrayParser(btfType)
	case *btf.Struct:
		return BTFStructParser(btfType)
	case *btf.Union:
		return BTFUnionParser(btfType)
	case *btf.Enum:
		return BTFEnumParser(btfType)
	case *btf.Fwd:
		return BTFFwdParser(btfType)
	case *btf.Typedef:
		return BTFTypeDefParser(btfType)
	case *btf.Volatile:
		return BTFVolatileParser(btfType)
	case *btf.Const:
		return BTFConstParser(btfType)
	case *btf.Restrict:
		return BTFRestrictParser(btfType)
	case *btf.Func:
		return BTFFuncParser(btfType)
	case *btf.FuncProto:
		return BTFFuncProtoParser(btfType)
	case *btf.Var:
		return BTFVarParser(btfType)
	case *btf.Datasec:
		return BTFDatasecParser(btfType)
	case *btf.Float:
		return BTFFloatParser(btfType)
	default:
		panic(fmt.Errorf("unknown type %v", btfType))
	}
	return nil
}

type BTFVoid struct {
	TypeName string `json:"type_name"`
}

func BTFVoidParser(t *btf.Void) *BTFVoid {
	return &BTFVoid{
		TypeName: "void",
	}
}

func (v *BTFVoid) GetTypeName() string {
	return v.TypeName
}

func (v *BTFVoid) GetDependencies() []uint32 {
	return []uint32{}
}

type BTFInt struct {
	TypeName string `json:"type_name"`
	Name     string `json:"name"`
	Size     uint32 `json:"size"`
	Encoding string `json:"encoding"`
}

func BTFIntParser(t *btf.Int) *BTFInt {
	return &BTFInt{
		TypeName: "int",
		Name:     t.Name,
		Size:     t.Size,
		Encoding: t.Encoding.String(),
	}
}

func (v *BTFInt) GetTypeName() string {
	return v.TypeName
}

func (v *BTFInt) GetDependencies() []uint32 {
	return []uint32{}
}

type BTFPointer struct {
	TypeName   string `json:"type_name"`
	TargetType uint32 `json:"target_type"`
}

func BTFPointerParser(t *btf.Pointer) *BTFPointer {
	typeID := GetTypeID(t.Target)
	return &BTFPointer{
		TypeName:   "pointer",
		TargetType: typeID,
	}
}

func (v *BTFPointer) GetTypeName() string {
	return v.TypeName
}

func (v *BTFPointer) GetDependencies() []uint32 {
	return []uint32{v.TargetType}
}

type BTFArray struct {
	TypeName  string `json:"type_name"`
	IndexType uint32 `json:"index_type"`
	ElemType  uint32 `json:"elem_type"`
	Count     uint32 `json:"count"`
}

func BTFArrayParser(t *btf.Array) *BTFArray {
	indexTypeID := GetTypeID(t.Index)
	elemTypeID := GetTypeID(t.Type)
	return &BTFArray{
		TypeName:  "array",
		IndexType: indexTypeID,
		ElemType:  elemTypeID,
		Count:     t.Nelems,
	}
}

func (v *BTFArray) GetTypeName() string {
	return v.TypeName
}

func (v *BTFArray) GetDependencies() []uint32 {
	return []uint32{v.IndexType, v.IndexType}
}

type BTFStruct struct {
	TypeName   string                      `json:"type_name"`
	Size       uint32                      `json:"size"`
	Name       string                      `json:"name"`
	MembersMap map[string]*BTFStructMember `json:"members_map,omitempty"`
	Members    []*BTFStructMember          `json:"members,omitempty"`
}

type BTFStructMember struct {
	Name         string `json:"name"`
	Type         uint32 `json:"type"`
	Offset       uint32 `json:"offset"`
	BitFieldSize uint32 `json:"bit_field_size"`
	Size         int    `json:"size"`
}

func BTFStructParser(t *btf.Struct) *BTFStruct {
	btfStruct := BTFStruct{
		TypeName: "struct",
		Size:     t.Size,
		Name:     t.Name,
	}
	membersMap := make(map[string]*BTFStructMember, len(t.Members))
	members := make([]*BTFStructMember, 0, len(t.Members))
	for _, member := range t.Members {
		memberTypeID := GetTypeID(member.Type)
		size, _ := btf.Sizeof(member.Type)
		btfMember := &BTFStructMember{
			Name:         member.Name,
			Type:         memberTypeID,
			Offset:       member.Offset.Bytes(),
			BitFieldSize: uint32(member.BitfieldSize),
			Size:         size,
		}
		membersMap[member.Name] = btfMember
		members = append(members, btfMember)
	}
	if *isAsMap {
		btfStruct.MembersMap = membersMap
	} else {
		btfStruct.Members = members
	}

	return &btfStruct
}

func (v *BTFStruct) GetTypeName() string {
	return v.TypeName
}

func (v *BTFStruct) GetDependencies() []uint32 {
	deps := make([]uint32, 0)
	if *isAsMap {
		for _, i := range v.MembersMap {
			deps = append(deps, i.Type)
		}
	} else {
		for _, i := range v.Members {
			deps = append(deps, i.Type)
		}
	}
	return deps
}

type BTFUnion struct {
	TypeName   string                      `json:"type_name"`
	Size       uint32                      `json:"size"`
	Name       string                      `json:"name"`
	MembersMap map[string]*BTFStructMember `json:"members_map,omitempty"`
	Members    []*BTFStructMember          `json:"members,omitempty"`
}

func BTFUnionParser(t *btf.Union) *BTFUnion {
	btfUnion := BTFUnion{
		TypeName: "union",
		Size:     t.Size,
		Name:     t.Name,
	}
	membersMap := make(map[string]*BTFStructMember, len(t.Members))
	members := make([]*BTFStructMember, 0, len(t.Members))
	for _, member := range t.Members {
		memberTypeID := GetTypeID(member.Type)
		size, _ := btf.Sizeof(member.Type)
		btfMember := &BTFStructMember{
			Name:         member.Name,
			Type:         memberTypeID,
			Offset:       member.Offset.Bytes(),
			BitFieldSize: uint32(member.BitfieldSize),
			Size:         size,
		}
		membersMap[member.Name] = btfMember
		members = append(members, btfMember)
	}
	if *isAsMap {
		btfUnion.MembersMap = membersMap
	} else {
		btfUnion.Members = members
	}
	return &btfUnion
}

func (v *BTFUnion) GetTypeName() string {
	return v.TypeName
}

func (v *BTFUnion) GetDependencies() []uint32 {
	deps := make([]uint32, 0)
	if *isAsMap {
		for _, i := range v.MembersMap {
			deps = append(deps, i.Type)
		}
	} else {
		for _, i := range v.Members {
			deps = append(deps, i.Type)
		}
	}
	return deps
}

type BTFEnum struct {
	TypeName  string                   `json:"type_name"`
	Name      string                   `json:"name"`
	Size      uint32                   `json:"size"`
	Signed    bool                     `json:"signed"`
	ValuesMap map[uint64]*BTFEnumValue `json:"values_map,omitempty"`
	Values    []*BTFEnumValue          `json:"values,omitempty"`
}

type BTFEnumValue struct {
	Name  string `json:"name"`
	Value uint64 `json:"value"`
}

func BTFEnumParser(t *btf.Enum) *BTFEnum {
	btfEnum := &BTFEnum{
		TypeName: "enum",
		Name:     t.Name,
		Size:     t.Size,
		Signed:   t.Signed,
	}
	valuesMap := make(map[uint64]*BTFEnumValue, len(t.Values))
	values := make([]*BTFEnumValue, 0, len(t.Values))
	for _, value := range t.Values {
		btfValue := &BTFEnumValue{
			Name:  value.Name,
			Value: value.Value,
		}
		valuesMap[value.Value] = btfValue
		values = append(values, btfValue)
	}
	if *isAsMap {
		btfEnum.ValuesMap = valuesMap
	} else {
		btfEnum.Values = values
	}
	return btfEnum
}

func (v *BTFEnum) GetTypeName() string {
	return v.TypeName
}

func (v *BTFEnum) GetDependencies() []uint32 {
	return []uint32{}
}

type BTFFwd struct {
	TypeName string `json:"type_name"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
}

func BTFFwdParser(t *btf.Fwd) *BTFFwd {
	return &BTFFwd{
		TypeName: "fwd",
		Name:     t.Name,
		Kind:     t.Kind.String(),
	}
}

func (v *BTFFwd) GetTypeName() string {
	return v.TypeName
}

func (v *BTFFwd) GetDependencies() []uint32 {
	return []uint32{}
}

type BTFTypeDef struct {
	TypeName string `json:"type_name"`
	Name     string `json:"name"`
	Type     uint32 `json:"type"`
}

func BTFTypeDefParser(t *btf.Typedef) *BTFTypeDef {
	typeID := GetTypeID(t.Type)
	return &BTFTypeDef{
		TypeName: "typedef",
		Name:     t.Name,
		Type:     typeID,
	}
}

func (v *BTFTypeDef) GetTypeName() string {
	return v.TypeName
}

func (v *BTFTypeDef) GetDependencies() []uint32 {
	return []uint32{v.Type}
}

type BTFVolatile struct {
	TypeName string `json:"type_name"`
	Type     uint32 `json:"type"`
}

func BTFVolatileParser(t *btf.Volatile) *BTFVolatile {
	typeID := GetTypeID(t.Type)
	return &BTFVolatile{
		TypeName: "volatile",
		Type:     typeID,
	}
}

func (v *BTFVolatile) GetTypeName() string {
	return v.TypeName
}

func (v *BTFVolatile) GetDependencies() []uint32 {
	return []uint32{v.Type}
}

type BTFConst struct {
	TypeName string `json:"type_name"`
	Type     uint32 `json:"type"`
}

func BTFConstParser(t *btf.Const) *BTFConst {
	typeID := GetTypeID(t.Type)
	return &BTFConst{
		TypeName: "const",
		Type:     typeID,
	}
}

func (v *BTFConst) GetTypeName() string {
	return v.TypeName
}

func (v *BTFConst) GetDependencies() []uint32 {
	return []uint32{v.Type}
}

type BTFRestrict struct {
	TypeName string `json:"type_name"`
	Type     uint32 `json:"type"`
}

func BTFRestrictParser(t *btf.Restrict) *BTFRestrict {
	typeID := GetTypeID(t.Type)
	return &BTFRestrict{
		TypeName: "restrict",
		Type:     typeID,
	}
}

func (v *BTFRestrict) GetTypeName() string {
	return v.TypeName
}

func (v *BTFRestrict) GetDependencies() []uint32 {
	return []uint32{v.Type}
}

type BTFFunc struct {
	TypeName string `json:"type_name"`
	Name     string `json:"name"`
	Type     uint32 `json:"type"`
	Linkage  string `json:"linkage"`
}

func BTFFuncParser(t *btf.Func) *BTFFunc {
	typeID := GetTypeID(t.Type)
	return &BTFFunc{
		TypeName: "func",
		Name:     t.Name,
		Type:     typeID,
		Linkage:  t.Linkage.String(),
	}
}

func (v *BTFFunc) GetTypeName() string {
	return v.TypeName
}

func (v *BTFFunc) GetDependencies() []uint32 {
	return []uint32{v.Type}
}

type BTFFuncProto struct {
	TypeName string          `json:"type_name"`
	Return   uint32          `json:"return"`
	Params   []*BTFFuncParam `json:"params"`
}

type BTFFuncParam struct {
	Name string `json:"name"`
	Type uint32 `json:"type"`
}

func BTFFuncProtoParser(t *btf.FuncProto) *BTFFuncProto {
	returnTypeID := GetTypeID(t.Return)
	btfFuncProto := &BTFFuncProto{
		TypeName: "funcproto",
		Return:   returnTypeID,
	}
	btfFuncParams := make([]*BTFFuncParam, 0, len(t.Params))
	for _, param := range t.Params {
		paramTypeID := GetTypeID(param.Type)
		btfFuncParam := &BTFFuncParam{
			Name: param.Name,
			Type: paramTypeID,
		}
		btfFuncParams = append(btfFuncParams, btfFuncParam)
	}
	btfFuncProto.Params = btfFuncParams
	return btfFuncProto
}

func (v *BTFFuncProto) GetTypeName() string {
	return v.TypeName
}

func (v *BTFFuncProto) GetDependencies() []uint32 {
	deps := make([]uint32, 0)
	deps = append(deps, v.Return)
	for _, i := range v.Params {
		deps = append(deps, i.Type)
	}
	return deps
}

type BTFVar struct {
	TypeName string `json:"type_name"`
	Name     string `json:"name"`
	Type     uint32 `json:"type"`
	Linkage  string `json:"linkage"`
}

func BTFVarParser(t *btf.Var) *BTFVar {
	TypeID := GetTypeID(t.Type)
	return &BTFVar{
		TypeName: "var",
		Name:     t.Name,
		Type:     TypeID,
		Linkage:  t.Linkage.String(),
	}
}

func (v *BTFVar) GetTypeName() string {
	return v.TypeName
}

func (v *BTFVar) GetDependencies() []uint32 {
	return []uint32{v.Type}
}

type BTFDatasec struct {
	TypeName string           `json:"type_name"`
	Name     string           `json:"name"`
	Size     uint32           `json:"size"`
	Vars     []*BTFVarSecInfo `json:"vars"`
}

type BTFVarSecInfo struct {
	Type   uint32 `json:"type"`
	Offset uint32 `json:"offset"`
	Size   uint32 `json:"size"`
}

func BTFDatasecParser(t *btf.Datasec) *BTFDatasec {
	btfDatasec := &BTFDatasec{
		TypeName: "datasec",
		Name:     t.Name,
		Size:     t.Size,
	}
	btfVarSecInfos := make([]*BTFVarSecInfo, 0, len(t.Vars))
	for _, varSecInfo := range t.Vars {
		TypeID := GetTypeID(varSecInfo.Type)
		btfVarSecInfo := &BTFVarSecInfo{
			Type:   TypeID,
			Offset: varSecInfo.Offset,
			Size:   varSecInfo.Size,
		}
		btfVarSecInfos = append(btfVarSecInfos, btfVarSecInfo)
	}
	btfDatasec.Vars = btfVarSecInfos
	return btfDatasec
}

func (v *BTFDatasec) GetTypeName() string {
	return v.TypeName
}

func (v *BTFDatasec) GetDependencies() []uint32 {
	deps := make([]uint32, 0)
	for _, i := range v.Vars {
		deps = append(deps, i.Type)
	}
	return deps
}

type BTFFloat struct {
	TypeName string `json:"type_name"`
	Name     string `json:"name"`
	Size     uint32 `json:"size"`
}

func BTFFloatParser(t *btf.Float) *BTFFloat {
	return &BTFFloat{
		TypeName: "float",
		Name:     t.Name,
		Size:     t.Size,
	}
}

func (v *BTFFloat) GetTypeName() string {
	return v.TypeName
}

func (v *BTFFloat) GetDependencies() []uint32 {
	return []uint32{}
}
