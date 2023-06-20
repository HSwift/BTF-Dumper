export declare namespace BTF {
    interface Void {
        type_name: "void";
    }

    interface Pointer {
        type_name: "pointer";
        target_type: number;
    }

    interface Int {
        type_name: "int";
        name: string;
        size: number;
        encoding: string;
    }

    interface Array {
        type_name: "array";
        index_type: number;
        elem_type: number;
        count: number;
    }

    interface Struct {
        type_name: "struct";
        size: number;
        name: string;
        members_map?: { [key: string]: StructMember };
        members?: StructMember[];
    }

    interface StructMember {
        name: string;
        type: number;
        offset: number;
        bit_field_size: number;
        size: number;
    }

    interface Union {
        type_name: "union";
        size: number;
        name: string;
        members_map?: { [key: string]: StructMember };
        members?: StructMember[];
    }

    interface Enum {
        type_name: "enum";
        name: string;
        size: number;
        signed: boolean;
        values_map?: { [key: number]: EnumValue };
        values?: EnumValue[];
    }

    interface EnumValue {
        name: string;
        value: number;
    }

    interface Fwd {
        type_name: "fwd";
        name: string;
        kind: string;
    }

    interface TypeDef {
        type_name: "typedef";
        name: string;
        type: number;
    }

    interface Volatile {
        type_name: "volatile";
        type: number;
    }

    interface Const {
        type_name: "const";
        type: number;
    }

    interface Restrict {
        type_name: "restrict";
        type: number;
    }

    interface Func {
        type_name: "func";
        name: string;
        type: number;
        linkage: string;
    }

    interface FuncProto {
        type_name: "funcproto";
        return: number;
        params: FuncParam[];
    }

    interface FuncParam {
        name: string;
        type: number;
    }

    interface Var {
        type_name: "var";
        name: string;
        type: number;
        linkage: string;
    }

    interface Datasec {
        type_name: "datasec";
        name: string;
        size: number;
        vars: VarSecInfo[];
    }

    interface VarSecInfo {
        type: number;
        offset: number;
        size: number;
    }

    interface Float {
        type_name: "float";
        name: string;
        size: number;
    }

    type Types =
        | Void
        | Pointer
        | Int
        | Array
        | Struct
        | Union
        | Enum
        | Fwd
        | TypeDef
        | Volatile
        | Const
        | Restrict
        | Func
        | FuncProto
        | Var
        | Datasec
        | Float;

    type TypesHasName =
        | Int
        | Struct
        | Union
        | Enum
        | Fwd
        | TypeDef
        | Func
        | Var
        | Datasec
        | Float;

    type Map = Record<string, Types>;
    type List = Types[];
}
