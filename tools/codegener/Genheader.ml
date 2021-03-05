(*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 *)

open Intel.Ast
open Intel.CodeGen
open Printf
open Commonfunc

let generate_header_start (name: string) (tag: string) =
    let guard =
        sprintf "CODEGENER_%s_%s_H" (String.uppercase_ascii name) tag
    in
    "#ifndef " ^ guard ^ "\n" ^ "#define " ^ guard ^ "\n\n"

let generate_args_include (ufs: untrusted_func list) =
    let error_include =
        if List.exists (fun f -> f.uf_propagate_errno) ufs then "#include <errno.h>"
    else "/* #include <errno.h> - Errno propagation not enabled so not included. */"
    in
    "#include <stdint.h>\n" ^
    "#include <stdlib.h>\n\n" ^
    "#include \"enclave.h\"\n" ^
    error_include ^ "\n"

let generate_function_id (f: func_decl) =
    let f_name = f.fname in
    "fid_" ^ f_name

let generate_unrproxy_prototype (fd: func_decl) =
    let func_name = fd.fname in
  let func_args =
      let func_args_list =
          List.map (fun f -> gen_parm_str f) fd.plist
    in
    if List.length fd.plist > 0 then
        let func_args_pre = String.concat ",\n    " func_args_list in
        "(\n    " ^ ( match fd.rtype with Void -> "" ^ func_args_pre 
                                         |   _ -> (get_tystr fd.rtype ^ "* retval,\n    "  ^ func_args_pre))
    else
        "(\n    " ^ ( match fd.rtype with Void -> ""
                                          |   _ -> (get_tystr fd.rtype ^ "* retval"))
    in
    [
        "cc_enclave_result_t " ^ func_name ^  func_args ^")";
    ]

let generate_rproxy_prototype (fd: func_decl) =
    let func_name = fd.fname in
    let enclave_decl = 
        "(\n    " ^  (match fd.rtype with Void -> "cc_enclave_t *enclave" | _ -> "cc_enclave_t *enclave,\n    " ^ (get_tystr fd.rtype ^ "* retval"))
    in
  let func_args =
      let func_args_list =
          List.map (fun f -> gen_parm_str f) fd.plist
    in
    if List.length fd.plist > 0 then
        let func_args_pre = String.concat ",\n    " func_args_list in
        ",\n    " ^ func_args_pre
        else ""
        in
    [
        "cc_enclave_result_t " ^ func_name ^ enclave_decl ^ func_args ^")";
    ]

let generate_parm_str (p: pdecl) =
    let (_, declr) = p in
    declr.identifier

let get_struct_ele_str (p: pdecl) =
    let (pt, decl) = p in
    let stype = get_param_atype pt in
    get_typed_declr_str stype decl

let get_union_ele_str (m: mdecl) =
    let (stype, decl) = m in
    get_typed_declr_str stype decl

let generate_struct_def (s: struct_def) =
    let struct_name = s.sname in
    let struct_body_pre = s.smlist in
    let struct_body =
        if List.length struct_body_pre > 0 then
            let struct_body_list =
                List.map (fun f -> sprintf "    %s;" (get_struct_ele_str f)) struct_body_pre
    in
      String.concat "\n" struct_body_list
    else ""
            in
    "typedef struct " ^ struct_name ^ "\n{\n" ^ struct_body ^ "\n} " ^ struct_name ^ ";\n"

let generate_union_def (u: union_def) =
    let union_name = u.uname in
    let union_body_pre = u.umlist in
    let union_body =
        if List.length union_body_pre > 0 then
            let union_body_list =
                List.map (fun f -> sprintf  "    %s;" (get_union_ele_str f)) union_body_pre
    in
      String.concat "\n" union_body_list
        else ""
            in
    "typedef union " ^ union_name ^ "\n{\n" ^ union_body ^ "\n} " ^ union_name ^ ";\n"

let generate_enum_def (e: enum_def) =
    let get_enum_ele_str (ele: enum_ele) =
        let (estr, eval) = ele in
        match eval with
      EnumValNone -> estr
    | EnumVal eeval -> estr ^ "=" ^ (attr_value_to_string eeval)
        in
    let enum_name = e.enname in
    let enum_body_pre = e.enbody in
    let enum_body =
        if List.length enum_body_pre > 0 then
            let enum_body_list =
                List.map (fun f -> sprintf  "%s" (get_enum_ele_str f)) enum_body_pre
    in
      String.concat ",\n    " enum_body_list
        else ""
            in
    if enum_name = "" then
        "enum \n{\n    " ^ enum_body ^ "\n};\n"
        else "typedef enum " ^ enum_name ^ "\n{\n    " ^ enum_body ^ "\n} " ^ enum_name ^ ";\n"

let generate_comp_def (ct: composite_type) =
    match ct with
      StructDef s -> generate_struct_def s
    | UnionDef u -> generate_union_def u
    | EnumDef e -> generate_enum_def e

let generate_trust_marshal_struct (tf: trusted_func) =
    let fd = tf.tf_fdecl in
    let s_name =
        sprintf "%s_size_t" fd.fname
    in
    let struct_start = "typedef struct _" ^ s_name ^ "\n{\n    size_t retval_size;\n" in
    let struct_body =
        let struct_body_list =
            List.map (fun f -> "    size_t " ^ generate_parm_str f ^"_size;") fd.plist
    in
    let struct_body_para = String.concat "\n" struct_body_list in   
    let deep_copy = List.filter is_deep_copy fd.plist in 
    let pre (_: parameter_type) = "\n    " in
    let post = "" in
    let generator (_ : parameter_type) (_ : parameter_type) (decl : declarator) (mem_decl : declarator) =
        sprintf "size_t %s_%s_size;" decl.identifier mem_decl.identifier in 
    let deep_copy_para = 
        String.concat "\n    "
            (List.map (deep_copy_func pre generator post) deep_copy);
    in
    struct_body_para ^ deep_copy_para;
    in
    let struct_end =
        sprintf "} %s;\n" s_name
    in
    if struct_body = "" then
        struct_start ^ struct_end
    else struct_start ^ struct_body ^ "\n" ^ struct_end

let generate_untrust_marshal_struct (uf: untrusted_func) =
    let fd = uf.uf_fdecl in
    let s_name =
        sprintf "%s_size_t" fd.fname
    in
    let struct_start = "typedef struct _" ^ s_name ^ "\n{\n    size_t retval_size;\n" in
    let struct_body =
        let struct_body_list =
            List.map (fun f -> "    size_t " ^ generate_parm_str f ^"_size;") fd.plist
    in
    let struct_body_para = String.concat "\n" struct_body_list in
    let deep_copy = List.filter is_deep_copy fd.plist in
    let pre (_: parameter_type) = "\n    " in
    let post = "" in
    let generator (_ : parameter_type) (_ : parameter_type) (decl : declarator) (mem_decl : declarator) =
        sprintf "size_t %s_%s_size;" decl.identifier mem_decl.identifier in
    let deep_copy_para =
        String.concat "\n    "
            (List.map (deep_copy_func pre generator post) deep_copy);
    in
    struct_body_para ^ deep_copy_para;
    in
    let struct_end =
        sprintf "} %s;\n" s_name
    in
    if struct_body = "" then
        struct_start ^ struct_end
    else struct_start ^ struct_body ^ "\n" ^ struct_end


let c_start = "#ifdef __cplusplus\n" ^ "extern \"C\" {\n" ^ "#endif\n"
let c_end = "\n#ifdef __cplusplus\n" ^ "}\n" ^ "#endif\n"

let generate_args_header (ec: enclave_content) =
    let hfile_start =
        generate_header_start ec.file_shortnm "ARGS"
    in
    let hfile_end = "#endif\n" in
    let hfile_include =
        generate_args_include ec.ufunc_decls
    in
    let def_include_com = "/**** User includes. ****/\n" in
    let def_include_list = ec.include_list in
    let def_include =
        if List.length def_include_list > 0 then
            let def_include_pre =
                List.map (fun f -> "#include \"" ^ f ^ "\"") def_include_list
    in
      String.concat "\n"  def_include_pre
    else "/* There were no user defined types. */"
            in
    let def_types_com = "/**** User defined types in EDL. ****/\n" in
    let def_types_list = ec.comp_defs in
    let def_types =
        if List.length def_types_list > 0 then
            let def_types_pre =
                List.map generate_comp_def def_types_list
    in
      String.concat "\n"  def_types_pre
        else "/* There were no user defined types. */\n"
            in
    let trust_fstruct_com = "/**** Trusted function marshalling structs. ****/\n" in
    let untrust_fstruct_com = "/**** Untrusted function marshalling structs. ****/\n" in
    let trust_fstruct =
        let trust_fstruct_pre =
            List.map generate_trust_marshal_struct ec.tfunc_decls
    in
    String.concat "\n" trust_fstruct_pre
        in
    let untrust_fstruct =
        let untrust_fstruct_pre =
            List.map generate_untrust_marshal_struct ec.ufunc_decls
    in
    String.concat "\n" untrust_fstruct_pre
        in
    let trust_fid_com = "/**** Trusted function IDs ****/\n" in
    let untrust_fid_com = "/**** Untrusted function IDs ****/\n" in
    let trust_fid_body =
        let trust_fid_pre =
            List.mapi
        (fun i f -> sprintf "    %s = %d," (generate_function_id f.tf_fdecl) i) ec.tfunc_decls
    in
    String.concat "\n" trust_fid_pre
        in
    let untrust_fid_body = 
        let untrust_fid_pre = 
            List.mapi
          (fun i f -> sprintf "    %s = %d," (generate_function_id f.uf_fdecl) i) ec.ufunc_decls
    in
      String.concat "\n" untrust_fid_pre
        in
    let untrust_fid_max = 
        "    fid_untrusted_call_id_max = SECGEAR_ENUM_MAX\n"
    in
    let trust_fid_max =
        "    fid_trusted_call_id_max = SECGEAR_ENUM_MAX\n"
    in
    let trust_fid = "enum\n{\n" ^ trust_fid_body ^ "\n" ^ trust_fid_max ^ "};" in
    let untrust_fid = "enum\n{\n" ^ untrust_fid_body ^ "\n" ^ untrust_fid_max ^ "};" in
    [
        hfile_start ^ hfile_include;
      def_include_com ^ def_include;
      c_start;
      def_types_com ^ def_types;
      trust_fstruct_com ^ trust_fstruct;
      untrust_fstruct_com ^ untrust_fstruct;
      trust_fid_com ^ trust_fid; 
      untrust_fid_com ^ untrust_fid;
      c_end; 
      hfile_end;
    ]

let generate_trusted_header (ec: enclave_content) =
    let hfile_start =
        generate_header_start ec.file_shortnm "T"
    in
    let hfile_end = "#endif\n" in
    let hfile_include =
        sprintf "#include \"enclave.h\"\n\n#include \"%s_args.h\"\n#include \"status.h\"\n#include \"gp.h\"\n#include \"gp_ocall.h\"\n" ec.file_shortnm
    in
    let trust_fproto_com = "/**** Trusted function prototypes. ****/\n" in
    let untrust_fproto_com = "/**** Untrusted function prototypes. ****/\n" in
    let r_proxy_proto = 
        List.map (fun f -> generate_unrproxy_prototype f.uf_fdecl) ec.ufunc_decls
    in
    let r_proxy = 
        String.concat ";\n\n" (List.flatten r_proxy_proto)
    in
    let trust_func_proto =
        List.map gen_func_proto (tf_list_to_fd_list ec.tfunc_decls)
    in
    let trust_func =
        String.concat ";\n\n" trust_func_proto
    in
    [
        hfile_start ^ hfile_include; 
        c_start; 
        trust_fproto_com ^ trust_func ^ ";"; 
        if (List.length ec.ufunc_decls <> 0) then untrust_fproto_com ^ r_proxy ^ ";"
        else "/**** There is no untrusted function ****/";
        c_end; 
        hfile_end;
    ]

let generate_untrusted_header (ec: enclave_content) =
    let hfile_start =
        generate_header_start ec.file_shortnm "U"
    in
    let hfile_end = "#endif\n" in
    let hfile_include =
        sprintf "#include \"%s_args.h\"\n#include \"secGear/enclave_internal.h\"\n" ec.file_shortnm
    in
    let agent_id = "#ifndef TEE_SECE_AGENT_ID\n#define TEE_SECE_AGENT_ID 0x53656345\n#endif\n"
    in
    let trust_fproto_com = "/**** Trusted function prototypes. ****/\n" in
    let untrust_fproto_com = "/**** Untrusted function prototypes. ****/\n" in
    let untrust_func_proto = 
        List.map gen_func_proto (uf_list_to_fd_list ec.ufunc_decls)
    in
    let untrust_func = 
        String.concat ";\n\n" untrust_func_proto
    in
    let r_proxy_proto =
        List.map (fun f -> generate_rproxy_prototype f.tf_fdecl) ec.tfunc_decls
    in
    let r_proxy =
        String.concat ";\n\n" (List.flatten r_proxy_proto)
    in
    [
        hfile_start ^ hfile_include; 
        c_start;
        agent_id;
        trust_fproto_com ^ r_proxy ^ ";";
        if (List.length ec.ufunc_decls <> 0) then untrust_fproto_com ^ untrust_func ^ ";"
        else "/**** There is no untrusted function ****/";
        c_end; 
        hfile_end;
    ]
