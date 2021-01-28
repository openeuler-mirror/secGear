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

open Printf 
open Intel.Util
open Intel.Ast
open Commonfunc

let g_undir = ref "."

let g_dir = ref "."

let get_args_header (fs : string) (flags : int) = 
    if flags = 1 then !g_dir ^ Intel.Util.separator_str ^ fs ^ "_args.h"
    else !g_undir  ^ Intel.Util.separator_str ^ fs ^ "_args.h"

let get_trusted_header (fs : string) =
    !g_dir ^ Intel.Util.separator_str ^ fs ^ "_t.h"

let get_trusted_source (fs : string) =
    !g_dir ^ Intel.Util.separator_str ^ fs ^ "_t.c"

let get_untrusted_header (fs : string) =
    !g_undir ^ Intel.Util.separator_str ^ fs ^ "_u.h"

let get_untrusted_source (fs : string) =
    !g_undir ^ Intel.Util.separator_str ^ fs ^ "_u.c"

let create_args_header (ec : enclave_content) (flags : int) =
    let file_name = get_args_header ec.file_shortnm flags in
    let output = open_out file_name in
    output_string output (
            String.concat "\n" (Genheader.generate_args_header ec));
    close_out output

let create_trusted_header (ec : enclave_content) = 
    let file_name = get_trusted_header ec.file_shortnm in 
    let output = open_out file_name in 
    output_string output (
            String.concat "\n" (Genheader.generate_trusted_header ec));
    close_out output

let create_trusted_source (ec : enclave_content) = 
    let file_name = get_trusted_source ec.file_shortnm in
    let output = open_out file_name in
    output_string output (
            String.concat "\n" (Gentrust.gen_trusted ec));
    close_out output

let create_untrusted_header (ec : enclave_content) =
    let file_name = get_untrusted_header ec.file_shortnm in
    let output = open_out file_name in
    output_string output (
            String.concat "\n" (Genheader.generate_untrusted_header ec));
    close_out output

let create_untrusted_source (ec : enclave_content) =
    let file_name = get_untrusted_source ec.file_shortnm in
    let output = open_out file_name in
    output_string output (
            String.concat "\n" (Genuntrust.gen_untrusted ec));
    close_out output

let params_is_userchk (p, _) = params_is_usercheck p

let check_is_user_check (fd : func_decl) =
    List.exists params_is_userchk fd.plist 

let check_trust_funcs_method (tfs : trusted_func list) (ep : edger8r_params)= 
    if ep.use_prefix then failwithf "Trustzone mode is not support --use_perfix option";
    List.iter 
        (fun t -> 
            if t.tf_is_priv then
                failwithf "%s :Trustzone mode is not support 'private' feature" 
                    t.tf_fdecl.fname;
            if t.tf_is_switchless then
                failwithf "%s :Trustzone mode is not support 'switchless' feature"
                    t.tf_fdecl.fname;
            if check_is_user_check t.tf_fdecl then 
                failwithf "%s :Trustzone mode is not support 'user_check' feature"
                    t.tf_fdecl.fname)
            tfs

let check_untrust_funcs_method (ufs : untrusted_func list) = 
    List.iter
        (fun t ->
            if t.uf_fattr.fa_dllimport then 
                failwithf "%s:Trustzone mode is not support dllimport\n"
                t.uf_fdecl.fname;
            if t.uf_allow_list != [] then
                printf "WARNING: %s: Reentrant ocalls are not supported by Open Enclave. Allow list ignored.\n"
                t.uf_fdecl.fname;
            if check_is_user_check t.uf_fdecl=true then 
                failwithf "%s :Trustzone mode is not support 'user_check' feature\n"
                t.uf_fdecl.fname;
            if t.uf_fattr.fa_convention <> CC_NONE then
                let cconv_str = get_call_conv_str t.uf_fattr.fa_convention in
                printf "WARNING: %s: Trustzone mode is not support Calling convention %s for ocalls\n"
                t.uf_fdecl.fname cconv_str)
        ufs

(* Check duplicated structure definition and illegal usage.
 *)
let check_structure (ec: enclave_content) =
    let trusted_fds = List.map (fun (tf: trusted_func) -> tf.tf_fdecl) ec.tfunc_decls in
    let untrusted_fds = List.map (fun (uf: untrusted_func) -> uf.uf_fdecl) ec.ufunc_decls in
    List.iter(fun (st: composite_type) ->
        match st with
            StructDef s ->
                if is_structure_defined s.sname then
                    failwithf "duplicated structure definition `%s'" s.sname
                else
                    defined_structure := (s, Intel.CodeGen.is_structure_deep_copy s) :: !defined_structure;
            | _ -> ()
    )  ec.comp_defs;
    List.iter  (fun (fd: func_decl) ->
        List.iter (fun (pd: pdecl) ->
            let (pt, _)= pd in
                match pt with
                | PTVal (Struct(s))     ->
                    if is_structure_defined s then
                        let (struct_def, deep_copy) = get_struct_def s
                        in
                        if deep_copy then
                            failwithf "the structure declaration \"%s\" specifies a deep copy is expected. Referenced by value in function \"%s\" detected."s fd.fname
                        else
                            if List.exists (fun (pt, _) ->
                               match pt with
                               PTVal _        -> false
                             | PTPtr _        -> true       )  struct_def.smlist
                            then (eprintf "warning: the structure \"%s\" is referenced by value in function \"%s\". Part of the data may not be copied.\n"s fd.fname)
                            else ()
                    else ()
                | PTPtr (Ptr(Struct(s)), attr) ->
                    if is_structure_defined s then
                        let (_, deep_copy) = get_struct_def s
                        in
                        if deep_copy && attr.pa_direction = PtrOut then
                            failwithf "the structure declaration \"%s\" specifies a deep copy, should not be used with an `out' attribute in function \"%s\"."s fd.fname
                        else ()
                    else ()
                | a -> let (found, name) = Intel.CodeGen.is_foreign_a_structure a
                    in
                    if found then
                        let (_, deep_copy) = get_struct_def name
                        in
                        if deep_copy then
                            failwithf "`%s' in function `%s' is a structure and it specifies a deep copy. Use `struct %s' instead." name fd.fname name
                        else
                            (eprintf "warning: `%s' in function `%s' is a structure. Use `struct %s' instead.\n" name fd.fname name)
                    else ()
        ) fd.plist
    ) (trusted_fds @ untrusted_fds)

let generate_enclave_code (ec : enclave_content) (ep : edger8r_params) = 
    g_undir := ep.untrusted_dir;
    g_dir := ep.trusted_dir;
    let trust_funcs = ec.tfunc_decls in
    let untrust_funcs = ec.ufunc_decls in
    check_trust_funcs_method trust_funcs ep;
    check_untrust_funcs_method untrust_funcs;
    check_structure ec;
    if ep.gen_trusted then (
        create_args_header ec 1;
        create_trusted_header ec;
        if not ep.header_only then
            create_trusted_source ec 
    );
    if ep.gen_untrusted then (
        create_args_header ec 0;
        create_untrusted_header ec;
        if not ep.header_only then
            create_untrusted_source ec
    );
    printf "Success. \n"
