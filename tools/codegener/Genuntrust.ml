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
open Printf
open String
open Commonfunc

(* It is used to save the structures defined in EDLs. *)

let deep_copy_func 
(pre : parameter_type -> string)
(generator: parameter_type -> parameter_type -> declarator -> declarator -> string)
(post : string)
((pty, decl): (parameter_type * declarator)) =
    let ty = get_param_atype pty in
    match ty with 
        Ptr(Struct(struct_type)) -> 
            let (struct_def, _)= get_struct_def struct_type in
            let body =
                List.fold_left (
                    fun acc (mem_pty, mem_decl) ->
                        match mem_pty with
                          PTVal _ -> acc
                        | PTPtr (_, mem_attr) ->
                            if mem_attr.pa_size <> empty_ptr_size then
                                acc ^ (generator pty mem_pty decl mem_decl)
                            else acc
                    ) (pre pty)  struct_def.smlist in
                body ^ post
        | _ ->  ""

let get_param_count (pt: parameter_type) =
  match pt with
    | PTVal _      -> "1"
    | PTPtr (_, a) -> match a.pa_size.ps_count with 
                      | Some count -> attr_value_to_string count
                      | _ -> "1"

let set_call_user_func (fd : func_decl) = 
    [
        "/* Call the cc_enclave function */";
        "if (!enclave) {";
        "    ret = CC_ERROR_BAD_PARAMETERS;";
        "    goto exit;";
        "}";
        "if (pthread_rwlock_rdlock(&enclave->rwlock)) {";
        "    ret = CC_ERROR_BUSY;";
        "    goto exit;";
        "}";
        "if (!enclave->list_ops_node || !enclave->list_ops_node->ops_desc ||";
        "         !enclave->list_ops_node->ops_desc->ops ||";
        "         !enclave->list_ops_node->ops_desc->ops->cc_ecall_enclave) {";
        "    ret = CC_ERROR_BAD_PARAMETERS;";
        "    goto exit;";
        "}";
        "if ((ret = enclave->list_ops_node->ops_desc->ops->cc_ecall_enclave(";
        "         enclave,";
        sprintf "         fid_%s," fd.fname;
        "         in_buf,";
        "         in_buf_size,";
        "         out_buf,";
        "         out_buf_size,";
        "         &ms,";
        "         &ocall_table)) != CC_SUCCESS) {";
        "    pthread_rwlock_unlock(&enclave->rwlock);";
        "    goto exit; }";
        "if (pthread_rwlock_unlock(&enclave->rwlock)) {";
        "    ret = CC_ERROR_BUSY;";
        "    goto exit;";
        "}";
    ]

let set_ecall_func_arguments (fd : func_decl) =
    [
        sprintf "cc_enclave_result_t %s(\n    %s" fd.fname  (match fd.rtype with Void -> "cc_enclave_t *enclave" | _ -> "cc_enclave_t *enclave,\n    " ^ (get_tystr fd.rtype ^ "* retval"))
        ^ (if fd.plist <> [] then
            ",\n    " ^
            concat ",\n    "
            (List.map
                (fun (ptype, decl) ->
                    match ptype with
                    PTVal ty -> (sprintf "%s %s" (get_tystr ty) decl.identifier) 
                    | PTPtr (t, a) -> match (a.pa_rdonly, is_array decl) with
                                      | (true, false) -> sprintf "const %s %s" (get_tystr t) decl.identifier
                                      | (false, true) -> sprintf "%s %s%s" (get_tystr t) decl.identifier (set_array_dims_str decl.array_dims)
                                      | (_, _) -> sprintf "%s %s" (get_tystr t) decl.identifier)
            fd.plist)
        else "")
    ]
    
let set_ecall_func (tf : trusted_func) =
    let tfd = tf.tf_fdecl in 
    let init_point = set_init_pointer tfd in
    let arg_size = set_args_size tfd in
    [
        concat ",\n    " (set_ecall_func_arguments tfd) ^ ")";
        "{";
        "    cc_enclave_result_t ret = CC_FAIL;";
        "";
        "    /* Init buffer and size  */";
        "    size_t in_buf_size = 0;";
        "    size_t out_buf_size = 0;";
        "    uint8_t* in_buf = NULL;";
        "    uint8_t* out_buf = NULL;";
        "    uint32_t ms = TEE_SECE_AGENT_ID;";
        sprintf "    %s_size_t args_size;" tfd.fname;
        "";
        "    /* Init pointer */";
        if init_point <> ["";"";""] then 
            concat "\n" init_point
        else "    /* There is no pointer */";
        "";
        "    memset(&args_size, 0, sizeof(args_size));";
        "    /* Fill argments size */";
        if arg_size <> [""] then
            "    " ^ concat "\n    " (set_args_size tfd)
        else "/* There is no argments size */";
        "";
        sprintf "    in_buf_size += size_to_aligned_size(sizeof(%s_size_t));"
          tfd.fname;

        "    " ^ concat "\n    " (set_data_in tfd);
        "";

        "    " ^ concat "\n    " (set_data_out tfd);
        "";
        "    /* Allocate in_buf and out_buf */";
        "    in_buf = (uint8_t*)malloc(in_buf_size);";
        "    out_buf = (uint8_t*)malloc(out_buf_size);";
        "    if (in_buf == NULL || out_buf == NULL) {";
        "        ret = CC_ERROR_OUT_OF_MEMORY;";
        "        goto exit;";
        "    }";

        "";
        "    " ^ concat "\n    " (set_in_memcpy tfd);
        "";
        "    " ^ concat "\n    " (set_call_user_func tfd);
        "";
        "    " ^ concat "\n    " (set_out_memcpy tfd);
        "    ret = CC_SUCCESS;";
        "";

        "exit:";
        "    if (in_buf)";
        "        free(in_buf);";
        "    if (out_buf)";
        "        free(out_buf);";
        "";
        "    return ret;";
        "}";
    ]

let set_ocall_func (uf : untrusted_func) =
    let ufd = uf.uf_fdecl in
    let params_point = Commonfunc.set_parameters_point ufd in
    let out_params = Commonfunc.set_out_params ufd in
    [
        sprintf "cc_enclave_result_t ocall_%s (" ufd.fname;
        "    uint8_t* in_buf,";
        "    size_t in_buf_size,";
        "    uint8_t* out_buf,";
        "    size_t out_buf_size)";
        "{";
        "    cc_enclave_result_t result = CC_FAIL;";
        "    size_t in_buf_offset = 0;";
        "    size_t out_buf_offset = 0;";
        "    OE_UNUSED(in_buf_size);";
        "    OE_UNUSED(out_buf_size);";
        "";
        "    /* Prepare parameters point */";
        if not (params_point = ["";""]) then (
                "    " ^ concat "\n    " params_point)
        else
                "    /* There is no parameters point */";
        if uf.uf_propagate_errno then "    uint8_t *errno_p;"
        else "    /* There is not enable propagation */";
        "";
        sprintf "    %s_size_t *args_size = (%s_size_t *)in_buf;" ufd.fname ufd.fname;
        "    in_buf_offset += size_to_aligned_size(sizeof(*args_size));";
        "";
        "    " ^ concat "\n    " (Commonfunc.set_in_params ufd);
        "";
        "    /* Fill return val, out and in-out parameters */";
        if out_params <> ["";""] then
        "    " ^ concat "\n    " (Commonfunc.set_out_params ufd)
        else "    /* there is no return val, out and in-out parameters */";
        if uf.uf_propagate_errno then "    SET_PARAM_OUT(errno_p, int, errno_ocall, size_to_aligned_size(sizeof(int)));"
        else "    /* There is not enable propagation */";
        "";
        "    /* Call host function */";
        "    " ^ concat "    \n" (Commonfunc.set_call_user_func ufd);
        if uf.uf_propagate_errno then "     memcpy(errno_ocall, &errno, (sizeof(int)));"
        else "    /* There is not enable propagation */";
        "    /* Sucess */";
        "    result = CC_SUCCESS;";
        "    return result;";
        "}";
    ]


let gen_untrusted(ec : enclave_content) = 
    let trust_funcs = ec.tfunc_decls in
    let untrust_funcs = ec.ufunc_decls in
    let ecall_func = List.flatten (List.map set_ecall_func trust_funcs) in
    let ocall_func = List.flatten (List.map set_ocall_func untrust_funcs) in
    let ocall_table = 
    [
        "ocall_enclave_table_t ocall_table = {";
        sprintf "    %d," (List.length untrust_funcs);
        "    {";
        "        " ^concat "\n        " 
            (List.map (fun (uf) ->
                    sprintf "(cc_ocall_func_t)ocall_%s," uf.uf_fdecl.fname)
                untrust_funcs);
        "    },";
        "};"
    ]    in
    [
        "/*";
        " *  Auto generated by Codegener.";
        " *  Do not edit.";
        " */";
        sprintf "#include \"%s_u.h\"" ec.file_shortnm;
        "";
        "#include <stdlib.h>";
        "#include <string.h>";
        "#include <wchar.h>";
        "";
        if (List.length untrust_funcs <> 0) then concat "\n" ocall_func ^"\n"
        else "/* There is no ocall funcs */\n";
        concat "\n" ocall_table ^"\n";
        concat "\n" ecall_func;
    ]
