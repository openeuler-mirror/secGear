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

let set_array_dims (ns : int list) = 
    let set_dim n = if n = -1 then "[]" else sprintf "[%d]" n in 
    concat "" (List.map set_dim ns)

let set_parameters_point (fd : func_decl) =
    let params = List.filter params_is_in_or_out_or_val_or_usrchk fd.plist in
    let deep_copy_in = List.filter is_deep_copy params in
    let params_inout = List.filter params_is__inout fd.plist in
    let deep_copy_inout = List.filter is_deep_copy params_inout in
    let pre (_: parameter_type) = "" in
    let post = "" in
    let generator_in (_ : parameter_type) (_ : parameter_type) (decl : declarator) (mem_decl : declarator) =
        sprintf "uint8_t *%s_%s_p;\n    " decl.identifier mem_decl.identifier in
    let generator_inout (_ : parameter_type) (_ : parameter_type) (decl : declarator) (mem_decl : declarator) =
        (sprintf "uint8_t *%s_%s_in_p;\n    " decl.identifier mem_decl.identifier) ^ (sprintf "uint8_t *%s_%s_out_p;\n    " decl.identifier mem_decl.identifier) in
    [
        (match fd.rtype with Void -> "" | _ -> "uint8_t *retval_p;");
        concat "\n    "
            (List.map
                (fun (_, decl) ->
                        sprintf "uint8_t *%s_p;" decl.identifier)
            params);
        concat "\n    "
            (List.map (deep_copy_func pre generator_in post) deep_copy_in);
        concat "\n    "
            (List.map
                (fun (_, decl) ->
                        sprintf "uint8_t *%s_out_p;\n    " decl.identifier ^
                        sprintf "uint8_t *%s_in_p;" decl.identifier)
            params_inout);
        concat "\n    "
            (List.map (deep_copy_func pre generator_inout post) deep_copy_inout);
        if deep_copy_inout <> [] then 
            "uint8_t tmp_size = 0;"
        else "";
    ]

let params_is_val = function PTVal _ -> true | PTPtr (_, _) -> false

let params_is_in = function PTVal _ -> true | PTPtr (_, t) -> t.pa_chkptr && t.pa_direction = PtrIn

let params_is_out = function PTVal _ -> false | PTPtr (_, t) -> t.pa_chkptr && t.pa_direction = PtrOut

let params_is_inout = function PTVal _ -> false | PTPtr (_, t) -> t.pa_chkptr && t.pa_direction = PtrInOut
    
let params_is_usercheck = function PTVal _ -> false | PTPtr (_, t) -> t.pa_chkptr = false

let params_is_in_or_inout (p, _) = params_is_in p || params_is_inout p || params_is_usercheck p

let params_is_out_or_inout (p, _) = params_is_out p || params_is_inout p

let params_is_foreign_array = function PTVal _ -> false | PTPtr (t, a) -> ( match t with Foreign _ -> a.pa_isary | _ -> false) 

let set_in_params (fd : func_decl) = 
    let params = List.filter params_is_in_or_inout fd.plist in
    let deep_copy = List.filter is_deep_copy params in
    let in_params = 
        (List.map
            (fun (ptype, decl) ->
                match ptype with
                | PTVal _ ->
                    sprintf "SET_PARAM_IN_1(%s_p, %s, %s, args_size->%s_size);" decl.identifier (get_tystr (get_param_atype ptype)) decl.identifier decl.identifier 
                | PTPtr (_, a) -> (match (params_is_inout ptype, a.pa_chkptr) with 
                                   | (true , true) -> sprintf "SET_PARAM_IN_2(%s_in_p, %s, %s, args_size->%s_size);\n    if(args_size->%s_size == 0)\n        %s = NULL;" decl.identifier (get_tystr2 (get_param_atype ptype)) decl.identifier decl.identifier decl.identifier decl.identifier
                                   | (false, true) -> sprintf "SET_PARAM_IN_2(%s_p, %s, %s, args_size->%s_size);\n    if(args_size->%s_size == 0)\n        %s = NULL;" decl.identifier (get_tystr2 (get_param_atype ptype)) decl.identifier decl.identifier decl.identifier decl.identifier
                                   | (_, false) -> sprintf "SET_PARAM_IN_1(%s_p, %s, %s, args_size->%s_size);\n    if(args_size->%s_size == 0)\n        %s = NULL;" decl.identifier (get_tystr2 (get_param_atype ptype)) decl.identifier decl.identifier decl.identifier decl.identifier))
        params) in
    let pre (_: parameter_type) = "" in
    let post = "" in
    let generator (pty : parameter_type) (mem_pty : parameter_type) (decl : declarator) (mem_decl : declarator) =
        if params_is_inout pty then
            (sprintf "%s_%s_in_p = in_buf + in_buf_offset;\n    for (int i = 0; i < %s; i++) {\n        " decl.identifier mem_decl.identifier (get_param_count pty)) ^ 
            (sprintf "(%s + i)->%s = (%s *)(in_buf + in_buf_offset);\n        in_buf_offset += size_to_aligned_size(%s);\n    }\n    " decl.identifier mem_decl.identifier (get_tystr2 (get_param_atype mem_pty)) (get_sizestr_2 (mem_pty, mem_decl) decl)) 
        else
            (sprintf "%s_%s_p = in_buf + in_buf_offset;\n    for (int i = 0; i < %s; i++) {\n        " decl.identifier mem_decl.identifier (get_param_count pty)) ^
            (sprintf "(%s + i)->%s = (%s *)(in_buf + in_buf_offset);\n        in_buf_offset += size_to_aligned_size(%s);\n    }\n    " decl.identifier mem_decl.identifier (get_tystr2 (get_param_atype mem_pty)) (get_sizestr_2 (mem_pty, mem_decl) decl)) in
    [
        "/* Fill in and in-out parameters */";
        if in_params <> [] then
            concat "\n    " in_params ^ "\n    " ^
        concat "\n    "
            (List.map (deep_copy_func pre generator post) deep_copy)
        else "/* there is no in and in-out parameters */";
    ]

let set_out_params (fd : func_decl) = 
    let params = List.filter params_is_out_or_inout fd.plist in
    let deep_copy = List.filter is_deep_copy params in
    let out_params = 
        (List.map
            (fun (p, decl) -> if params_is_out p then
                sprintf "SET_PARAM_OUT(%s_p, %s, %s, args_size->%s_size);\n    if(args_size->%s_size == 0)\n        %s = NULL;" decl.identifier (get_tystr2 (get_param_atype p)) decl.identifier decl.identifier decl.identifier decl.identifier
            else
                sprintf "SET_PARAM_OUT_2(%s_out_p, %s, %s, args_size->%s_size);\n    if(args_size->%s_size == 0)\n        %s = NULL;" decl.identifier (get_tystr2 (get_param_atype p)) decl.identifier decl.identifier decl.identifier decl.identifier)
        params) in
    let pre (_: parameter_type) = "" in
    let post = "" in
    let generator (pty : parameter_type) (mem_pty : parameter_type) (decl : declarator) (mem_decl : declarator) =
        (sprintf "%s_%s_out_p = out_buf + out_buf_offset;\n    for (int i = 0; i < %s; i++) {\n        " decl.identifier mem_decl.identifier (get_param_count pty)) ^
        (sprintf "(%s + i)->%s = (%s *)(out_buf + out_buf_offset);\n        out_buf_offset += size_to_aligned_size(%s);\n        " decl.identifier mem_decl.identifier (get_tystr2 (get_param_atype mem_pty)) (get_sizestr_2 (mem_pty, mem_decl) decl)) ^
        (sprintf "memcpy((%s + i)->%s, %s_%s_in_p + tmp_size, %s);\n        " decl.identifier mem_decl.identifier decl.identifier mem_decl.identifier (get_sizestr_2 (mem_pty, mem_decl) decl)) ^
        (sprintf "tmp_size = size_to_aligned_size(%s);\n    }\n    tmp_size = 0;\n    " (get_sizestr_2 (mem_pty, mem_decl) decl)) in
    [
        (match fd.rtype with Void -> "" | _ -> sprintf "SET_PARAM_OUT(retval_p, %s, retval, args_size->retval_size);" (get_tystr fd.rtype));
        if out_params <> [] then 
            concat ";\n    " out_params ^ "\n    " ^
        concat "\n    "
            (List.map (deep_copy_func pre generator post) deep_copy)
        else "";
    ]

let get_array_dims (il : int list) = 
    concat "" 
    (List.map 
        (fun(n) -> 
            if n = -1 then "[]" 
            else sprintf "[%d]" n)
    il)

let set_ecall_func (tf : trusted_func) =
    let tfd = tf.tf_fdecl in 
    let params_point = set_parameters_point tfd in
    let out_params = set_out_params tfd in
    [
        sprintf "cc_enclave_result_t ecall_%s (" tfd.fname;
        "    uint8_t* in_buf,";
        "    size_t in_buf_size,";
        "    uint8_t* out_buf,";
        "    size_t out_buf_size,";
        "    size_t* output_bytes_written)";
        "{";
        "    cc_enclave_result_t result = CC_FAIL;";
        "    size_t in_buf_offset = 0;";
        "    size_t out_buf_offset = 0;";
        "";
        "    /* Prepare parameters point */";
        if not (params_point = ["";""]) then (
                "    " ^ concat "\n    " params_point) 
        else    
                "    /* There is no parameters point */"; 
        "";
        sprintf "    %s_size_t *args_size = (%s_size_t *)in_buf;" tfd.fname tfd.fname;
        "    in_buf_offset += size_to_aligned_size(sizeof(*args_size));";
        "";
        "    " ^ concat "\n    " (set_in_params tfd);
        "";
        "    /* Fill return val, out and in-out parameters */";
        if out_params <> ["";""] then 
        "    " ^ concat "\n    " (set_out_params tfd)
        else "    /* there is no return val, out and in-out parameters */";
        "";
        "    /* Check if the input and output buffers can be visited */";
        "    if (!in_buf || !cc_is_within_enclave(in_buf, in_buf_size))";
        "        goto done;";
        "";
        "    if (out_buf && !cc_is_within_enclave(out_buf, out_buf_size))";
        "        goto done;";
        "";
        "    /* Call host function */";
        "    " ^ concat "    \n" (Commonfunc.set_call_user_func tfd);
        "    /* Sucess */";
        "    result = CC_SUCCESS;";
        "    *output_bytes_written = out_buf_offset;";
        "done:";
        "    return result;";
        "}";
    ]

let set_ocall_func_arguments (fd : func_decl) =
    [
        sprintf "cc_enclave_result_t %s(\n    %s" fd.fname  (match fd.rtype with Void -> "" | _ -> (get_tystr fd.rtype ^ "* retval"))
        ^ (if fd.plist <> [] then
           (match fd.rtype with Void -> 
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
                              | _ ->
            ",\n     " ^ concat ",\n    "
            (List.map
                (fun (ptype, decl) ->
                    match ptype with
                    PTVal ty -> (sprintf "%s %s" (get_tystr ty) decl.identifier)
                    | PTPtr (t, a) -> match (a.pa_rdonly, is_array decl) with
                                      | (true, false) -> sprintf "const %s %s" (get_tystr t) decl.identifier
                                      | (false, true) -> sprintf "%s %s%s" (get_tystr t) decl.identifier (set_array_dims_str decl.array_dims)
                                      | (_, _) -> sprintf "%s %s" (get_tystr t) decl.identifier)
            fd.plist))
        else "")
    ]


let set_call_user_func (fd : func_decl) = 
    [
        "/* Call the cc_enclave function */";
        "if ((ret = cc_ocall_enclave(";
        sprintf "         fid_%s," fd.fname;
        "         in_buf,";
        "         in_buf_size,";
        "         out_buf,";
        "         out_buf_size)) != CC_SUCCESS)";
        "    goto exit;";
    ]

let set_ocall_func (uf : untrusted_func) =
    let ufd = uf.uf_fdecl in
    let init_point = set_init_pointer ufd in
    let arg_size = set_args_size ufd in
    [
        concat ",\n    " (set_ocall_func_arguments ufd) ^ ")";
        "{";
        "    cc_enclave_result_t ret = CC_FAIL;";
        "";
        "    /* Init buffer and size  */";
        "    size_t in_buf_size = 0;";
        "    size_t out_buf_size = 0;";
        "    uint8_t* in_buf = NULL;";
        "    uint8_t* out_buf = NULL;";
        sprintf "    %s_size_t args_size;" ufd.fname;
        "";
        "    /* Init pointer */";
        if init_point <> ["";"";""] then
            concat "\n" init_point
        else "    /* There is no pointer */";
        "";
        if uf.uf_propagate_errno then "    size_t errno_p;"
        else "    /* There is not enable propagation */";
        "";
        "    memset(&args_size, 0, sizeof(args_size));";
        "    /* Fill argments size */";
        if arg_size <> [""] then
            "    " ^ concat "\n    " (set_args_size ufd)
        else "/* There is no argments size */";
        "";
        sprintf "    in_buf_size += size_to_aligned_size(sizeof(%s_size_t));"
          ufd.fname;

        "    " ^ concat "\n    " (set_data_in ufd);
        "";

        "    " ^ concat "\n    " (set_data_out ufd);
        if uf.uf_propagate_errno then "    SIZE_ADD_POINT_OUT(errno_p, size_to_aligned_size(sizeof(int)));"
        else "    /* There is not enable propagation */";
        "";
        "    /* Allocate in_buf and out_buf */";
        "    in_buf = (uint8_t*)malloc(in_buf_size);";
        "    out_buf = (uint8_t*)malloc(out_buf_size);";
        "    if (in_buf == NULL || (out_buf_size != 0 && out_buf == NULL)) {";
        "        ret = CC_ERROR_OUT_OF_MEMORY;";
        "        goto exit;";
        "    }";

        "";
        "    " ^ concat "\n    " (set_in_memcpy ufd);
        "";
        "    " ^ concat "\n    " (set_call_user_func ufd);
        "";
        "    " ^ concat "\n    " (set_out_memcpy ufd);
        if uf.uf_propagate_errno then "     memcpy((uint8_t *)&errno, out_buf + errno_p, sizeof(int));"
        else "    /* There is not enable propagation */";
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

let g_caller_ca_owner =
    [
        "void set_caller_ca_owner()";
        "{";
        "#ifdef WHITE_LIST_OWNER";
        "\tchar *white_list_owner = WHITE_LIST_OWNER;";
        "#else";
        "\tchar *white_list_owner = \"root\";";
        "#endif";
        "\t";
        "#ifdef WHITE_LIST_0";
        "\taddcaller_ca_exec(WHITE_LIST_0, white_list_owner);";
        "#endif";
        "\t";
        "#ifdef WHITE_LIST_1";
        "\taddcaller_ca_exec(WHITE_LIST_1, white_list_owner);";
        "#endif";
        "\t";
        "#ifdef WHITE_LIST_2";
        "\taddcaller_ca_exec(WHITE_LIST_2, white_list_owner);";
        "#endif";
        "\t";
        "#ifdef WHITE_LIST_3";
        "\taddcaller_ca_exec(WHITE_LIST_3, white_list_owner);";
        "#endif";
        "\t";
        "#ifdef WHITE_LIST_4";
        "\taddcaller_ca_exec(WHITE_LIST_4, white_list_owner);";
        "#endif";
        "\t";
        "#ifdef WHITE_LIST_5";
        "\taddcaller_ca_exec(WHITE_LIST_5, white_list_owner);";
        "#endif";
        "\t";
        "#ifdef WHITE_LIST_6";
        "\taddcaller_ca_exec(WHITE_LIST_6, white_list_owner);";
        "#endif";
        "\t";
        "#ifdef WHITE_LIST_7";
        "\taddcaller_ca_exec(WHITE_LIST_7, white_list_owner);";
        "#endif";
        "\t";
        "#ifdef WHITE_LIST_8";
        "\taddcaller_ca_exec(WHITE_LIST_8, white_list_owner);";
        "#endif";
        "\t";
        "#ifndef WHITE_LIST_0";
        "\taddcaller_ca_exec(\"/vendor/bin/teec_hello\", white_list_owner);";
        "#endif";
        "}";
    ]

let gen_trusted(ec : enclave_content) = 
    let trust_funcs = ec.tfunc_decls in
    let untrust_funcs = ec.ufunc_decls in
    let ecall_func = List.flatten (List.map set_ecall_func trust_funcs) in
    let ocall_func = List.flatten (List.map set_ocall_func untrust_funcs) in
    let ecall_table = 
        [
            "cc_ecall_func_t cc_ecall_tables[] = {";
            "        "^ concat ",\n    " 
                (List.map (fun (tf) ->
                    sprintf "(cc_ecall_func_t) ecall_%s" tf.tf_fdecl.fname)
                trust_funcs);
            "};";
            "";
            "size_t ecall_table_size = COUNT(cc_ecall_tables);";
        ]
    in
    [
        "";
        sprintf "#include \"%s_t.h\"" ec.file_shortnm;
        "";
        "#include <stdio.h>";
        "#include <string.h>";
        "";
        " /* ECALL FUNCTIONs */";
        concat "\n" ecall_func;
        "";
        "/* set_caller_ca_owner*/";
        concat "\n" g_caller_ca_owner;
        "";
        " /* OCALL FUNCTIONs */";
        if (List.length untrust_funcs <> 0 ) then concat "\n" ocall_func ^"\n"
        else "/* There is no ocall functions */\n";
        concat "\n" ecall_table;
        "";
    ]
