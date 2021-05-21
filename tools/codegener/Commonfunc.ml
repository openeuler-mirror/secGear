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

let defined_structure = ref []
let is_structure_defined s = List.exists (fun (( i, _ ): (struct_def * bool)) -> i.sname = s) !defined_structure
let get_struct_def s = List.find (fun (( i, _ ): (struct_def * bool)) -> i.sname = s) !defined_structure

let get_array_dims (il : int list) =
    concat "" (List.map
                (fun(n) ->
                    if n = -1 then "[]"
                else sprintf "[%d]" n)
                il)

let set_array_dims_str (ns : int list) =
    let set_dim_str n = if n = -1 then "[]" else sprintf "[%d]" n in
    concat "" (List.map set_dim_str ns)

let params_is_val = function PTVal _ -> true | PTPtr (_, _) -> false

let params_is_in = function PTVal _ -> true | PTPtr (_, t) -> t.pa_chkptr && t.pa_direction = PtrIn

let params_is_out = function PTVal _ -> false | PTPtr (_, t) -> t.pa_chkptr && t.pa_direction = PtrOut

let params_is_inout = function PTVal _ -> false | PTPtr (_, t) -> t.pa_chkptr && t.pa_direction = PtrInOut
let params_is__inout (p, _) = params_is_inout p

let params_is_usercheck = function PTVal _ -> false | PTPtr (_, t) -> t.pa_chkptr = false

let params_is_in_or_inout (p, _) = params_is_in p || params_is_inout p || params_is_usercheck p

let params_is_in_or_inout_or_val_or_usrchk (p, _) = params_is_in p || params_is_inout p || params_is_val p || params_is_usercheck p

let params_is_out_or_inout (p, _) = params_is_out p || params_is_inout p

let params_is_in_or_out_or_val_or_usrchk (p, _) = params_is_in p || params_is_out p || params_is_val p || params_is_usercheck p

let params_is_str = function PTVal _ -> false | PTPtr (_, t) -> t.pa_isstr

let params_is_sized_buf = function PTVal _ -> false | PTPtr (_, t) -> t.pa_size <> empty_ptr_size

let params_is_foreign_array = function PTVal _ -> false | PTPtr (t, a) -> ( match t with Foreign _ -> a.pa_isary | _ -> false) 

let is_array (declr: declarator) = declr.array_dims <> []

let get_ptrtystr = function Ptr ty -> get_tystr(ty) | _ -> ""

let rec mul xs = match xs with
    | [] -> 1
    | h :: t -> h * mul t

let attr_value_to_string2 (decl:declarator) (attr: attr_value) =
    match attr with
      ANumber n -> sprintf "%d" n
    | AString s -> sprintf "(%s + i)->%s" decl.identifier s

let get_sizestr =
    fun (p, decl) ->
        match p with
          PTVal ty -> sprintf "sizeof(%s)" (get_tystr ty)
        | PTPtr (t, a) -> match (a.pa_size.ps_size, a.pa_size.ps_count) with
                          (None, None) -> (match (a.pa_isstr, a.pa_iswstr, is_array decl, a.pa_chkptr) with
                                           | (true, false, false, true) -> sprintf "(%s) ? ((strlen(%s) + 1) * sizeof(char)) : 0" decl.identifier decl.identifier
                                           | (false, true, false, true) -> sprintf "(%s) ? wcslen(%s) : 0" decl.identifier decl.identifier
                                           | (false, false, true, true) -> sprintf "sizeof(%s) * %d" (get_tystr t) (mul decl.array_dims)
                                           | (false, false, false, true) -> sprintf "sizeof(%s)" (get_ptrtystr t)
                                           | (false, false, false, false) -> sprintf "sizeof(%s)" (get_tystr t)
                                           | (false, false, true, false) -> sprintf "sizeof(%s *)" (get_tystr t)
                                           | (_, _, _, _) -> "")
                          | (Some size, Some count) -> sprintf "%s * %s" (attr_value_to_string (size)) (attr_value_to_string(count))
                          | (Some size, None) -> sprintf "%s" (attr_value_to_string size)
                          | (None, Some count) -> sprintf "sizeof(%s) * %s" (get_ptrtystr t) (attr_value_to_string count)

let get_sizestr_2 =
    fun (p, decl) dec ->
        match p with
          PTVal ty -> sprintf "sizeof(%s)" (get_tystr ty)
        | PTPtr (t, a) -> match (a.pa_size.ps_size, a.pa_size.ps_count) with
                          (None, None) -> (match (a.pa_isstr, a.pa_iswstr, is_array decl, a.pa_chkptr) with
                                           | (true, false, false, true) -> sprintf "(%s) ? ((strlen(%s) + 1) * sizeof(char)) : 0" decl.identifier decl.identifier
                                           | (false, true, false, true) -> sprintf "(%s) ? wcslen(%s) : 0" decl.identifier decl.identifier
                                           | (false, false, true, true) -> sprintf "sizeof(%s) * %d" (get_tystr t) (mul decl.array_dims)
                                           | (false, false, false, true) -> sprintf "sizeof(%s)" (get_ptrtystr t)
                                           | (false, false, false, false) -> sprintf "sizeof(%s)" (get_tystr t)
                                           | (false, false, true, false) -> sprintf "sizeof(%s *)" (get_tystr t)
                                           | (_, _, _, _) -> "")
                          | (Some size, Some count) -> sprintf "%s * %s" (attr_value_to_string2 dec size) (attr_value_to_string2 dec count)
                          | (Some size, None) -> sprintf "(%s + i)->%s" dec.identifier (attr_value_to_string size)
                          | (None, Some count) -> sprintf "sizeof(%s) * %s" (get_ptrtystr t) (attr_value_to_string2 dec count)

let set_retval_pointer (fd : func_decl) =
    [
        (match fd.rtype with Void -> "" | _ -> "size_t retval_p;");
    ]

let is_deep_copy ((pty, _):(parameter_type * declarator)) =
    let ty = get_param_atype pty in
    match ty with
        Ptr(Struct(struct_type)) ->
            if is_structure_defined struct_type then
                let (_, deep_copy)= get_struct_def struct_type in
                if deep_copy then true
                else false
            else false
      | _ -> false

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
                                   | (true , true) -> 
                                   sprintf "SET_PARAM_IN_2(%s_in_p, %s, %s, args_size->%s_size);\n    if(args_size->%s_size == 0)\n        %s = NULL;" decl.identifier (get_tystr2 (get_param_atype ptype)) decl.identifier decl.identifier decl.identifier decl.identifier
                                   | (false, true) -> 
                                   sprintf "SET_PARAM_IN_2(%s_p, %s, %s, args_size->%s_size);\n    if(args_size->%s_size == 0)\n        %s = NULL;" decl.identifier (get_tystr2 (get_param_atype ptype)) decl.identifier decl.identifier decl.identifier decl.identifier
                                   | (_, false) -> 
                                   sprintf "SET_PARAM_IN_1(%s_p, %s, %s, args_size->%s_size);" decl.identifier (get_tystr2 (get_param_atype ptype)) decl.identifier decl.identifier ))
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

let set_call_user_func (fd : func_decl) =
    let pl = fd.plist in
    [
        (match fd.rtype with Void -> "" | _ -> "* retval = ") ^ fd.fname ^ "(";
        "    " ^ concat ",\n    "
                (List.map
                        (fun(ptype, decl) ->
                            match ptype with
                            | PTVal _ -> sprintf "    %s" decl.identifier
                            | PTPtr (t, a) ->
                                if is_array decl then
                                    sprintf "    *(%s(*)%s)%s" (get_tystr t) (get_array_dims decl.array_dims) decl.identifier
                                else if params_is_foreign_array ptype then
                                    sprintf "    *(%s*)%s" (get_tystr t) decl.identifier
                                else if a.pa_rdonly then
                                    sprintf "    (const %s)%s" (get_tystr t) decl.identifier
                                else if a.pa_chkptr=false then
                                    sprintf "    &%s" decl.identifier
                                else sprintf "    %s" decl.identifier)
                pl) ^ ");";
    ]

let set_args_size (fd : func_decl) =
    let deep_copy = List.filter is_deep_copy fd.plist in
    let argment_size = 
        (List.map
            (fun (ptype, decl) ->
                match ptype with
                | PTVal _ ->
                    sprintf "args_size.%s_size = size_to_aligned_size(sizeof(%s));" decl.identifier (get_tystr (get_param_atype ptype))
                | PTPtr _ ->
                    sprintf "if(%s)\n        args_size.%s_size = size_to_aligned_size(%s);" decl.identifier decl.identifier (get_sizestr (ptype, decl)))
            fd.plist) in
    let pre (pty : parameter_type) = sprintf "for (int i = 0; i < %s; i++) {\n        " (get_param_count pty)  in
    let post = "}\n    " in
    let generator (_ : parameter_type) (mem_pty : parameter_type) (decl : declarator) (mem_decl : declarator) =
        sprintf "if(%s)\n        args_size.%s_%s_size += size_to_aligned_size(%s);\n        " decl.identifier decl.identifier mem_decl.identifier (get_sizestr_2 (mem_pty, mem_decl) decl) in
    [
        (match fd.rtype with Void -> "" | _ -> sprintf "args_size.retval_size = size_to_aligned_size(sizeof(%s));" (get_tystr fd.rtype));
        concat "\n    "  argment_size;
        concat "\n    "
            (List.map (deep_copy_func pre generator post) deep_copy);
    ]

let set_in_out_val_parameters_pointer (fd : func_decl) =
    let params = List.filter params_is_in_or_out_or_val_or_usrchk fd.plist in
    let deep_copy = List.filter is_deep_copy params in 
    let deep_copy_all = List.filter is_deep_copy fd.plist in 
    let pre (_: parameter_type) = "" in
    let post = "" in
    let generator (pty: parameter_type) (_ : parameter_type) (decl : declarator) (mem_decl : declarator) =
            ((sprintf "size_t %s_p;\n    size_t _%s_index = 0;\n    void** _%s = malloc(sizeof(void*) * (%s));\n    if(_%s == NULL)\n        return ret;\n    " mem_decl.identifier mem_decl.identifier mem_decl.identifier (get_param_count pty) mem_decl.identifier) ^
            (sprintf "for (int i = 0; i < %s; i++) {\n        if(%s)\n            _%s[_%s_index++]= (void *)(%s + i)->%s;\n    } " (get_param_count pty) decl.identifier mem_decl.identifier mem_decl.identifier decl.identifier mem_decl.identifier)) in
    [
       (* (match fd.rtype with Void -> "" | _ -> "uint8_t *retval_p;"); *)
        concat "\n    "
            (List.map  
                (fun (_, decl) ->
                    sprintf "size_t %s_p;" decl.identifier)
            params);
        concat "\n    "
            (List.map (deep_copy_func pre generator post) deep_copy);
        if deep_copy_all <> [] then 
            "size_t tmp_size = 0;"
        else "";
    ]

let set_inout_parameters_pointer (fd : func_decl) =
    let params = List.filter params_is__inout fd.plist in
    let deep_copy = List.filter is_deep_copy params in
    let pre (_ : parameter_type) = "" in
    let post = "" in
    let generator (pty : parameter_type) (_ : parameter_type) (decl : declarator) (mem_decl : declarator) =
        ((sprintf "size_t %s_in_p;\n    size_t %s_out_p;\n    size_t _%s_index = 0;\n    void** _%s = malloc(sizeof(void*) * (%s));\n    if(_%s == NULL)\n        return ret;\n    " mem_decl.identifier mem_decl.identifier mem_decl.identifier mem_decl.identifier (get_param_count pty) mem_decl.identifier) ^
        (sprintf "for (int i = 0; i < %s; i++) {\n        if(%s)\n            _%s[_%s_index++]= (void *)(%s + i)->%s;\n    } " (get_param_count pty) decl.identifier mem_decl.identifier mem_decl.identifier decl.identifier mem_decl.identifier)) in
    [
       (* (match fd.rtype with Void -> "" | _ -> "uint8_t *retval_p;"); *)
        concat "\n    "
            (List.map  
                (fun (_, decl) ->
                        sprintf "size_t %s_in_p;" decl.identifier ^ sprintf "\n    size_t %s_out_p;" decl.identifier)
            params); 
        concat "\n    "
            (List.map (deep_copy_func pre generator post) deep_copy);
    ]

let set_init_pointer (fd : func_decl) =
    let retval_point = set_retval_pointer fd in
    let in_out_val_point = set_in_out_val_parameters_pointer fd in
    let inout_point = set_inout_parameters_pointer fd in
    [
        if retval_point <> [""] then 
            "    " ^ concat "\n    " retval_point
        else "";
        if in_out_val_point <> [""] then
            "    " ^ concat "\n    " in_out_val_point
        else "";
        if inout_point <> ["";""] then
            "    " ^ concat "\n    " inout_point
        else "";
    ]

let set_data_in (fd : func_decl) = 
    let params = List.filter params_is_in_or_inout_or_val_or_usrchk fd.plist in
    let deep_copy = List.filter is_deep_copy fd.plist in
    let data_in = 
        (List.map
            (fun (ptype, decl) ->
                match ptype with
                PTPtr _ -> 
                    (if params_is_inout ptype then
                        sprintf "if (%s)\n        SIZE_ADD_POINT_IN(%s_in_p, args_size.%s_size);" decl.identifier decl.identifier decl.identifier
                    else
                        sprintf "if (%s)\n        SIZE_ADD_POINT_IN(%s_p, args_size.%s_size);" decl.identifier decl.identifier decl.identifier)
                | PTVal _ -> sprintf "SIZE_ADD_POINT_IN(%s_p, args_size.%s_size);" decl.identifier decl.identifier)
        params) in 
    let pre (_ : parameter_type) = "" in
    let post = "" in
    let generator (pty : parameter_type) (_ : parameter_type) (decl : declarator) (mem_decl : declarator) =
        if params_is_inout pty then 
            sprintf "SIZE_ADD_POINT_IN(%s_in_p, args_size.%s_%s_size);\n    " mem_decl.identifier decl.identifier mem_decl.identifier
        else
            sprintf "SIZE_ADD_POINT_IN(%s_p, args_size.%s_%s_size);\n    " mem_decl.identifier decl.identifier mem_decl.identifier in
    [
        "/* Fill data in */";
        if data_in <> [] then
            concat "\n    " data_in ^ "\n    " ^ concat "\n    " (List.map (deep_copy_func pre generator post) deep_copy)
        else "/* There is no data in */";
    ]

let set_data_out (fd : func_decl) = 
    let params = List.filter params_is_out_or_inout fd.plist in
    let deep_copy = List.filter is_deep_copy params in
    let data_out =
        [
        (match fd.rtype with Void -> "" | _ -> sprintf "SIZE_ADD_POINT_OUT(retval_p, size_to_aligned_size(sizeof(%s)));" (get_tystr fd.rtype));
            concat "\n    "
                (List.map
                    (fun (ptype, decl) ->
                        match ptype with
                        | PTVal _ ->
                            sprintf "SIZE_ADD_POINT_OUT(%s_p, args_size.%s_size);" decl.identifier decl.identifier
                        | PTPtr _ -> if params_is_inout ptype then
                                       sprintf "if (%s)\n        SIZE_ADD_POINT_OUT(%s_out_p, args_size.%s_size);" decl.identifier decl.identifier decl.identifier
                                      else
                                         sprintf "if (%s)\n        SIZE_ADD_POINT_OUT(%s_p, args_size.%s_size);" decl.identifier decl.identifier decl.identifier)
                 params) 
        ] in
    let pre (_ : parameter_type) = "" in
    let post = "" in
    let generator (pty : parameter_type) (_ : parameter_type) (decl : declarator) (mem_decl : declarator) =
        if params_is_inout pty then
            sprintf "SIZE_ADD_POINT_OUT(%s_out_p, args_size.%s_%s_size);\n    "  mem_decl.identifier decl.identifier mem_decl.identifier
        else
            sprintf "SIZE_ADD_POINT_OUT(%s_p, args_size.%s_%s_size);\n    " mem_decl.identifier decl.identifier mem_decl.identifier in
    [
        "/* Fill data out */";
        if data_out <> ["";""] then 
            concat "\n    " data_out ^ "\n    " ^concat "\n    "
            (List.map (deep_copy_func pre generator post) deep_copy)
        else "/* There is no data out */";
    ]

let set_in_memcpy (fd : func_decl) = 
    let params = List.filter params_is_in_or_inout_or_val_or_usrchk fd.plist in
    let deep_copy = List.filter is_deep_copy params in
    let in_memcpy = 
        (List.map
            (fun (ptype, decl) ->
                match ptype with
                | PTVal _ ->
                    sprintf "memcpy(in_buf + %s_p, (uint8_t *)&%s, sizeof(%s));" decl.identifier decl.identifier (get_tystr (get_param_atype ptype))
                | PTPtr (_, a) -> (match (params_is_inout ptype, a.pa_chkptr) with
                                   | (true, true) -> sprintf "if(%s)\n        memcpy(in_buf + %s_in_p, (uint8_t *)%s, %s);" decl.identifier decl.identifier decl.identifier (get_sizestr (ptype, decl))
                                   | (false, true) -> sprintf "if(%s)\n        memcpy(in_buf + %s_p, (uint8_t *)%s, %s);" decl.identifier decl.identifier decl.identifier (get_sizestr (ptype, decl))
                                   | (true, false) -> sprintf "memcpy(in_buf + %s_in_p, (uint8_t *)&%s, %s);" decl.identifier decl.identifier (get_sizestr (ptype, decl))
                                   | (false, false) -> sprintf "memcpy(in_buf + %s_p, (uint8_t *)&%s, %s);" decl.identifier decl.identifier (get_sizestr (ptype, decl))))
        params) in
    let pre(_ :parameter_type)  = ""in
    let post = "" in
    let generator (pty : parameter_type) (mem_pty : parameter_type) (decl : declarator) (mem_decl : declarator) =
        if params_is_inout pty then
            sprintf "for (int i = 0; i < %s; i++) {\n        if((%s + i)->%s) {\n            memcpy(in_buf + %s_in_p + tmp_size, (uint8_t *)(%s + i)->%s, %s);\n            tmp_size += size_to_aligned_size(%s);\n        }\n    }\n    tmp_size = 0;\n    " (get_param_count pty) decl.identifier mem_decl.identifier mem_decl.identifier decl.identifier mem_decl.identifier (get_sizestr_2 (mem_pty, mem_decl) decl) (get_sizestr_2 (mem_pty, mem_decl) decl)
        else
            sprintf "for (int i = 0; i < %s; i++) {\n        if((%s + i)->%s) {\n            memcpy(in_buf + %s_p + tmp_size, (uint8_t *)(%s + i)->%s, %s);\n        tmp_size += size_to_aligned_size(%s);\n        }\n    }\n    tmp_size = 0;\n    " (get_param_count pty) decl.identifier mem_decl.identifier mem_decl.identifier decl.identifier mem_decl.identifier (get_sizestr_2 (mem_pty, mem_decl) decl) (get_sizestr_2 (mem_pty, mem_decl) decl) in
    [
        "/* Copy in_params to in_buf*/";
        sprintf "memcpy(in_buf, &args_size, sizeof(%s_size_t));" fd.fname;
        if in_memcpy <> [] then
        concat "\n    " in_memcpy ^ "\n    " ^ 
        concat "\n    "
            (List.map (deep_copy_func pre generator post) deep_copy)
        else "/* There is no other in_params to in_buf */";
    ]

let set_out_memcpy (fd : func_decl) = 
    let params = List.filter params_is_out_or_inout fd.plist in
    let deep_copy = List.filter is_deep_copy fd.plist in
    let out_retval = match fd.rtype with Void -> ""
                     | _ -> sprintf "memcpy(retval, out_buf + retval_p, sizeof(%s));"  (get_tystr fd.rtype) in
    let out_memcpy = 
        (List.map
            (fun (ptype, decl) ->
                match ptype with
                | PTVal _ -> ""
                | PTPtr _ -> if params_is_inout ptype then
                    sprintf "if(%s)\n        memcpy((uint8_t *)%s, out_buf + %s_out_p, %s);" decl.identifier  decl.identifier decl.identifier (get_sizestr (ptype, decl))
                else
                    sprintf "if(%s)\n        memcpy((uint8_t *)%s, out_buf + %s_p, %s);" decl.identifier decl.identifier decl.identifier (get_sizestr (ptype, decl)))
        params) in
    let pre (_ : parameter_type) = "" in
    let post = "" in
    let generator (pty : parameter_type) (mem_pty : parameter_type) (decl : declarator) (mem_decl : declarator) =
        match mem_pty with 
        PTPtr (_, _) ->
        if params_is_inout pty then
            ((sprintf "_%s_index = 0;\n    for (int i = 0; i < %s; i++) {\n        if(%s) {\n            (%s + i)->%s = (%s)_%s[_%s_index++];\n        }\n    }\n    " mem_decl.identifier (get_param_count pty) decl.identifier decl.identifier mem_decl.identifier (get_tystr (get_param_atype mem_pty)) mem_decl.identifier mem_decl.identifier) ^
            (sprintf "for (int i = 0; i < %s; i++) {\n        if((%s + i)->%s) {\n            memcpy((uint8_t *)((%s + i)->%s), out_buf + %s_out_p + tmp_size, %s);\n            tmp_size += size_to_aligned_size(%s);\n        }\n    }\n    tmp_size = 0;\n    "(get_param_count pty) decl.identifier mem_decl.identifier decl.identifier  mem_decl.identifier  mem_decl.identifier (get_sizestr_2 (mem_pty, mem_decl) decl) (get_sizestr_2 (mem_pty, mem_decl) decl)))
        else
            ((sprintf "_%s_index = 0;\n    for (int i = 0; i < %s; i++) {\n        if(%s) {\n            (%s + i)->%s = (%s)_%s[_%s_index++];\n        }\n    }\n    " mem_decl.identifier (get_param_count pty) decl.identifier decl.identifier mem_decl.identifier (get_tystr (get_param_atype mem_pty))mem_decl.identifier mem_decl.identifier) ^
            (sprintf "for (int i = 0; i < %s; i++) {\n        if((%s + i)->%s) {\n            memcpy((uint8_t *)((%s + i)->%s), out_buf + %s_p + tmp_size, %s);\n            tmp_size += size_to_aligned_size(%s);\n        }\n    }\n    tmp_size = 0;\n    "(get_param_count pty) decl.identifier mem_decl.identifier decl.identifier mem_decl.identifier mem_decl.identifier  (get_sizestr_2 (mem_pty, mem_decl) decl) (get_sizestr_2 (mem_pty, mem_decl) decl)))
        | _ -> ""  in
    [
        "/* Copy out_buf to out_params */";
        if out_memcpy <> [] || out_retval <> ""then
        out_retval ^ "\n    " ^ concat "\n    " out_memcpy ^ "\n    " ^
        concat "\n    "
            (List.map (deep_copy_func pre generator post) deep_copy)
        else "/* There is no out_buf to out_params */"
    ]

