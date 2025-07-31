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

(*open Emitter*)
open Codegener 

let _ =
    Printf.printf "Generate code for secGear SDK.\n";
    Intel.Plugin.instance.available <- true;
    Intel.Plugin.instance.gen_edge_routines <- generate_enclave_code

let main = 
    let progname = Sys.argv.(0) in
    let argc = Array.length Sys.argv in
    let args = if argc = 1 then [||] else Array.sub Sys.argv 1 (argc-1) in
    let cmd_params = Intel.Util.parse_cmdline progname (Array.to_list args) in

    let real_ast_handler fname =
        try
            Intel.CodeGen.gen_enclave_code (Intel.CodeGen.start_parsing fname) cmd_params
        with
            Failure s -> (Printf.eprintf "error: %s\n" s; exit (-1))
    in
    if cmd_params.input_files = [] then Intel.Util.usage progname
    else List.iter real_ast_handler cmd_params.input_files

