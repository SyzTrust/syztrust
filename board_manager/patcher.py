import sys
import json
import configparser
c = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
c.read(r'config.ini') 
config = c['DEFAULT']
target_TEE = config.get('target_TEE')
config = c[target_TEE]
config_path = config.get('config_path')
raw_trace_rootdir = config.get('raw_trace_rootdir')
payload_root_dir = config.get('payload_root_dir')
generated_payload_root_dir = config.get('generated_payload_root_dir')
execution_file_root_dir = config.get('execution_file_root_dir')
payload_log_file_root_dir = config.get('payload_log_file_root_dir')
command_python = config.get('command_python')
temp_result_file = config.get('temp_result_file')
execution_file = config.get('execution_file')
corpus_file = config.get('corpus_file')
trace_input = config.get('trace_input')
trace_output = config.get('trace_output')
trace_id = config.get('trace_id')
pickle_filepath = config.get('pickle_file')
funcs = [    "__NR_tee_obj_alloc",
 "__NR_tee_ta_open_session",
 "__NR_tee_ta_get_session",
 "__NR_tee_ta_push_current_session",
 "__NR_tee_ta_get_current_session",
 "__NR_tee_ta_pop_current_session",
 "__NR_TEE_MemFill",
 "__NR_tee_ta_invoke_command",
 "__NR_tee_hash_get_digest_size",
 "__NR_tee_hash_createdigest",
 "__NR_tee_mac_get_digest_size",
 "__NR_tee_cipher_get_block_size",
 "__NR_tee_do_cipher_update",
 "__NR_tee_aes_cbc_cts_update",
 "__NR_tee_cryp_init",
 "__NR_to_user_ta_ctx",
 "__NR_tee_obj_add",
 "__NR_tee_obj_get",
 "__NR_tee_obj_verify",
 "__NR_tee_obj_close",
 "__NR_tee_obj_close_all",
 "__NR_tee_obj_free",
 "__NR___utee_from_param",
 "__NR_tee_user_mem_alloc",
 "__NR_tee_user_mem_realloc",
 "__NR_tee_user_mem_free",
 "__NR_TEE_Malloc",
 "__NR_TEE_Realloc",
 "__NR_TEE_Free",
 "__NR_tee_ta_close_session",
 "__NR___utee_to_param",
 "__NR_tee_svc_copy_from_user",
 "__NR_tee_svc_copy_to_user",
 "__NR_tee_svc_copy_kaddr_to_uref",
 "__NR_tee_svc_kaddr_to_uref",
 "__NR_tee_svc_uref_to_vaddr",
 "__NR_tee_svc_uref_to_kaddr",
 "__NR_tee_uuid_to_octets",
 "__NR_tee_uuid_from_octets",
 "__NR_uuid_print",
 "__NR_tee_obj_attr_free",
 "__NR_tee_obj_attr_clear",
 "__NR_tee_obj_attr_copy_from",
 "__NR_tee_obj_set_type",
 "__NR_utee_cryp_obj_alloc",
 "__NR_utee_cryp_obj_get_info",
 "__NR_utee_cryp_obj_close",
 "__NR_utee_cryp_obj_reset",
 "__NR_utee_cryp_obj_populate",
 "__NR_utee_cryp_obj_copy",
 "__NR_utee_cryp_state_alloc",
 "__NR_utee_cryp_state_free",
 "__NR_utee_hash_init",
 "__NR_utee_hash_update",
 "__NR_utee_hash_final",
 "__NR_utee_cipher_init",
 "__NR_utee_cipher_update",
 "__NR_tee_svc_cryp_free_states",
 "__NR_tee_pobj_release",
 "__NR_tee_pobj_rename",
 "__NR_tee_pobj_get",
 "__NR_TEE_GetObjectInfo",
 "__NR_TEE_GetObjectInfo1",
 "__NR_TEE_CloseObject",
 "__NR_TEE_AllocateTransientObject",
 "__NR_TEE_FreeTransientObject",
 "__NR_TEE_ResetTransientObject",
 "__NR_TEE_PopulateTransientObject",
 "__NR_TEE_InitRefAttribute",
 "__NR_TEE_InitValueAttribute",
 "__NR_TEE_CopyObjectAttributes",
 "__NR_TEE_CopyObjectAttributes1",
 "__NR_TEE_SetInstanceData",
 "__NR_TEE_GetInstanceData",
 "__NR_TEE_MemMove",
 "__NR_TEE_MemCompare",
 "__NR_TEE_AllocateOperation",
 "__NR_TEE_FreeOperation",
 "__NR_TEE_GetOperationInfo",
 "__NR_TEE_GetOperationInfoMultiple",
 "__NR_TEE_ResetOperation",
 "__NR_TEE_SetOperationKey",
 "__NR_TEE_SetOperationKey2",
 "__NR_TEE_DigestUpdate",
 "__NR_TEE_DigestDoFinal",
 "__NR_TEE_CipherInit",
 "__NR_TEE_CipherUpdate",
 "__NR_TEE_MACInit",
 "__NR_TEE_MACUpdate",
 "__NR_TEE_MACComputeFinal",
 "__NR_TEE_MACCompareFinal",
 "__NR_TEE_AEInit",
 "__NR_TEE_AEUpdate",
 "__NR_TEE_AEEncryptFinal",
 "__NR_TEE_AEDecryptFinal",
 "__NR_TEE_CopyOperation",
 "__NR_TA_GetObjhandle",
 "__NR_TA_GetObjhandlePtr",
 "__NR_TA_GetOphandle",
 "__NR_TA_GetOphandlePtr",
 "__NR_TA_GetAttr",
 "__NR_TA_GetAttrPtr",
 "__NR_TA_GetObjinfo",
 "__NR_TA_GetObjinfoPtr",
 ]
enabled_syscalls_M2351_mTower = [
     "TEE_MemFill",
     "TEE_Malloc",
     "TEE_Realloc",
     "TEE_Free",
     "TEE_GetObjectInfo",
     "TEE_GetObjectInfo1",
     "TEE_CloseObject",
     "TEE_AllocateTransientObject",
     "TEE_FreeTransientObject",
     "TEE_ResetTransientObject",
     "TEE_PopulateTransientObject",
     "TEE_InitRefAttribute",
     "TEE_InitValueAttribute",
     "TEE_CopyObjectAttributes",
     "TEE_CopyObjectAttributes1",
     "TEE_SetInstanceData",
     "TEE_GetInstanceData",
     "TEE_MemMove",
     "TEE_MemCompare",
     "TEE_AllocateOperation",
     "TEE_FreeOperation",
     "TEE_GetOperationInfo",
     "TEE_GetOperationInfoMultiple",
     "TEE_ResetOperation",
     "TEE_SetOperationKey",
     "TEE_SetOperationKey2",
     "TEE_DigestUpdate",
     "TEE_DigestDoFinal",
     "TEE_CipherInit",
     "TEE_CipherUpdate",
     "TEE_MACInit",
     "TEE_MACUpdate",
     "TEE_MACComputeFinal",
     "TEE_MACCompareFinal",
     "TEE_AEUpdate",
     "TEE_AEEncryptFinal",
     "TEE_AEDecryptFinal",
]


enabled_syscalls_M2351_TinyTEE = [
    "TEE_Malloc",
    "TEE_Realloc",
    "TEE_Free",
    "TEE_GetObjectInfo1",
    "TEE_GetObjectBufferAttribute",
    "TEE_GetObjectValueAttribute",
    "TEE_CloseObject",
    "TEE_AllocateTransientObject",
    "TEE_FreeTransientObject",
    "TEE_ResetTransientObject",
    "TEE_PopulateTransientObject",
    "TEE_InitRefAttribute",
    "TEE_InitValueAttribute",
    "TEE_CopyObjectAttributes1",
    "TEE_OpenPersistentObject",
    "TEE_CreatePersistentObject",
    "TEE_CloseAndDeletePersistentObject1",
    "TEE_ReadObjectData",
    "TEE_WriteObjectData",
    "TEE_AllocateOperation",
    "TEE_FreeOperation",
    "TEE_GetOperationInfo",
    "TEE_ResetOperation",
    "TEE_SetOperationKey",
    "TEE_DigestUpdate",
    "TEE_DigestDoFinal",
    "TEE_CipherInit",
    "TEE_CipherUpdate",
    "TEE_CipherDoFinal",
    "TEE_AsymmetricSignDigest",
    "TEE_AsymmetricVerifyDigest",
    "TEE_DeriveKey",
    "TEE_GenerateRandom",
]

additional_syscalls = [
    "TA_GetObjhandle",
    "TA_GetObjhandlePtr",
    "TA_GetOphandle",
    "TA_GetOphandlePtr",
    "TA_GetAttr",
    "TA_GetAttrPtr",
    "TA_GetObjinfo",
    "TA_GetObjinfoPtr",
]

def patch_const(const_file_location:str):
    res = []
    to_fix = []
    with open(const_file_location,'r',encoding='utf8') as const_f:
        for line in const_f:
            l0 = line.split()[0]
            #check valid functions
            if l0.startswith('__NR'):
                if l0 not in funcs:
                    to_fix.append(l0)
                    s = line
                else:
                    s = line.replace('???',str(funcs.index(l0)))
            else:
                s = line
            res.append(s)
    if len(to_fix) > 0:
        print("Nah... You need to add the following functions in patcher.py:")
        print(*to_fix)
        return False
    with open(const_file_location,'w',encoding='utf8') as const_f:
        for i in res:
            print(i,file=const_f,end='')
        print('const file has been patched. Please run `make` in syzkaller.')
    return True
def patch_ta(ta_file_location:str,_enabled_syscalls:list,func_width=40):
    res = []
    with open(ta_file_location,'r',encoding='utf8') as ta_f:
        for line in ta_f:
            if '[ENABLED]' in line or '[DISABLED]' in line:
                funcname = line[line.index('"')+1:line.rindex('"')]
                newline = "    {" + '"' + funcname + '"' + ' '*(func_width-len(funcname)) + ', '
                if funcname in _enabled_syscalls:
                    newline += funcname + ' '*(func_width-len(funcname))
                    newline += line[line.index(',', func_width+8):line.index('//[')] + '//[ENABLED]'
                else:
                    newline += '/*' + funcname + '*/NULL' + ' '*(func_width-8-len(funcname))
                    newline += line[line.index(',',func_width+8):line.index('//[')] + '//[DISABLED]'
                res.append(newline+'\n')
            else:
                res.append(line)
    with open(ta_file_location, 'w', encoding='utf8') as ta_f:
        for line in res:
            print(line,end='',file=ta_f)

def patch_config(file_location:str):
    res = []
    with open(file_location,'r',encoding='utf8') as f:
        modifying = False
        for line in f:
            if '[CONFIG-SELECT-START]' in line:
                modifying = True
                res.append(line)
                res.append(f"c.read(r'{config_path}')\n")
            if '[CONFIG-SELECT-END]' in line:
                modifying = False
            if not modifying:
                res.append(line)
    with open(file_location,'w',encoding='utf8') as f:
        for line in res:
            print(line,end='',file=f)

def gen_mycfg(mycfg_path:str):
    cfg = json.dumps({
        "target": "trusty/arm",
        "http": "127.0.0.1:56743",
        "workdir": config.get("workdir"),
        "syzkaller": config.get("project_root_dir"),
        "procs": 1,
        "board_controller": config.get("board_controller"),
        "board_server": config.get("net_addr")+":"+config.get("net_port"),
        "progs_dir": config.get("progs_dir"),
        "payload_dir": config.get("generated_payload_root_dir"),
        "sigcovstate_dir": config.get("sigcovstate_dir"),
        "timer_log": config.get("timer_log"),
        "command_python": config.get("command_python"),
        "corpus_file" : config.get("corpus_file"),
        "trace_id" : config.get("trace_id"),
        "state_flag": config.get("state_flag"),
        "handle_division": config.get("handle_division"),
    },indent=2)
    with open(mycfg_path,'w',encoding='utf8') as f:
        print(cfg,file=f)

def patch_trace_extraction(file_location:str):
    res = []
    with open(file_location,'r',encoding='utf8') as f:
        modifying = False
        for line in f:
            if '[CONFIG-SELECT-START]' in line:
                modifying = True
                res.append(line)
                res.append(f"c.read(r'{config_path}')\n")
                res.append(f"trace_input = '{trace_input}'\n")
                res.append(f"trace_output = '{trace_output}'\n")
                res.append(f"pickleFilePath = '{pickle_filepath}'\n")
            if '[CONFIG-SELECT-END]' in line:
                modifying = False
            if not modifying:
                res.append(line)
    with open(file_location,'w',encoding='utf8') as f:
        for line in res:
            print(line,end='',file=f)

if __name__ == '__main__':
    # for filename in ['ETMUtils.py','RTTUtils.py','TimingUtils.py','main.py','ExpAnalyzer.py','GraphUtils.py']:
    for filename in ['ETMUtils.py','RTTUtils.py','TimingUtils.py','main.py']:
        patch_config(filename)
    gen_mycfg(config.get("go_mycfg"))
    patch_trace_extraction(config.get("trace_extraction"))