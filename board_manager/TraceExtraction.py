#!python
import os
from datetime import datetime
from TEE_Const import *
import copy
import pickle
import SharingData
import configparser
from SharingData import Payload
# payload the log file
c = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
#[CONFIG-SELECT-START]
c.read(r'D:/Gits/github.com/google/syzkaller/board_manager/config.ini')
trace_input = 'D:/Gits/github.com/google/syzkaller/workdir/fuzz_data/trace_files/trace_input.txt'
trace_output = 'D:/Gits/github.com/google/syzkaller/workdir/fuzz_data/trace_files/trace_output.txt'
pickleFilePath = 'D:/Gits/github.com/google/syzkaller/workdir/fuzz_data/payloads.pickle'
#[CONFIG-SELECT-END]
config = c['DEFAULT']
target_TEE = config.get('target_TEE')
config = c[target_TEE]
log_filename = 'temp_result.txt'
execution_filename = 'execution_file.txt'
CorpusFile = 'seeds.txt'
analysis_filename = 'analyze_result.txt'
timer_log_filename = 'timer_log.txt'
x = []
y = []
rate_y = []

payload = []
payload_output = []
payload_outputs = []
syscall = ""
TEE_Return_Code_Re = {v : k for k, v in TEE_Return_Code.items()}
# from main import hand_out_data

def fetch_payloads():
    # return hand_out_data()
    return SharingData.PayloadStorage.payloads
################################
# diversity of testcase
################################
def unique_payload():
    payloads = fetch_payloads()
    unique_payloads = []
    unique_payload_outputs = []
    for i in range(len(payloads)):
        # handle a syscall sequence
        if payloads[i].syscalls in unique_payloads:
            continue
        else:
            unique_input = list(payloads[i].syscalls) # will be sorted later
            input_len = len(payloads[i].syscalls)
            output_len = len(payloads[i].syscall_results)
            final_result = []    # will be sorted later
            for syscall_result in payloads[i].syscall_results:
                if syscall_result in TEE_Return_Code_Re:
                    final_result.append(copy.deepcopy(TEE_Return_Code_Re[syscall_result]))
                else:   # result is None
                    if payloads[i].status_code == 1 or payloads[i].status_code == 3 or payloads[i].status_code == 4:
                        unique_input.pop()
                    elif payloads[i].status_code == 2:
                        if payloads[i].panic_code:
                            final_result.append(TEE_Return_Code_Re[payloads[i].panic_code])
                        else:
                            print (payloads[i].syscalls, "no panic code!")
            # syscall result crash, not recorded
            if (len(payloads[i].syscalls) > len(payloads[i].syscall_results)) and (payloads[i].status_code == 1 or payloads[i].status_code == 3 or payloads[i].status_code == 4):
                unique_input.pop()
            if len(unique_input):
                unique_payloads.append(unique_input)
                unique_payload_outputs.append(final_result)
    unique_payloads_len = [ [] for i in range(21)]
    unique_payload_outputs_len = [ [] for i in range(21)]
    for j in range(len(payloads)):
        i = len(payloads[j].syscalls)
        if payloads[j].syscalls in unique_payloads_len[i]:
            continue
        else:
            unique_input_len = list(payloads[j].syscalls)
            input_len = len(payloads[j].syscalls)
            final_result_len = []
            for syscall_result in payloads[j].syscall_results:
                if syscall_result in TEE_Return_Code_Re:
                    final_result_len.append(TEE_Return_Code_Re[syscall_result])
                else:   # result is None
                    if payloads[j].status_code == 1 or payloads[j].status_code == 3 or payloads[j].status_code == 4:
                        unique_input_len.pop()
                    elif payloads[j].status_code == 2:
                        if payloads[j].panic_code:
                            final_result_len.append(TEE_Return_Code_Re[payloads[j].panic_code])
                        else:
                            print (payloads[j].syscalls, "no panic code!")
            # syscall result crash, not recorded
            if (len(payloads[j].syscalls) > len(payloads[j].syscall_results)) and (payloads[j].status_code == 1 or payloads[j].status_code == 3 or payloads[j].status_code == 4):
                unique_input_len.pop()
            if len(unique_input_len):
                unique_payloads_len[i].append(unique_input_len)
                unique_payload_outputs_len[i].append(final_result_len)
    # log the unique testcase into test.trace
    with open(trace_input,'w',encoding='utf8') as f:
        for i in range(21):
            if i == 0:
                continue
            else: 
                for j in range(len(unique_payloads_len[i])):
                    list_tmp = unique_payloads_len[i][j]
                    str_tmp = ' '.join(list_tmp)
                    print(f'{str_tmp}',file=f)
    
    with open(trace_output,'w',encoding='utf8') as f:
        for i in range(21):
            if i == 0:
                continue
            else: 
                for j in range(len(unique_payload_outputs_len[i])):
                    list_tmp = unique_payload_outputs_len[i][j]
                    str_tmp = ' '.join(list_tmp)
                    print(f'{str_tmp}',file=f)



def load_payloads():
    """This function analyses log file and fill the global payloads list

        The following payloads will not be loaded to `payloads` list:
        1. No function invoked successfully inside
        2. CRASH-TA
        3. Nothing exist between start symbol and final symbols

        The syscalls in each payload in the `payloads` list:
        1. Only contains TEE_xxx functions
        2. Only successfully invoked and returned syscalls are counted into `len`
        3. Syscalls that invoked but failed to return are reserved
    :return:
    """
    payloads = fetch_payloads()
    payload_cur_index = None
    # load payloads from log_file
    with open(log_dir+log_filename,'r',encoding='utf8') as log_file:
        _payload = None
        for line in log_file:
            if 'Payload index' in line:
                payload_cur_index = int(line.split()[-1])
            elif '[BEFORE FUZZ]' in line:
                _payload = Payload()
                _payload.index = payload_cur_index
            elif '[FUNC]' in line:
                if _payload is None: continue
                _payload.add_func(line)
            elif '[CRASH-TEE]' in line:
                if _payload is None: continue
                _payload.status_code = Payload.status_hardfault
                if _payload.valid:
                    payloads.append(_payload)
                    _payload = None
            elif '[CRASH-TA]' in line:
                if _payload is None: continue
                _payload.valid = False
                _payload = None
            elif '[SUCCESS]' in line:
                if _payload is None: continue
                _payload.status_code = Payload.status_success
                if _payload.valid:
                    payloads.append(_payload)
                    _payload = None
            elif '[PANIC]' in line:
                if _payload is None: continue
                _list = line.split()
                if len(_list) > 1:
                    _payload.panic_code = _list[1]
                _payload.status_code = Payload.status_panic
                if _payload.valid:
                    payloads.append(_payload)
                    _payload = None
            elif '[STUCK]' in line:
                if _payload is None: continue
                _payload.status_code = Payload.status_stuck
                if _payload.valid:
                    payloads.append(_payload)
                    _payload = None
            elif '[RTT-TIMEOUT]' in line:
                if _payload is None: continue
                _payload.status_code = Payload.status_timeout
                if _payload.valid:
                    payloads.append(_payload)
                    _payload = None
        if _payload is not None:
            payloads.append(_payload)
            _payload = None
    # additional information from execution_file
    skipped_cnt = 0
    executed_cnt = 0
    with open(log_dir+execution_filename,'r',encoding='utf8') as exe_file:
        payloads_index  = 0 # speed up searching because len(payloads) is smaller than number of executed payloads
        exec_index      = 0
        start_time      = None
        delta_time      = None
        for line in exe_file:
            if 'skipped' in line:
                skipped_cnt += 1
            elif 'Payload index' in line:
                exec_index = int(line.split()[-1])
                executed_cnt += 1
            elif 'Receive payload at' in line:
                exec_timestamp = datetime.strptime(line[-27:-1],'%Y-%m-%d %H:%M:%S.%f')
                if start_time is None:
                    start_time = exec_timestamp
                else:
                    delta_time = exec_timestamp - start_time
                for ind in range(payloads_index,len(payloads)):
                    if payloads[ind].index == exec_index:
                        payloads[ind].timestamp = exec_timestamp
                        payloads_index = ind
                        break
            elif 'Covs' in line:
                for ind in range(payloads_index,len(payloads)):
                    if payloads[ind].index == exec_index:
                        payloads[ind].covs_str = line
                        payloads_index = ind
                        break
            elif 'Sigs' in line:
                for ind in range(payloads_index,len(payloads)):
                    if payloads[ind].index == exec_index:
                        payloads[ind].sigs_str = line
                        payloads_index = ind
                        break
    return executed_cnt,skipped_cnt,delta_time,payloads


def modify_logfile():
    """This function modifies the log file to new format

    1. add '0x' before uint32_t return value
    2. replace the random return value with 'void' for functions with 'void' return type
    3. distinguish CRASH-TEE and CRASH-TA

    """
    funcname = ''
    with open(log_dir+log_filename,'r',encoding='utf8') as origin_file:
        with open(log_dir+log_filename+'.bak','w',encoding='utf8') as new_file:
            for line in origin_file:
                _list = line.split()
                if '[FUNC]' in line:
                    try:
                        funcname = _list[1]
                    except IndexError:
                        # No function name found. Something wrong?
                        continue
                    if 'return' in line:
                        if funcname in TEE_Syscall_Void or funcname.startswith('TA'): # does not care TA
                            _list[-1] = 'void'
                        else:
                            if not _list[-1].startswith('0x'):
                                _list[-1] = '0x'+_list[-1]
                elif '[CRASH]' in line:
                    if funcname.startswith('TEE'):
                        _list[0] = '[CRASH-TEE]'
                    elif funcname.startswith('TA'):
                        _list[0] = '[CRASH-TA]'
                elif '[PANIC]' in line and len(_list) > 1:
                    if not _list[-1].startswith('0x'):
                        _list[-1] = '0x' + _list[-1]
                print(' '.join(_list),file=new_file)
    os.replace(log_dir+log_filename+'.bak',log_dir+log_filename)



if __name__ == "__main__":
    log_dir = config.get('payload_log_file_root_dir')
    executed, skipped, fuzz_time,the_payloads = load_payloads()
    payloads = fetch_payloads()
    with open(pickleFilePath, 'wb') as f: pickle.dump(payloads, f)
    unique_payload()
