import os
import ctypes
import sys
import time
import struct
import traceback
import datetime
import threading
import jlinksdk
import socket
import RTTUtils
import ETMUtils
import TimingUtils
import configparser
import win32gui
import win32con
import SharingData
from TEE_Const import *
from TraceExtraction import Payload
import json
#
# Load DLL
#
dll : ctypes.CDLL
controller = jlinksdk.JLink()

server : socket.socket
c = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
#[CONFIG-SELECT-START]
c.read(r'D:/Gits/github.com/google/syzkaller/board_manager/config.ini')
#[CONFIG-SELECT-END]
config = c['DEFAULT']
target_TEE = config.get('target_TEE')
config = c[target_TEE]
raw_trace_filename : str
raw_trace_rootdir = config['raw_trace_rootdir']
sleep_sep = config.getfloat('sleep_sep')
sleep_time = config.getfloat('sleep_time')
payload_log_file_root_dir = config.get('payload_log_file_root_dir')
payload_log = config.getboolean('payload_log_file')
generated_payload_root_dir = config.get('generated_payload_root_dir')
payload_timeout_cnt = config.getint('payload_timeout_cnt')
handle_size = json.loads(config.get('handle_size'))
payload_buf_addr = int(config['payload_buf_addr'], 16)
payload_size_addr = int(config['payload_size_addr'], 16)
execute_info_addr = int(config['execute_info_s_addr'], 16)
ETMCR = int(config['ETMCR'], 16)
DEMCR = int(config['DEMCR'], 16)
DFSR = int(config['DFSR'], 16)
protector_value = int(config['protector_value'], 16)
protector_start_addr = int(config['protector_start_addr'], 16)
protector_end_addr = int(config['protector_end_addr'], 16)
data_event_s_addr = int(config['data_event_s_addr'], 16)
state_variable_addr = int(config['state_variables_addr'], 16)
fuzzing = True
execution_file_path = os.path.join(config['execution_file_root_dir'] , 'execution_file.txt')
if not os.path.exists(config['execution_file_root_dir']):
    os.makedirs(config['execution_file_root_dir'])
execution_file = open(execution_file_path,'a',encoding='utf8')
payload_log_file = None
payload_size = 0

class StateVars:
    STATE_TEE_OPERATION_HANDLE = 1
    STATE_TEE_OBJECT_HANDLE    = 2

    ALL_TYPES = [i for i in range(1,3)]
'''*********************************************************************
*
*      jlink sdk error helper
*
*********************************************************************
'''
class WindowsHelper(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self) -> None:
        global fuzzing
        while fuzzing:
            hwnd_list = []
            win32gui.EnumWindows(lambda _hwnd, param: param.append(_hwnd), hwnd_list)
            # hwnd = win32gui.FindWindow(None,jlinksdk_error_title) // Not sure the version
            for hwnd in hwnd_list:
                title = win32gui.GetWindowText(hwnd)
                if 'J-Link V' in title and 'Error' in title:
                    # if hwnd > 0:
                    win32gui.PostMessage(hwnd,win32con.WM_CLOSE,0,0)
            time.sleep(2)


'''*********************************************************************
*
*      local functions
*
**********************************************************************
'''
const_chars = lambda x : ctypes.c_char_p(x.encode('utf8'))
i2b = lambda x : struct.pack('<I',x)

state_variables = [] # nested list : each item stands for all state variables in one syscall
def _debug(info):
    return
    print(f'\033[32m[DEBUG] {info}\033[0m')
def _set_register(address,value):
    """ update the origin-value at address -> origin-value | value

    :param address:
    :param value:
    :return:
    """
    cr = controller.ReadMem(address, 4)
    val = struct.unpack('<I', cr[1])[0]
    val |= value
    controller.WriteMemU32(address,val)

def _check_state_variables(addr):
    """This function is used to check state variables stored on the board and update global state_variables in manager

    :param addr: The address of state_variables on the board
    :return: No return values
    """
    p1 = _read_uint(protector_start_addr)
    p2 = _read_uint(protector_end_addr)
    if p1 != protector_value or p2 != protector_value:
        print(f"Protection failed: Expect {hex(protector_value)} but found {hex(p1)} , {hex(p2)}")
        return False
    global state_variables
    t_state_addr = '' # debug
    state_addr = ''   # debug
    try:
        variable_num = _read_uint(addr)
        syscall_states = {}
        for i in range(1,variable_num+1):
            state_base_addr = addr+8*i-4
            state_type = _read_uint(state_base_addr)
            state_addr = _read_uint(state_base_addr+4)
            if state_addr != 0:
                state_size = _read_uint(state_addr-4) >> 3 << 3
            else:
                continue
            if state_size == 0x8 or state_size == 0x10: 
                t_state_addr = _read_uint(state_addr)       # struct address
                if t_state_addr != 0 :
                    state_addr = t_state_addr
                    state_size = _read_uint(state_addr-4) >> 3 << 3 # struct size
            for valid_size in handle_size:
                if state_size == valid_size:
                    _,state_data = controller.ReadMem(state_addr,state_size)
                    for t in StateVars.ALL_TYPES:
                        if t == state_type:
                            syscall_states.setdefault(t,[])
                            syscall_states[t].append(state_data)
        for t in StateVars.ALL_TYPES: # if no such pointer, set it null
            syscall_states.setdefault(t,[])
        state_variables.append(syscall_states)
        return True
    except Exception as e:
        print(e,f'state_addr = {state_addr} t_state_addr = {t_state_addr}')
        return False
def _serialize_state_varibles(fuzzing_region):
    """This function will serialize the dict 'state_variables' for syzkaller end.

    :return: Bytes of serialized state_variables
    """
    if not fuzzing_region:
        return i2b(0)
    global state_variables
    result = i2b(len(state_variables)) # number of snapshots
    for snapshot in state_variables:
        result += i2b(len(snapshot)) # number of types for this snapshot
        for t in snapshot:
            result += i2b(t) # type of state variable
            result += i2b(len(snapshot[t])) # number of handlers for this type
            for index, item in enumerate(snapshot[t]):
                for size in handle_size:
                    if len(snapshot[t][index]) == size:
                        break
                else:
                    snapshot[t][index] = struct.pack('<I', 0)

                result += i2b(len(snapshot[t][index]))
                result += snapshot[t][index]
    return result

def _generate_trace_file_name(cur_test_index):

    global raw_trace_filename
    now = datetime.datetime.now()
    raw_trace_filename = rf'{raw_trace_rootdir}TraceFile_{now.strftime("%Y%m%d_%H%M%S")}_{now.microsecond}_{cur_test_index}.bin'
    res, err = controller.Exec(rf'TraceFile={raw_trace_filename}')

def _tcp_handler(sock:socket.socket,address):
    global fuzzing
    global payload_size
    print(f'Syzkaller connected: {address[0]}:{address[1]}')
    while fuzzing:
        try:
            data = sock.recv(0x4000)
        except ConnectionResetError:
            traceback.print_exc()
            break
        if data.startswith(b'stop'):
            print('Syzkaller stopped normaly.')
            break
        if len(data) > 0:

            if len(data)< 4:
                sock.send(i2b(0))
                continue
            go_index = struct.unpack('<I',data[:4])[0]
            print(f'Handling payload {go_index}')
            data = data[4:] # First 4 bytes is index for synchronizing
            payload_size = len(data)
            TimingUtils.update_timestamp(TimingUtils.Timing.payload_receive_index)
            try:
                Syztrust_ExecutePayloadMultiSync(data,go_index, sock)
            except :
                traceback.print_exc()
    try:
        sock.send(i2b(0xffffffff))
        sock.close()
    except ConnectionResetError:
        print('Syzkaller closed the connection.')
    print('TCP_Handler finished.')
def _read_int(addr):
    num,info = controller.ReadMem(addr,4)
    return struct.unpack('<i',info)[0]
def _read_uint(addr):
    num,info = controller.ReadMem(addr,4)
    return struct.unpack('<I',info)[0]
'''*********************************************************************
*
*        _ConsoleGetString
*
*      function description
*        get user console input and return it
*        needs stringtext as argument e.g. "Insert Info and press ENTER"
**********************************************************************
'''
def _ConsoleGetString(request):
    Input = input(request)
    return Input

# copy input to board
def rtt_copy_to_board(payload):
    size = len(payload)
    controller.WriteMem(payload_buf_addr,size,payload)
    controller.WriteMemU32(payload_size_addr,size)

def modify_payload_log(_log):
    funcname = ''
    result = ''
    for line in _log.split('\n'):
        _list = line.split()
        if '[FUNC]' in line:
            try:
                funcname = _list[1]
            except IndexError:
                # No function name found. Something wrong?
                continue
            if 'return' in line:
                if funcname in TEE_Syscall_Void or funcname.startswith('TA'):  # does not care TA
                    _list[-1] = 'void'
                else:
                    if not _list[-1].startswith('0x'):
                        _list[-1] = '0x' + _list[-1]
        elif '[CRASH]' in line:
            if funcname.startswith('TEE'):
                _list[0] = '[CRASH-TEE]'
            elif funcname.startswith('TA'):
                _list[0] = '[CRASH-TA]'
        elif '[PANIC]' in line and len(_list) > 1:
            if not _list[-1].startswith('0x'):
                _list[-1] = '0x' + _list[-1]
        result += ' '.join(_list) + '\n'
    return result


def append_one_payload(_exe_log:str,_rtt_log:str):
    """This function analyses log and fill the global payloads list

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
    payloads = SharingData.PayloadStorage.payloads
    _exe_logs = _exe_log.replace('\r','').split('\n')
    _rtt_logs = _rtt_log.replace('\r','').split('\n')
    _payload = Payload()

    for line in _rtt_logs:
        if 'Payload index' in line:
            _payload.index = int(line.split()[-1])
        elif '[FUNC]' in line:
            _payload.add_func(line) # important!
        elif '[CRASH-TEE]' in line:
            _payload.status_code = Payload.status_hardfault
        elif '[CRASH-TA]' in line:
            _payload.valid = False
        elif '[SUCCESS]' in line:
            _payload.status_code = Payload.status_success
        elif '[PANIC]' in line:
            _list = line.split()
            if len(_list) > 1:
                _payload.panic_code = _list[1]
            _payload.status_code = Payload.status_panic
        elif '[STUCK]' in line:
            _payload.status_code = Payload.status_stuck
        elif '[RTT-TIMEOUT]' in line:
            if _payload is not None:
                _payload.status_code = Payload.status_timeout
    for line in _exe_logs:
        if 'Covs' in line:
            _payload.covs_str = line
        elif 'Sigs' in line:
            _payload.sigs_str = line
    if _payload is not None and _payload.valid:
        payloads.append(_payload)
        _payload = None

# Currently used
def Syztrust_ExecutePayloadMultiSync(payload, _go_index, sock:socket.socket=None):
    global payload_log_file
    global state_variables
    TimingUtils.update_timestamp(TimingUtils.Timing.board_reset_index)
    dll.JLINKARM_ResetNoHalt()

    time.sleep(0.5)  # wait until initialized
    while controller.IsHalted(): # Note: tight timing. halt check may happen between two halts and cause fuzzing failures
        # dll.JLINKARM_Step()
        controller.Go()
        time.sleep(sleep_time) # Make sure correct check
    time.sleep(0.5)  # wait until initialized
    # _set_register(DEMCR,0x7f0)
    TimingUtils.update_total(TimingUtils.Timing.board_reset_index)
    TimingUtils.update_timestamp(TimingUtils.Timing.payload_copy_index)
    rtt_copy_to_board(payload) # copy payload to the board and halt the board
    TimingUtils.update_total(TimingUtils.Timing.payload_copy_index)
    reply = b''
    all_sigs = []
    all_covs = []
    state_variables = []
    tmp_log = ''
    extra_info = ''
    rnd = 0
    prev_status = 0
    ETMUtils.State.decode_error = False
    fuzzing_region = True
    if payload_log:
        print(f'Payload index {_go_index}\nGo index {_go_index}', file=payload_log_file)
    TimingUtils.update_timestamp(TimingUtils.Timing.payload_execute_index)
    while fuzzing :
        rnd += 1
        controller.STRACE_Stop()  # make sure stop
        # Make sure halted before starting tracing
        while not controller.IsHalted():
            time.sleep(sleep_sep)  # wait until halt
        if ETMUtils.State.decode_error:
            break
        TimingUtils.update_timestamp(TimingUtils.Timing.tracefile_config_index)
        _generate_trace_file_name(_go_index) # set new trace file name
        TimingUtils.update_timestamp(TimingUtils.Timing.tracefile_config_index)
        TimingUtils.update_timestamp(TimingUtils.Timing.syscall_execute_index)
        # print('strace start.')

        controller.STRACE_Start()
        controller.Go() # halt soon in most cases
        cnt = payload_timeout_cnt
        while not controller.IsHalted() and cnt > 0:
            cnt -= 1
            time.sleep(sleep_sep)  # wait until halt
        controller.STRACE_Stop()  # raw tracefile generated at this point
        # print('strace stop.')
        # One syscall executed. Check program status now.
        TimingUtils.update_total(TimingUtils.Timing.syscall_execute_index)
        if cnt <= 0: # timeout
            print(f'Payload {_go_index} Syscall time out.')
            try:
                os.remove(raw_trace_filename.replace('.bin','_0000.bin'))
            except:
                traceback.print_exc()
            break
        try:
            status = _read_int(data_event_s_addr)
        except:
            ETMUtils.State.decode_error = True
            break
        # print(f'rnd={rnd}, data_event={status}')
        # successfully executed all syscalls in this payload.
        if status == -1:
            try:
                os.remove(raw_trace_filename.replace('.bin','_0000.bin'))
            except:
                traceback.print_exc()
            break
        if status > 100 or rnd > 100:
            print('ERROR: more than 100 syscalls') # Memory data crash caused by testcase
            ETMUtils.State.decode_error = True
            break
        # check state variables
        if fuzzing_region and not _check_state_variables(state_variable_addr):
            fuzzing_region = False
        TimingUtils.update_timestamp(TimingUtils.Timing.tracefile_decode_index)
        sigs, covs = Syztrust_ParseTraceFile_Sync()
        all_sigs.append(sigs)
        all_covs.append(covs)
        TimingUtils.update_total(TimingUtils.Timing.tracefile_decode_index)
        if prev_status == status:
            extra_info += '\n[STUCK]\n'
            break
        prev_status = status
        if status < 0:
            break

    TimingUtils.update_total(TimingUtils.Timing.payload_execute_index)
    # get board infomation
    execute_nums = 0
    execute_info = b''
    try:
        execute_nums = _read_int(execute_info_addr)
        read_num, execute_info = controller.ReadMem(execute_info_addr+4,execute_nums*4*4)
    except:
        ETMUtils.State.decode_error = True
    if ETMUtils.State.decode_error: # in case of jlink trace error
        exec_info = f'Payload skipped index : {_go_index}\n'
        print(exec_info, file=execution_file)
        if sock is not None:
            try:
                sock.send(i2b(0))
            except ConnectionResetError:
                print('syzkaller stopped in excption.')
        return # if decoding error occurs, do not output execution information then.
    else:
        TimingUtils.update_timestamp(TimingUtils.Timing.callreply_craft_index)
        reply += _serialize_state_varibles(fuzzing_region)
        reply += i2b(execute_nums)
        for i in range(len(all_sigs)):
            reply += execute_info[i*16:(i+1)*16] + i2b(len(all_sigs[i])>>2) + i2b(len(all_covs[i])>>2) + i2b(0)
            reply += all_sigs[i] + all_covs[i]
        for i in range(len(all_sigs),execute_nums): # prepare empty callReply for timeout syscalls
            reply += execute_info[i*16:(i+1)*16] + i2b(0)*3
        TimingUtils.update_total(TimingUtils.Timing.callreply_craft_index)
        if sock is not None:
            try:
                TimingUtils.update_timestamp(TimingUtils.Timing.callreply_trans_index)
                l = len(reply)
                if l < 0x1000000:
                    sock.send(i2b(l))
                    sock.send(reply)
                else:
                    print(f'Error: Too large reply for payload-{_go_index}')
                    sock.send(i2b(0))
                TimingUtils.update_total(TimingUtils.Timing.callreply_trans_index)
            except ConnectionResetError:
                print('syzkaller stopped in excption.')
                return
    Sigs = [str(len(i)) for i in all_sigs]
    sig_sum = sum([len(i) for i in all_sigs])
    Covs = [str(len(i)) for i in all_covs]
    cov_sum = sum([len(i) for i in all_covs] )
    exec_info = f'Payload index : {_go_index}\n' \
                f'Go index {_go_index}\n' \
                f'Sigs {sig_sum} : {",".join(Sigs)}\n' \
                f'Covs {cov_sum} : {",".join(Covs)}\n' \
                f'Payload size : {payload_size}\n' \
                f'Execute syscall num : {execute_nums}\n' \
                f'Bytes sent to syzkaller : {len(reply)}\n'
    exec_info += TimingUtils.get_time_log()
    print(exec_info, file=execution_file)
    execution_file.flush()
    # prepare payload
    if payload_log:
        cnt = payload_timeout_cnt * 3
        TimingUtils.update_timestamp(TimingUtils.Timing.rtt_log_collect_index)
        while True and cnt > 0:
            readin = controller.RTTERMINAL_Read(0, 0x1000)
            readin_num = len(readin)
            if readin_num > 0:
                try:
                    tmp_log += readin[0:readin_num].decode('utf8')
                except UnicodeDecodeError:
                    tmp_log += '[DECODE ERROR]\n'
                if '[PANIC]' in tmp_log or '[CRASH]' in tmp_log or '[SUCCESS]' in tmp_log:
                    break
                continue # continue reading if rtt get some bytes
            cnt-=1
            time.sleep(sleep_sep)
        else:
            extra_info += '\n[RTT-TIMEOUT]\n'
        TimingUtils.update_total(TimingUtils.Timing.rtt_log_collect_index)
        rtt_info = modify_payload_log(tmp_log + extra_info)
        print(rtt_info, file=payload_log_file,flush=True)

# parse raw trace file sync
def Syztrust_ParseTraceFile_Sync():
    global raw_trace_filename
    filename = raw_trace_filename.replace('.bin','_0000.bin')
    parser = ETMUtils.ParserSync(filename,controller)
    return parser.parse()

def Syztrust_JLinkInit():
    global dll
    RTTUtils.connectM2351(controller)
    dll = jlinksdk.GetCDLLInst()
    res, err = controller.Exec('SelectTraceSource=1')
    print(f'SelectTraceSource result = {res} , err = {err}')
    res = dll.JLINK_STRACE_Config(const_chars('PortWidth=4'))
    print(f'STRACEConfig result = {res}')
    dll.JLINK_TRACE_PortWidth = 4
    Syztrust_SetDataEvent()




def Syztrust_SetDataEvent():
    """ This function will call JLINKARM_SetDataEvent at data_event_s_addr.
    After setting, any writes to this address will halt the board.

    :return:
    """
    size = ctypes.sizeof(RTTUtils.JLINKARM_DATA_EVENT())
    data_event = RTTUtils.JLINKARM_DATA_EVENT(
        size,                                                       # SizeOfStruct
        RTTUtils.JLINKARM_DATA_EVENT.JLINKARM_EVENT_TYPE_DATA_BP,   # Type
        data_event_s_addr,                       # Addr
        0,                                                          # AddrMask   -> matching one sepecific address
        0,                                                          # Data       -> base data
        0xffffffff,                                                 # DataMask   -> matching any change
        RTTUtils.JLINKARM_DATA_EVENT.JLINK_EVENT_DATA_BP_SIZE_32BIT
        | RTTUtils.JLINKARM_DATA_EVENT.JLINK_EVENT_DATA_BP_DIR_WR,  # Access     -> matching 'write' operation
        RTTUtils.JLINKARM_DATA_EVENT.JLINK_EVENT_DATA_BP_MASK_PRIV  # AccessMask -> do not care (non-)secure operation
    )
    tmp = ctypes.c_uint32(0)
    res = dll.JLINKARM_SetDataEvent(ctypes.pointer(data_event),ctypes.pointer(tmp))
    if res >= 0:
        print(f'Successfully set data event at {config["data_event_s_addr"]}')
    else:
        print(f'Failed to set data event at {config["data_event_s_addr"]} :',end='')
        if res == RTTUtils.JLINKARM_DATA_EVENT.JLINKARM_EVENT_ERR_UNKNOWN:
            print(f'Err unknown')
        elif res == RTTUtils.JLINKARM_DATA_EVENT.JLINKARM_EVENT_ERR_NO_MORE_EVENTS:
            print(f'Err no more events')
        elif res == RTTUtils.JLINKARM_DATA_EVENT.JLINKARM_EVENT_ERR_NO_MORE_ADDR_COMP:
            print(f'Err no more addr comp')
        elif res == RTTUtils.JLINKARM_DATA_EVENT.JLINKARM_EVENT_ERR_NO_MORE_DATA_COMP:
            print(f'Err no more data comp')
        elif res == RTTUtils.JLINKARM_DATA_EVENT.JLINKARM_EVENT_ERR_INVALID_ADDR_MASK:
            print(f'Err invalid addr mask')
        elif res == RTTUtils.JLINKARM_DATA_EVENT.JLINKARM_EVENT_ERR_INVALID_DATA_MASK:
            print(f'Err invalid data mask')
        elif res == RTTUtils.JLINKARM_DATA_EVENT.JLINKARM_EVENT_ERR_INVALID_ACCESS_MASK:
            print(f'Err invalid access mask')
        else:
            print(f'Wrong function')
    controller.Reset()  # After set data event, the board should reset.
    while controller.IsHalted():
        dll.JLINKARM_Step()
        dll.JLINKARM_Go()
        time.sleep(0.01)  # In case of halting on following data event
    return res

def Syztrust_StartSocket():
    global server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port_num = config.getint('net_port')
    max_clients = config.getint('max_clients')

    try:
        server.bind((config['net_addr'],port_num))
        print(f'Server binds socket port {port_num}... Listening connections now...')
    except:
        print(f'Server failed binding port {port_num}')
        return
    try:
        server.listen(max_clients)
        client, addr = server.accept()
    except KeyboardInterrupt:
        print('break by ctrl+C')
        return
    _tcp_handler(client,addr)
def interact_debug():
    """ Interact with the board using terminal.
    Examples:
    q                    -> quit debug
    b 0x11bf2            -> set a break point at 0x11bf2
    info bps             -> show all break points
    remove b 0           -> remove the break point at index 0
    r                    -> reset and halt the borad
    rn                   -> reset and go the board
    h                    -> halt the board
    g                    -> go the board
    go                   -> step and go the board
    step                 -> step the board
    read 0x40001e00      -> read and print the data at 0x40001e00
    write 0x30000000 0x4 -> write 0x4 to location 0x30000000
    check halt           -> check whether the board is halt
    payload 3            -> write payload-3 to the board
    exec 3               -> call Syztrust_ExecuteFile to execute payload-3
    :return:
    """
    try:
        RTTOut = RTTUtils.RTThreading(controller, 'out')
        time.sleep(0.1)
        # RTTFuzzer = RTThreading(jlink,'fuzz')
        rtt_debug = RTTUtils.RTThreading(controller, 'debug')
        RTTOut.start()
        rtt_debug.start()
        time.sleep(0.1)

        # RTTFuzzer.start()
        # print('check1')
        RTTOut.join()
        rtt_debug.join()
    except :
        traceback.print_exc()
        RTTUtils.RTThreading.conti = False

def main():
    global fuzzing
    global payload_log_file
    # Wait the testecase to be written
    if payload_log:
        payload_log_file = open(f'{payload_log_file_root_dir}temp_result.txt', 'a', encoding='utf8')
    try:
        TimingUtils.update_timestamp(TimingUtils.Timing.board_init_index)
        Syztrust_JLinkInit()  # init J-Trace
        TimingUtils.update_total(TimingUtils.Timing.board_init_index)
        print(f'Init board: {TimingUtils.Timing.timetotal[TimingUtils.Timing.board_init_index]}',file=execution_file)
        windows_helper = WindowsHelper()
        windows_helper.start()
        Syztrust_StartSocket()
    except KeyboardInterrupt:
        print('break.')
    except NameError as e:
        print(e.args)
    except:
        traceback.print_exc()
    # call InitDeubgSession
    print('done.')
    fuzzing = False
    controller.RTTERMINAL_Stop()
    controller.Close()
    if payload_log:
        payload_log_file.close()

def debug():
    global fuzzing
    global payload_log_file
    # Wait the testecase to be written
    #
    try:
        Syztrust_JLinkInit()  # init J-Trace
        if payload_log:
            payload_log_file = open(f'{payload_log_file_root_dir}temp_result.txt', 'a', encoding='utf8')
        interact_debug()
        input("Press Enter to Exit")
        execution_file.close()
        fuzzing = False
        controller.RTTERMINAL_Stop()
        controller.Close()
    except NameError as e:
        print(e.args)
    except:
        traceback.print_exc()




if __name__ == "__main__":
    try:
        main()
    except:
        traceback.print_exc()