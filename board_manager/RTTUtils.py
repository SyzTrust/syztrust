import copy
import re
import struct
from importlib.metadata import files
from math import fabs
import os
import sys
import time
import jlinksdk
import threading
import traceback
import datetime
import ctypes
import configparser
import binascii
import SharingData
# import CMBackTraceUtils as Cmbt
#/*********************************************************************
#*
#*       "Defines"
#*
#**********************************************************************
#*/
def b2i(x):
    return struct.unpack('<i',x)[0]
def i2b(x):
    return struct.pack('B',x)
def read_int(addr):
    _,res = controller.ReadMem(addr,4)
    return b2i(res)
_MAX_RTT_DATA = 0x3000                # 12kiB maximum RTT data
_TIMEOUT      = 10                    # Stop if we do not find the RTT Control block within 10 sec.
controller : jlinksdk.JLink
dll : ctypes.CDLL
c = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
#[CONFIG-SELECT-START]
c.read(r'D:/Gits/github.com/google/syzkaller/board_manager/config.ini')
#[CONFIG-SELECT-END]
config = c['DEFAULT']
target_TEE = config.get('target_TEE')
config = c[target_TEE]
sleep_sep = config.getfloat('sleep_sep')
generated_payload_root_dir = config.get('generated_payload_root_dir')
payload_log_file_root_dir = config.get('payload_log_file_root_dir')
payload_log = config.getboolean('payload_log_file')
payload_root_dir = config.get('payload_root_dir')
payload_buf_addr = int(config['payload_buf_addr'],16)
payload_size_addr = int(config['payload_size_addr'], 16)
data_event_s_addr = int(config['data_event_s_addr'], 16)
execute_info_s_addr = int(config['execute_info_s_addr'], 16)
state_variable_addr = int(config['state_variables_addr'], 16)
debug_regs = {
    'CFSR' :int(config['CFSR'], 16),
    'DEMCR':int(config['DEMCR'],16),
    'DFSR' :int(config['DFSR'], 16),
    'SFAR' :int(config['SFAR'], 16),
    'SFSR' :int(config['SFSR'], 16),
    'SHCSR':int(config['SHCSR'],16),
    'MMFAR':int(config['MMFAR'],16),
}
arm_regs = {
    'R0' : jlinksdk.ARM_REG.R0,
    'R1' : jlinksdk.ARM_REG.R1,
    'R2' : jlinksdk.ARM_REG.R2,
    'R3' : jlinksdk.ARM_REG.R3,
    'R4' : jlinksdk.ARM_REG.R4,
    'R5' : jlinksdk.ARM_REG.R5,
    'R6' : jlinksdk.ARM_REG.R6,
    'R7' : jlinksdk.ARM_REG.R7,
    'R8' : jlinksdk.ARM_REG.R8,
    'R9' : jlinksdk.ARM_REG.R9,
    'R10' : jlinksdk.ARM_REG.R10,
    'R11' : jlinksdk.ARM_REG.R11,
    'R12' : jlinksdk.ARM_REG.R12,
    'R13 (SP)' : jlinksdk.ARM_REG.R13,
    'R14 (LR)' : jlinksdk.ARM_REG.R14,
    'R15 (PC)' : jlinksdk.ARM_REG.R15,

}


fuzzing_event = threading.Event()
reading_event = threading.Event()
#/*********************************************************************
#*
#*       _Error()
#*
#*  Function description
#*    Called when an error occurs while using RTT.
#*    Makes sure we do stop RTT and exit on Error.
#*/
def _Error(sErr):
    print("ERROR: " + sErr)
    controller.RTTERMINAL_Stop()
    sys.exit(-1)

#/*********************************************************************
#*
#*       _RTTHandleStart()
#*
#*  Function description
#*    Starts RTT.
#*/
def _RTTHandleStart(jlink):
    jlink.RTTERMINAL_Start()
    #
    # Wait for the control block to be detected...
    #
    t = time.time() + _TIMEOUT
    while 1:
        NumBuf = jlink.RTTERMINAL_GetNumBuf(jlinksdk.RTTERMINAL_BUFFER_DIR.UP)
        if NumBuf != None:  # CB found? => Done.
            break
        if t - time.time() < 0:
            raise Exception("Could not find RTT Control Block.")
        time.sleep(0.1)
    #
    # Print the description of the buffer
    #
    print("NumBuffersTotal: %d" % NumBuf)
    for Index in range(0, NumBuf-1):
        desc = jlink.RTTERMINAL_GetDesc(Index, jlinksdk.RTTERMINAL_BUFFER_DIR.UP)
        if desc.SizeOfBuffer != 0:
            print("Index:         %i" % Index)
            print("Buffer Name:   %s" % desc.sName)
            print("Buffer Size:   %d" % desc.SizeOfBuffer)
            print("Buffer Flags:  %d" % desc.Flags)

#/*********************************************************************
#*
#*       _RTTHandleReadPrint()
#*
#*  Function description
#*    Start reading data until we do not receive data anymore for 0.5 sec. or
#*    until _MAX_RTT_DATA is reached
#*/
def _RTTHandleReadPrint(jlink):
    sData = ""
    NumBytesReadTotal = 0
    NumBytesRead      = 1    # Make sure we enter while loop
    while NumBytesRead > 0:
        s    = jlink.RTTERMINAL_Read(0, 0x100)
        NumBytesRead = len(s)
        if NumBytesRead < 0:
            _Error("Failed to read RTT data from target")
        sData             += s[0:NumBytesRead].decode("utf-8")
        NumBytesReadTotal += NumBytesRead
        #
        # Show kb read
        #
        sys.stdout.write("\r" + '{:15}'.format("Data read:") + "%8.4fkB" % (NumBytesReadTotal / 1000))
        sys.stdout.flush()
        if NumBytesReadTotal >= _MAX_RTT_DATA: # Maximum reached? => We are done.
            sys.stdout.write("\nMaximum of %d bytes reached" % _MAX_RTT_DATA)
            break
        time.sleep(0.5)        # Sleep 500 ms to give target some time to write more data
    #
    # Print data if any
    #
    print("")    # Line break
    if NumBytesReadTotal >= 0:
        print("--- Data ---")
        print(sData)

#/*********************************************************************
#*
#*       _RTTHandleWriteData()
#*
#*  Function description
#*    Write a string to the target via RTT
#*/
def _RTTHandleWriteData(jlink):
    x = input("String to send to target: ")
    if x == "":
        x = '\n'
    x = x.encode("utf-8")  # Convert string to an utf-8 byte object.
    NumBytesWritten = jlink.RTTERMINAL_Write(0, x, len(x))
    if NumBytesWritten < 0:
        _Error("Failed to write RTT data to target")
    print("NumBytesWritten = %d" % NumBytesWritten)



def connectM2351(_jlink):
    global controller
    global dll
    dll = jlinksdk.GetCDLLInst()
    if config.getboolean('api_log'):
        dll.JLINKARM_SetLogFile(ctypes.c_char_p(config.get('logfile').encode('utf8')))
    controller = _jlink
    controller.Exec(config.get('scriptfile'))
    host_if = jlinksdk.HOST_IF.USB
    serial_number = config.getint('serial_number')
    _jlink.Open(HostIF=host_if, SN=serial_number)
    s_device = config.get('target_device')
    tif = jlinksdk.TIF.SWD
    speed = config.getint('speed')
    _jlink.Connect(sDevice=s_device, TIF=tif, TIFSpeed=speed)
    _RTTHandleStart(_jlink)

def _set_register(name,value):
    """ update the origin-value at debug[name] -> origin-value | value

    :param name:
    :param value:
    :return:
    """
    name = name.upper()
    for _reg_name in debug_regs:
        if _reg_name == name:
            cr = controller.ReadMem(debug_regs[_reg_name], 4)
            val = struct.unpack('<I', cr[1])[0]
            val |= value
            print(f'Set {_reg_name}(at {hex(debug_regs[_reg_name])}) -> {hex(val)}')
            controller.WriteMemU32(debug_regs[_reg_name],val)

def _check_register(name):
    """ read, print and return registers' values according to their name

    :param name:
    :return:
    """
    name = name.upper()
    for _reg_name in debug_regs:
        if _reg_name == name:
            _, a = controller.ReadMem(debug_regs[_reg_name], 4)
            a = struct.unpack('<I',a)
            a = hex(a[0])
            print(f'{_reg_name} = {a}')
            return f'{_reg_name} = {a}'

def infer_handler(funcname, args, history_info):
    # arg: [arg name, arg value, offsets(strings to fill)]
    # history_info : funcname -> [args, ]
    # infer-> [arg name, arg value, possible offsets]
    split_state = {} # raw bytes -> occurence
    for ind,arg in enumerate(args):
        controller.WriteMemU32(payload_buf_addr + 4*ind, arg[1])
    controller.WriteMemU32(payload_size_addr, 0xcafebabe) # start handler inferring
    time.sleep(1)
    state_num = read_int(state_variable_addr)
    assert state_num == 1
    state_ptr = read_int(state_variable_addr + 8)
    state_size = read_int(state_ptr - 4) & 0xfffffff8
    _, state_raw = controller.ReadMem(state_ptr, state_size)
    tmp_state = state_raw
    while len(tmp_state) > 0:
        tmp_4bytes = tmp_state[:4]
        split_state.setdefault(tmp_4bytes,0)
        split_state[tmp_4bytes] += 1
        tmp_state= tmp_state[4:]
    for tmp_4bytes_offset in range(0,len(state_raw),4):
        for arg in args:
            arg_4bytes = struct.pack('<i',arg[1])
            if split_state.get(arg_4bytes,0) == 1 and arg_4bytes == state_raw[tmp_4bytes_offset:tmp_4bytes_offset+4]:
                arg.append(f'[{tmp_4bytes_offset:2d}:{tmp_4bytes_offset+3:2d}]')
    history_info.setdefault(funcname,[])
    history_info[funcname].append(copy.deepcopy(args))

class RTThreading(threading.Thread):
    conti = True
    current_ind = 0
    bps = {}
    panic_files = []
    success_files = []
    hardfault_files = []
    tmp_addr2line = '' #using addr2line
    def __init__(self,jlink:jlinksdk.JLink,attr):
        threading.Thread.__init__(self)
        self.jlink = jlink
        self.attr = attr
        self.payload_log_file = None
    def external_log_write(self,info):
        if self.payload_log_file is not None:
            print(info,file=self.payload_log_file)
    def run(self) -> None:
        try:
            if self.attr == 'out':
                if payload_log and __name__ != '__main__':
                    self.payload_log_file = open(f'{payload_log_file_root_dir}temp_result.txt', 'w', encoding='utf8')
                while RTThreading.conti:
                    readin = self.jlink.RTTERMINAL_Read(0,0x1000)
                    readin_num = len(readin)
                    if readin_num > 0:
                        data = readin[0:readin_num]
                        if payload_log and __name__ != '__main__':
                            data = data.decode('utf8')
                            print(data, file =self.payload_log_file)
                            self.payload_log_file.flush()
                        else:
                            try:
                                data = data.decode('utf8')
                                RTThreading.tmp_addr2line += data
                                if '[PANIC]' in data:
                                    RTThreading.panic_files.append(RTThreading.current_ind)
                                print(data,end='')
                                if '[CRASH]' in data : #####
                                    time.sleep(1)
                                    if '[PANIC]' not in data:
                                        RTThreading.hardfault_files.append(RTThreading.current_ind)
                                    fuzzing_event.set()
                                if '[SUCCESS]' in data:
                                    RTThreading.success_files.append(RTThreading.current_ind)
                                    time.sleep(1)
                                    fuzzing_event.set()
                            except UnicodeDecodeError:
                                print(f'decode err, raw data = {data}',end='')
                    time.sleep(sleep_sep)
                if payload_log and __name__ != '__main__':
                    self.payload_log_file.close()
                    self.payload_log_file = None
            elif self.attr == 'debug':
                while RTThreading.conti:
                    x = input('Command:')
                    try:
                        if len(x) <1:
                            continue
                        elif x.startswith('check'):
                            command = x.split()
                            if command[1].upper().startswith('ADDRESS'):
                                controller.WriteMemU32(payload_size_addr,0xbadef00d)
                    except KeyboardInterrupt:
                        print('keyboard ctrl+c.')
                    except Exception as e:
                        traceback.print_exc()
        except Exception as e:
            RTThreading.conti = False
            traceback.print_exc()
            return

class JLINKARM_DATA_EVENT(ctypes.Structure):
    _fields_ = [
        ('SizeOfStruct',ctypes.c_int),
        ('Type',ctypes.c_int),
        ('Addr',ctypes.c_uint32),
        ('AddrMask',ctypes.c_uint32),
        ('Data',ctypes.c_uint32),
        ('DataMask',ctypes.c_uint32),
        ('Access',ctypes.c_uint8),
        ('AccessMask',ctypes.c_uint8),
    ]
    JLINKARM_EVENT_TYPE_DATA_BP = 1 << 0

    JLINKARM_EVENT_ERR_UNKNOWN = 0x80000000
    JLINKARM_EVENT_ERR_NO_MORE_EVENTS = 0x80000001
    JLINKARM_EVENT_ERR_NO_MORE_ADDR_COMP = 0x80000002
    JLINKARM_EVENT_ERR_NO_MORE_DATA_COMP = 0x80000004
    JLINKARM_EVENT_ERR_INVALID_ADDR_MASK = 0x80000020
    JLINKARM_EVENT_ERR_INVALID_DATA_MASK = 0x80000040
    JLINKARM_EVENT_ERR_INVALID_ACCESS_MASK = 0x80000080

    JLINK_EVENT_HANDLE_ALL = 0xFFFFFFFF

    JLINK_EVENT_DATA_BP_DIR_RD = 0 << 0
    JLINK_EVENT_DATA_BP_DIR_WR = 1 << 0
    JLINK_EVENT_DATA_BP_PRIV = 1 << 4
    JLINK_EVENT_DATA_BP_SIZE_8BIT = 0 << 1
    JLINK_EVENT_DATA_BP_SIZE_16BIT = 1 << 1
    JLINK_EVENT_DATA_BP_SIZE_32BIT = 2 << 1

    JLINK_EVENT_DATA_BP_MASK_SIZE = 3 << 1
    JLINK_EVENT_DATA_BP_MASK_DIR = 1 << 0
    JLINK_EVENT_DATA_BP_MASK_PRIV = 1 << 4

if __name__ == '__main__':
    try:
        jlink = jlinksdk.JLink()
        print("DLL Version: %s" % jlink.GetDllVersionString())
        connectM2351(jlink)
        RTTOut = RTThreading(controller, 'out')
        time.sleep(0.1)
        rtt_debug = RTThreading(controller, 'debug')
        RTTOut.start()
        rtt_debug.start()
        time.sleep(0.1)

        rtt_debug.join()
    except:
        traceback.print_exc()
    input('Press Enter to Exit')
    controller.RTTERMINAL_Stop()
    controller.Close()
    exit(0)
"""RTT Control Block 0x30010be8 (Non-Secure)
SEGGER_RTT_CB
    char                    acID[16];                                 0x30010be8// Initialized to "SEGGER RTT"
    int                     MaxNumUpBuffers;                          0x30010bf8// Initialized to SEGGER_RTT_MAX_NUM_UP_BUFFERS (type. 2)
    int                     MaxNumDownBuffers;                        0x30010bfc// Initialized to SEGGER_RTT_MAX_NUM_DOWN_BUFFERS (type. 2)
    SEGGER_RTT_BUFFER_UP    aUp[SEGGER_RTT_MAX_NUM_UP_BUFFERS];       0x30010c00
          const     char*    sName;                                   0x30010c00// Optional name. Standard names so far are: "Terminal", "SysView", "J-Scope_t4i4"
          char*    pBuffer;                                           0x30010c04// Pointer to start of buffer
          unsigned SizeOfBuffer;                                      0x30010c08// Buffer size in bytes. Note that one byte is lost, as this implementation does not fill up the buffer in order to avoid the problem of being unable to distinguish between full and empty.
          unsigned WrOff;                                             0x30010c0c// Position of next item to be written by either target.
          volatile  unsigned RdOff;                                   0x30010c10// Position of next item to be read by host. Must be volatile since it may be modified by host.
          unsigned Flags;                                             0x30010c14// Contains configuration flags
    SEGGER_RTT_BUFFER_DOWN  aDown[SEGGER_RTT_MAX_NUM_DOWN_BUFFERS];   0x30010c48

RTT Control Block 0x200025b0 (Secure)
SEGGER_RTT_CB
    char                    acID[16];                                 0x200025b0// Initialized to "SEGGER RTT"
    int                     MaxNumUpBuffers;                          0x200025c0// Initialized to SEGGER_RTT_MAX_NUM_UP_BUFFERS (type. 2)
    int                     MaxNumDownBuffers;                        0x200025c4// Initialized to SEGGER_RTT_MAX_NUM_DOWN_BUFFERS (type. 2)
    SEGGER_RTT_BUFFER_UP    aUp[SEGGER_RTT_MAX_NUM_UP_BUFFERS];       0x200025c8
          const     char*    sName;                                   0x200025c8// Optional name. Standard names so far are: "Terminal", "SysView", "J-Scope_t4i4"
          char*    pBuffer;                                           0x200025cc// Pointer to start of buffer
          unsigned SizeOfBuffer;                                      0x200025d0// Buffer size in bytes. Note that one byte is lost, as this implementation does not fill up the buffer in order to avoid the problem of being unable to distinguish between full and empty.
          unsigned WrOff;                                             0x200025d4// Position of next item to be written by either target.
          volatile  unsigned RdOff;                                   0x200025d8// Position of next item to be read by host. Must be volatile since it may be modified by host.
          unsigned Flags;                                             0x200025dc// Contains configuration flags
    SEGGER_RTT_BUFFER_DOWN  aDown[SEGGER_RTT_MAX_NUM_DOWN_BUFFERS];   

"""