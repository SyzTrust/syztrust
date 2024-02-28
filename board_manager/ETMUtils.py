import os
import socket
import time
import struct
import traceback
import queue
import jlinksdk
import datetime
import configparser
import threading
import TimingUtils
cur_trace_id = b'\x00'

def i2b(x):
    return struct.pack('B',x)
c = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())

#[CONFIG-SELECT-START]
c.read(r'D:/Gits/github.com/google/syzkaller/board_manager/config.ini')
#[CONFIG-SELECT-END]
config = c['DEFAULT']
target_TEE = config.get('target_TEE')
config = c[target_TEE]
sleep_sep = config.getfloat('sleep_sep')
payload_timeout_cnt = config.getint('payload_timeout_cnt')
parse_delete = config.getboolean('parse_delete')
branch_log = config.getboolean('branch_log_file')
class Const:
    alternative = 'alternative'
    thumb = 'thumb'
    thumbee = 'thumbee'
    hypervisor = 'hypervisor'
    original = 'original'

class State:
    decode_error = False
    def __init__(self):
        self.cycle_accurate_mode = False
        self.handling_exception = False
        self.processor_in_non_secure_mode = False
        self.prev_branch = 0
        self.base_address = 0
        self.ne_atoms_num = 0
        self.context_id = 0
        self.context_id_size = 0
        self.exit_status = 0
        self.processor_state = ''
        self.branch_encoding_scheme = Const.alternative
        # debug
        self.file = None
        self.coverage = b'' # for coverage files
        self.raw_cov = [] # backup raw result
state : State

dedup_table_size = 8 << 10
dedup_table = [0] * dedup_table_size


def _dedup(sig):
    """Poorman's best-effort hashmap-based deduplication.
    The hashmap is global which means that we deduplicate across different calls.
    This is OK because we are interested only in new signals.

    :param sig:
    :return:
    """
    global dedup_table
    for i in range(4):
        pos = (sig + i) % dedup_table_size
        if dedup_table[pos] == sig:
            return True
        if dedup_table[pos] == 0:
            dedup_table[pos] = sig
            return False
    dedup_table[sig % dedup_table_size] = sig
    return False

def _hash(a):
    a = (a ^ 61) ^ (a >> 16)
    a = a + (a << 3)
    a = a ^ (a >> 4)
    a = a * 0x27d4eb2d
    a = a ^ (a >> 15)
    a &= 0xFFFFFFFF # uint32
    return a

def _coverage_filter(pc):
    return True

def _mix(x):
    x ^= x >> 23
    x *= 0x2127599bf4325c37
    x ^= x >> 47
    return x & 0xFFFFFFFFFFFFFFFF # uint64

def _syz_hash32(a,b,seed=0xdeadbeef):
    h = _syz_hash64(a,b,seed)
    return (h - (h >> 32)) & 0xFFFFFFFF

def _syz_hash64(a,b,seed=0xdeadbeef):
    m = 0x880355f21e6d1965
    h = seed ^ (b * m)
    h ^= _mix(a)
    h *= m
    x = (a >> b) | (a << (32-b))
    v = 0
    b &= 7
    for i in range(b,0,-1):
        v ^= (x & (0xFF << ((i-1)*8)))
    h ^= _mix(v)
    h *= m
    return _mix(h)
def cov_hash(a,b):
    b &= 0x1F
    return _syz_hash32(a,b)

def get_covs(raw_cov:list):
    covs = b''
    new_covs = sorted(list(set(raw_cov)))
    for cov in new_covs:
        covs += struct.pack('<I',cov)
    return covs

def get_sigs(raw_cov:list):
    sigs = b''
    prev_pc = 0
    prev_filter = True
    for pc in raw_cov:
        sig = pc
        sig ^= _hash(prev_pc) # do this if use_cover_edges(pc). always true in 32-bit
        _filter = _coverage_filter(pc)
        ignore = (not _filter) and (not prev_filter)
        prev_pc = pc
        prev_filter = _filter
        if ignore or _dedup(sig):
            continue
        try:
            sigs += struct.pack('<I',sig)
        except:
            traceback.print_exc()
    return sigs

class ParserSync:
    def __init__(self, filename:str, controller:jlinksdk.JLink):
        self.filename = filename
        self.controller = controller
        self.branch_file_name = filename.replace('_0000.bin', '.txt').replace('TraceFile', 'BranchFile')

    def parse(self):
        global state
        state = State()
        cnt = payload_timeout_cnt
        while not os.path.exists(self.filename) and cnt > 0:
            cnt -= 1
            time.sleep(sleep_sep)
        if cnt <= 0:
            print(f'\033[31mTimeout but not found {self.filename}.\033[0m')
            State.decode_error = True
            return b'',b''
        # not parse large trace file
        filesize = os.path.getsize(self.filename) // (1024*1024) # MB
        if filesize >= 2: # not parse files larger than 2MB, not delete them
            print(f'\033[31mDrop {filesize}MB tracefile.\033[0m')
            State.decode_error = True
            return b'',b''
        if branch_log:
            state.file = open(self.branch_file_name, 'w', encoding='utf8')
        TimingUtils.update_timestamp(TimingUtils.Timing.tracefile_decode_index)
        try:
            parse_raw(self.filename,self.controller)
        except:
            traceback.print_exc()
            State.decode_error = True
            return b'',b''
        TimingUtils.update_total(TimingUtils.Timing.tracefile_decode_index)
        if branch_log:
            state.file.close()

        # remove .bin files
        if parse_delete:
            os.remove(self.filename)
        state.raw_cov = state.raw_cov[1:]
        return get_sigs(state.raw_cov),get_covs(state.raw_cov)


class ParserAsync(threading.Thread):
    def __init__(self,all_sigs:list,all_covs:list,controller:jlinksdk.JLink):
        threading.Thread.__init__(self)
        self.all_sigs = all_sigs
        self.all_covs = all_covs
        self.enqueue_done = False
        self.trace_queue = queue.Queue(maxsize=20)
        self.controller = controller
    def enqueue_tracefile(self,trace_file:str):
        self.trace_queue.put_nowait(trace_file)
        # debug(f'enqueue {trace_file}, size = {self.trace_queue.qsize()}',-1)
    def run(self) -> None:
        while not self.enqueue_done:
            if not self.trace_queue.empty():
                trace_file = self.trace_queue.get()
                self.parse(trace_file)
                self.trace_queue.task_done()
        while not self.trace_queue.empty():
            trace_file = self.trace_queue.get()
            self.parse(trace_file)
            self.trace_queue.task_done()

    def parse(self,trace_file):
        global state
        state = State()
        cnt = payload_timeout_cnt
        # debug(f'parse {trace_file}',level=-1)
        while not os.path.exists(trace_file) and cnt > 0:
            cnt -= 1
            time.sleep(sleep_sep)
        if cnt <= 0:
            State.decode_error = True
            print(f'\033[31mTimeout but not found {trace_file}.\033[0m')
            self.all_sigs.append(b'')
            self.all_covs.append(b'')
            return
        # TODO not parse large trace file
        filesize = os.path.getsize(trace_file) // (1024*1024) # MB
        if filesize >= 2: # not parse files larger than 2MB, but not delete them
            State.decode_error = True
            print(f'\033[31mDrop {filesize}MB tracefile.\033[0m')
            self.all_sigs.append(b'')
            self.all_covs.append(b'')
            return
        if branch_log:
            branch_file_name = trace_file.replace('_0000.bin', '.txt').replace('TraceFile', 'BranchFile')
            state.file = open(branch_file_name, 'w', encoding='utf8')
        parse_raw(trace_file,self.controller)
        if branch_log:
            state.file.close()
        # remove .bin files
        if parse_delete:
            os.remove(trace_file)
        self.all_sigs.append(get_sigs(state.raw_cov))
        self.all_covs.append(get_covs(state.raw_cov))

def add_cov(addr):
    state.coverage += struct.pack('<I', addr)
    state.raw_cov.append(addr)

def debug(info, level = 1):
    global state

    if branch_log:
        print(info,file=state.file)
    if level < 4:
        return
    if level == 1:
        print(f'[debug log - {level}] {info}')
    elif level == 2:
        print(f'\033[32m[debug log - {level}] {info}\033[0m')
    elif level == 3:
        print(f'\033[33m[debug log - {level}] {info}\033[0m')
    elif level == 4:
        print(f'\033[31m[debug log - {level}] {info}\033[0m')

def parse_error(*info):
    print(f'\033[31m[error log] ',*info,'\033[0m')
    State.decode_error = True

def parse_tpiu_packet(packet, trace_id):
    global cur_trace_id
    res = b''
    final_byte = packet[-1]
    for i in range(7):
        byte_a = packet[i << 1]
        byte_b = packet[(i << 1) + 1]
        if byte_a & 1 == 1:
            # trace source is changed, byte_a is ID
            if (final_byte >> i) & 1 == 1:
                # second byte corresponds to the previous ID
                if cur_trace_id == trace_id:
                    res += i2b(byte_b)
                cur_trace_id = i2b(byte_a >> 1)
            else:
                # second byte corresponds to the new ID
                cur_trace_id = i2b(byte_a >> 1)
                if cur_trace_id == trace_id:
                    res += i2b(byte_b)
        else:
            # trace source is not changed, byte_a is Data
            if cur_trace_id == trace_id:
                res += i2b((byte_a & 0xFE) | ((final_byte >> i) & 1)) + i2b(byte_b)
    byte_a = packet[-2]
    if byte_a & 1 == 1:
        cur_trace_id = i2b(byte_a >> 1)
    else:
        if cur_trace_id == trace_id:
            res += i2b((byte_a & 0xFE) | ((final_byte >> 7) & 1))
    return res

def extract_etm_from_tpiu_file(tpiu_filename):
    packet_sep = b'\xff\xff\xff\x7f'
    etm = b''
    with open(tpiu_filename, 'rb') as f:
        while True:
            buffer4 = f.read(4)
            if len(buffer4) < 4:
                break
            if buffer4 == packet_sep:
                continue
            packet = buffer4 + f.read(12)
            if len(packet) < 16:
                break
            etm += parse_tpiu_packet(packet, b'\x10')
    return etm

def decode_raw_etm(raw_data:bytes,controller:jlinksdk.JLink):
    def from_branch(address):
        debug(f'not support from branch {address} now.',4)
        return False
        
    def record_branch(branch_info, bits):
        """Handling coverage information for fuzzing

        """
        add_cov(cov_hash(state.prev_branch,state.ne_atoms_num))
        state.ne_atoms_num = 0
        state.prev_branch = (state.base_address >> bits << bits) | branch_info
        return
    def decode_branch_address(index, data, size):
        """ No header. : bCxxxxxx1 C=another byte follows
        Branch packets are used to indicate the destination address of indirect branches. Branch packets are also
        used to give information on exceptions, and to indicate changes of the instruction set state or security
        state of the processor.\n
        If an instruction that causes an indirect branch is traced, a Branch address packet must be output even if the
        target of the branch is not traced, unless prevented by a FIFO overflow. This enables the address of the first
        instruction in any trace gap to be determined.\n
        Multiple branch packets can be output for a single instruction. If this happens, each must be interpreted in
        turn in relation to the previous branch packet, after which all but the final branch packet must be ignored.\n
        In cycle-accurate mode, the branch might not be traced on the same cycle as the instruction.\n
        A branch packet consists of a maximum of five Address Bytes, optionally followed by up to three Exception Information Bytes.
        The Address Bytes indicate: \n
        • the branch target address
        • the alignment of the instruction set, for example word, halfword or byte alignment
        • whether any Exception Information bytes follow.
        The Exception Information Bytes indicate:\n
        • additional information about the instruction set
        • the security state
        • the hypervisor mode
        • when exceptions occur.
        """
        debug(f'decoding branch address: data[{index}]')
        bytes_taken_in = 0
        address_info = 0
        address_byte = 0
        if state.branch_encoding_scheme == Const.alternative:
            for address_bytes_index in range(4):
                try:
                    address_byte = data[index+address_bytes_index]
                except IndexError:
                    parse_error('index out of range in decoding branch address')
                bytes_taken_in += 1
                if ((address_byte >> 7) & 1) == 1: # more bytes
                    if address_bytes_index == 0:
                        address_info |= address_byte & 0x7E # Address[6:1]
                    else:
                        address_info |= (address_byte & 0x7F) << (7 * address_bytes_index) # Address[7x+6:7x]
                else: # final address byte [0:4)
                    if address_bytes_index == 0:
                        address_info |= address_byte & 0x7E # Address[6:1]
                        record_branch(address_info, 7)
                        return  bytes_taken_in
                    else:
                        address_info |= (address_byte & 0x3F) << (7 * address_bytes_index) # Address[7x+5:7x]
                        diff_bits = 6 + 7 * address_bytes_index
                        break
            else: # address bytes 4
                address_byte = data[index+bytes_taken_in]
                bytes_taken_in += 1
                address_info |= (address_byte & 0xF) << 28
                diff_bits = 32
            # Check exception bytes
            exception_info = 0
            resume = 0
            if ((address_byte >> 6) & 1) == 1: # contains exception bytes
                exception_byte = data[index+bytes_taken_in] # exception bytes 0
                bytes_taken_in += 1
                state.handling_exception = True
                # Exception byte 0 : C | Alt | Can | Exception[3:0] | NS
                state.processor_in_non_secure_mode = True if (exception_byte & 1) == 1 else False
                exception_info |= (exception_byte & 0x1E) >> 1
                if ((exception_byte >> 5) & 1) == 1: # Can = 1
                    state.ne_atoms_num -= 1
                if ((exception_byte >> 6) & 1) == 1: # Alt = 1
                    state.processor_state = Const.thumbee
                if ((exception_byte >> 7) & 1) == 1: # contains more exception bytes
                    exception_byte = data[index+bytes_taken_in]
                    bytes_taken_in += 1
                    if ((exception_byte >> 7) & 1) == 1:  # contains exception bytes 1 and 2
                        exception_info |= (exception_byte & 0x1F) << 4
                        if ((exception_byte >> 5) & 1) == 1:  # Hyp = 1
                            state.processor_state = Const.hypervisor  # ETMv3.5, otherwise SBZ
                        exception_byte = data[index + bytes_taken_in]
                        bytes_taken_in += 1
                        resume = exception_byte & 0xF
                    elif (exception_byte >> 6) == 0: # only exception bytes 0 and 1
                        # Exception byte 1 :0 0 | Hyp mode | Exception[8:4]
                        exception_info |= (exception_byte & 0x1F) << 4
                        if ((exception_byte >> 5) & 1) == 1: # Hyp = 1
                            state.processor_state = Const.hypervisor # ETMv3.5, otherwise SBZ
                    elif (exception_byte >> 6) == 1: # only exception bytes 0 and 2
                        resume = exception_byte & 0xF
            if not state.handling_exception: 
                if state.exit_status == 2:
                    tmp_addr = (state.base_address >> diff_bits << diff_bits) | address_info
                    if from_branch(tmp_addr):
                        record_branch(address_info,diff_bits)
                    state.exit_status-=1
                elif state.exit_status == 1:
                    record_branch(address_info, diff_bits)
                    state.exit_status-=1
                else:
                    record_branch(address_info, diff_bits)
            # Update address
            state.base_address = (state.base_address >> diff_bits << diff_bits) | address_info
            return  bytes_taken_in
        elif state.branch_encoding_scheme == Const.original:
            parse_error('original branch encoding scheme has been deprecated')
        else :
            parse_error('no suitable branch encdoing scheme')
    def decode_a_sync(index,data, size):
        """ Alignment synchroniztion : b00000000
        Periodically a sequence of five or more A-sync P-headers, b0000 0000, are output, followed by the binary value
        b1000 0000. This is equivalent to a string of 47 or more 0 bits followed by a 1.\n
        To synchronize, the decompressor must search for this sequence, that cannot occur in any other way. While trace
        capture devices are usually byte-aligned, this might not be the case for sub-byte ports. Therefore, the decompressor
        must realign all data following the A-sync sequence if required.\n
        The next byte is a header, that can be of any type.
        """
        debug(f'decoding A-Sync : data[{index}]')
        bytes_taken_in = 0
        # at least 5 bytes of 0
        for i in range(5):
            bytes_taken_in += 1
            if i+index < size:
                if data[i+index] != 0:
                    parse_error(f'Decode A-sync error: data[{i + index}] = {data[i + index]}, shoud be 0')
            else:
                return  bytes_taken_in
        # take in more 0s
        while bytes_taken_in + index < size:
            if data[bytes_taken_in+index] == 0:
                bytes_taken_in+=1
            else:
                break
        else:
            return bytes_taken_in
        # must follow by 1
        if data[bytes_taken_in+index] != 0b1000_0000:
            parse_error(f'Decode A-sync error: data[{bytes_taken_in + index}] = {data[bytes_taken_in + index]}, shoud be 0x80')
        bytes_taken_in += 1
        return bytes_taken_in
    # def decode_cycle_count(index, data, size):
    #     """ 1 to (2^32 - 1) x W : b00000100
    #
    #     """
    #     bytes_taken_in = 0
    #
    #     debug(f'decoding Cycle count : data[{index}]')
    #     bytes_taken_in += 1
    #     return bytes_taken_in
    def decode_i_sync(index, data, size):
        """ Instruction flow synchronization b00001000
        When the decompressor finds an A-sync sequence, it must search for an I-sync packet. This provides synchronization
        of the following parts of the trace:
        • instruction address
        • instruction set state
        • address of previous data instruction, if it is still executing
        • Context ID.
        """
        debug(f'decoding I-Sync : data[{index}]')

        bytes_taken_in = 0
        if not state.cycle_accurate_mode:
            # Normal I-Sync packet
            bytes_taken_in += decode_context_id(index,data,size)
            if bytes_taken_in + index < size:
                # Get information byte
                infomation_byte = data[bytes_taken_in+index]
                if infomation_byte & 0b1000_0001 != 0b0000_0001:
                    parse_error(f'Wrong information byte in I-Sync, index = {index}, byte = {bin(infomation_byte)}')
                state.processor_in_non_secure_mode = True if infomation_byte & 0b0000_1000 != 0 else False
                bytes_taken_in += 1
            else: return bytes_taken_in
            # Get Address
            state.base_address = int.from_bytes(data[index + bytes_taken_in:index + bytes_taken_in + 4], 'little')
            if state.base_address & 1 == 1:
                state.processor_state = 'thumb'
            state.base_address = state.base_address >> 1 << 1 # set T bit be 0
            bytes_taken_in += 4
            return bytes_taken_in
        else:
            parse_error('not support cycle-accurate mode')
    # def decode_trigger(index,data, size):
    #     """ Trigger : b00001100
    #
    #     """
    #     debug(f'decoding Trigger : data[{index}]')
    #     pass
    # def decode_out_of_order_data(index, data, size):
    #     """out-of-order : b0TT0SS00 TT=tag(1-3), SS=data value size
    #
    #     """
    #     debug(f'decoding Out-of-order data : data[{index}]')
    #     pass
    # def decode_store_failed(index, data, size):
    #     """ For use with the STREX instruction : b01010000
    #
    #     """
    #     debug(f'decoding store failed : data[{index}]')
    #
    #
    #     pass
    # def decode_i_sync_with_cycle_count(index, data, size):
    #     """ Sync. : b01110000
    #
    #     """
    #     debug(f'decoding I-Sync with cycle count : data[{index}]')
    #     pass
    # def decode_out_of_order_placeholder(index, data, size):
    #     """ b01A1TT00 TT=tag(1-3) A=Address follows where address tracing is enabled
    #
    #     """
    #     debug(f'decoding Out-of-order-placeholder : data[{index}]')
    #     pass
    def decode_context_id(index, data, size):
        """ b01101110
        When the Context ID changes, a Context ID packet is output to give the new value. It comprises the following components:\n
        • Context ID packet header (1 byte)
        • Context ID (1-4 bytes).
        The number of bytes output depends on the ContextIDSize bits, bits [15:14] of the ETMCR.\n
        The Context ID packet is output: \n
        • after tracing all instructions up to the point where the Context ID is changed
        • before tracing any instructions that are executed with the new Context ID

        """
        debug(f'decoding ContextID : data[{index}]')
        if state.context_id_size == 0:
            return 1
        elif state.context_id_size == 1:
            if index + 1 < size:
                state.context_id = data[index + 1]
            return 2
        elif state.context_id_size == 2:
            if index + 2 < size:
                state.context_id = int.from_bytes(data[index + 1:index + 3], 'little')
            return 3
        elif state.context_id_size == 3:
            if index + 4 < size:
                state.context_id = int.from_bytes(data[index + 1:index + 5], 'little')
            return 5
        else:
            parse_error(f'Invalid value of context id size {state.context_id_size}, please check ETMCR[15:14]')
    def decode_exception_exit(index, data, size):
        """ Tracing return from an exception : b01110110

        """
        debug(f'decoding Exception Exit : data[{index}]')
        state.handling_exception = False
        state.exit_status = 2
        return 1
    # def decode_exception_entry(index, data, size):
    #     """ Automatic stack push on exception entry and pop on excption exit : b01111110
    #
    #     """
    #     debug(f'decoding Exception Entry : data[{index}]')
    #     pass
    def decode_p_header(index, data, size):
        """ b1xxxxxx0. P-headers represent a sequence of Atoms that indicate the execution of instructions
        or Java bytecodes. There are three atom types, as follows:\n
        • E is an instruction that passed its condition codes test
        • N is an instruction that failed its condition codes test
        • W is a cycle boundary, and occurs in cycle-accurate mode only.

        These atoms are mapped onto several P-header encodings for efficient output in the trace.
        Different encodings are, depending on whether cycle-accurate mode is enabled.
        Where cycle-accurate tracing is not required, a more compressible stream can be generated by removing the W atoms.
        """
        debug(f'decoding P-header : data[{index}]')
        p_header = data[index]
        if state.cycle_accurate_mode:
            pass
        else:
            if not state.handling_exception:
                if p_header & 0b1000_0011 == 0b1000_0000: # Format 1 P-header b1NEEEE00
                    state.ne_atoms_num += (p_header >> 2) & 0xF # number of E
                    state.ne_atoms_num += (p_header >> 6) & 1   # number of N
                    debug(f'format 1 P-header: {(p_header >> 2) & 0xf} E and {(p_header >> 6) & 1} N')
                elif p_header & 0b1111_0011 == 0b1000_0010: # Fomat 2 P-header b1000FF10
                    state.ne_atoms_num += 2 
                    debug(f'format 2 P-header: first {(p_header >> 3) & 1} and second {(p_header >> 2) & 1}')
                else:
                    print('Wrong P-header format',bin(p_header),'in non-cycle-accurate mode')
        return 1 # no payload

    data_size = len(raw_data)
    cur_byte_index = 0
    while cur_byte_index < data_size:
        header_description = raw_data[cur_byte_index]
        if header_description & 1 == 1: # Instruction : Branch address
            cur_byte_index += decode_branch_address(cur_byte_index, raw_data, data_size)
        elif header_description == 0: # Sync. : A-sync
            cur_byte_index += decode_a_sync(cur_byte_index,raw_data,data_size)
        # elif header_description == 0b0000_0100: # Instruction : Cycle count
        #     cur_byte_index += decode_cycle_count(cur_byte_index,raw_data,data_size)
        elif header_description == 0b0000_1000: # Sync. : I-sync
            cur_byte_index += decode_i_sync(cur_byte_index,raw_data,data_size)
        # elif header_description == 0b0000_1100: # Trace port : trigger
        #     cur_byte_index += decode_trigger(cur_byte_index,raw_data,data_size)
        # elif (header_description & 0b1001_0011 == 0) and (header_description & 0b0110_0000 > 0): # Data : Out-of-order data
        #     cur_byte_index += decode_out_of_order_data(cur_byte_index,raw_data,data_size)
        # elif header_description == 0b0101_0000: # Data : Store failed
        #     cur_byte_index += decode_store_failed(cur_byte_index,raw_data,data_size)
        # elif header_description == 0b0111_0000: # Sync : I-sync with cycle count
        #     cur_byte_index += decode_i_sync_with_cycle_count(cur_byte_index,raw_data,data_size)
        # elif (header_description & 0b1101_0011 == 0b0101_0000) and (header_description & 0b0000_1100 > 0): # Data : out-of-order placeholder
        #     cur_byte_index += decode_out_of_order_placeholder(cur_byte_index,raw_data,data_size)
        # elif header_description == 0b0110_1110: # Instruction : Context ID
        #     cur_byte_index += decode_context_id(cur_byte_index,raw_data,data_size)
        #     debug(f'current context ID = {hex(state.context_id)}')
        elif header_description == 0b0111_0110: # Instruction : Exception exit
            cur_byte_index += decode_exception_exit(cur_byte_index,raw_data,data_size)
        # elif header_description == 0b0111_1110: # Instruction : Exception entry
        #     cur_byte_index += decode_exception_entry(cur_byte_index, raw_data,data_size)
        elif header_description & 0b1000_0001 == 0b1000_0000: # P-header
            cur_byte_index += decode_p_header(cur_byte_index,raw_data,data_size)
        else:
            parse_error(f'Invalid byte to decode : raw_data[{cur_byte_index}] = {raw_data[cur_byte_index]}')
            cur_byte_index += 1



def parse_raw(raw_tpiu_filename, controller=None):
    if not os.path.exists(raw_tpiu_filename):
        print(f'No such raw data : {raw_tpiu_filename}')
        return
    global cur_trace_id
    cur_trace_id = b'\x00'
    raw_etm = extract_etm_from_tpiu_file(raw_tpiu_filename)
    decode_raw_etm(raw_etm,controller)

if __name__ == '__main__':
    pass