import datetime
import configparser

c = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())

#[CONFIG-SELECT-START]
c.read(r'D:/Gits/github.com/google/syzkaller/board_manager/config.ini')
#[CONFIG-SELECT-END]
config = c['DEFAULT']
target_TEE = config.get('target_TEE')
config = c[target_TEE]
timing = config.getboolean('timing')
payload_log_file_root_dir = config.get('payload_log_file_root_dir')

class Timing:
    index_num = 12
    board_init_index        = 0
    payload_receive_index   = 1
    board_reset_index       = 2
    payload_execute_index   = 3
    payload_copy_index      = 4
    tracefile_config_index  = 5
    syscall_execute_index   = 6
    tracefile_load_index    = 7
    tracefile_decode_index  = 8
    callreply_craft_index   = 9
    callreply_trans_index   = 10
    rtt_log_collect_index   = 11

    timestamps = [datetime.datetime.now()] * index_num
    timetotal = [datetime.timedelta(0)] * index_num
    hints = [
        'Init board : ',
        'Receive payload at : ',
        'Board reset costs : ',
        'Payload execution : ',
        'Payload copy to board : ',
        'Halt and config tracefile : ',
        'Syscall and tracefile total : ',
        'Tracefile load total : ',
        'Decode tracefile total : ',
        'CallReply craft : ',
        'CallReply trans : ',
        'RTT log collect : ',
    ]


def update_timestamp(index:int):
    if not timing: return
    Timing.timestamps[index] = datetime.datetime.now()

def update_total(index:int):
    if not timing: return
    cur = datetime.datetime.now()
    Timing.timetotal[index] += cur - Timing.timestamps[index]

def get_time_log():
    if not timing: return ''
    result =  f'{Timing.hints[Timing.payload_receive_index]}{Timing.timestamps[Timing.payload_receive_index].strftime("%Y-%m-%d %H:%M:%S.%f")}\n' \
              f'{Timing.hints[Timing.board_reset_index]}{Timing.timetotal[Timing.board_reset_index]}\n' \
              f'{Timing.hints[Timing.payload_execute_index]}{Timing.timetotal[Timing.payload_execute_index]}\n' \
              f'{Timing.hints[Timing.payload_copy_index]}{Timing.timetotal[Timing.payload_copy_index]}\n' \
              f'{Timing.hints[Timing.tracefile_config_index]}{Timing.timetotal[Timing.tracefile_config_index]}\n' \
              f'{Timing.hints[Timing.syscall_execute_index]}{Timing.timetotal[Timing.syscall_execute_index]}\n' \
              f'{Timing.hints[Timing.tracefile_load_index]}{Timing.timetotal[Timing.tracefile_load_index]}\n' \
              f'{Timing.hints[Timing.tracefile_decode_index]}{Timing.timetotal[Timing.tracefile_decode_index]}\n' \
              f'{Timing.hints[Timing.callreply_craft_index]}{Timing.timetotal[Timing.callreply_craft_index]}\n' \
              f'{Timing.hints[Timing.callreply_trans_index]}{Timing.timetotal[Timing.callreply_trans_index]}\n' \
              f'{Timing.hints[Timing.rtt_log_collect_index]}{Timing.timetotal[Timing.rtt_log_collect_index]}\n'
    Timing.timetotal = [datetime.timedelta(0)] * Timing.index_num
    return result
