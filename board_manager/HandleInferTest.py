import configparser
import os
import datetime
import pprint
import re
import math
import functools
import pickle
import struct
import numpy as np
# raw_data = r'D:\ExpData\20221027-FStategoolddivision\raw data'
raw_data = r'D:\ExpData\20221114-mode6-TinyTEE\raw data'
filepath = os.path.join(raw_data,'sig_cov_states')
objPath = os.path.join(raw_data,'obj.txt')
opPath = os.path.join(raw_data,'op.txt')

def calculate_entropy(_number_list:list,_entropy_type=2):
    number_num = len(_number_list)
    number_sum = sum(_number_list)
    number_dict = {}
    for number in _number_list:
        number_dict.setdefault(number,0)
        number_dict[number] += 1
    if _entropy_type == 1:
        return abs(sum(map(lambda x:-x/number_num * math.log2(x/number_num),number_dict.values())))
    elif _entropy_type == 2:
        return np.var(_number_list)
    else:
        return 0

def split_number(_raw_handler,_start_index,_width):
    final_byte_index = (_start_index+_width-1) * 2
    if final_byte_index < 0:
        return 0
    res = ''
    for _ in range(_width):
        res += _raw_handler[final_byte_index:final_byte_index+2]
        final_byte_index-=2
    return int(res,16)

def SaveHandlesHexToFile(filepath, handles):
    with open(filepath,"w") as fp:
        for item in handles:
            s = ''.join('{:02x}'.format(x) for x in item)
            fp.write(s)
            fp.write('\n')

def generate_handlers_file(_states_number,_handle_size,_dedup=True):
    if _dedup:
        objecthandles = set()
        operationhandles = set()
    else:
        objecthandles = []
        operationhandles = []
    len_objh = set()
    len_oph = set()
    for i in range(_states_number):
        filename = os.path.join(filepath,"state-"+str(i + 1) + ".txt")
        try:
            with open(filename, 'rb') as statefile:
                datas = statefile.read()
                data = datas.split(b'[end]\n')
                for line in data:
                    if b'Syscall' in line:
                        index = line.find(b'[OperationHandle Start]:')
                        index2 = line.find(b'[ObjectHandle Start]:')
                        if index != -1:
                            num_oph = int(chr(line[index + 24]))
                            if num_oph > 0:
                                ophs = line[index + 25:index2].split(b'[syztrust]')
                                for j in range(num_oph):
                                    if len(ophs[j]) != _handle_size:
                                        pass
                                    else:
                                        if _dedup:
                                            operationhandles.add(ophs[j])
                                        else:
                                            operationhandles.append(ophs[j])
                                        len_oph.add(len(ophs[j]))
                        if index2 != -1:
                            num_objh = int(chr(line[index2 + 21]))
                            if num_objh > 0:
                                objhs = line[index2 + 22:].split(b'[syztrust]')
                                for j in range(num_objh):
                                    if len(objhs[j]) != _handle_size:
                                        pass
                                    else:
                                        if _dedup:
                                            objecthandles.add(objhs[j])
                                        else:
                                            objecthandles.append(objhs[j])
                                        len_objh.add(len(objhs[j]))
        except FileNotFoundError:
            pass
        except Exception as e:
            print(e)
    print(f'Collect {len(operationhandles)} operation handlers')
    print(f'Possible size of operation handlers: {len_oph}')
    print(f'Collect {len(objecthandles)} object handlers')
    print(f'Possible size of object handlers: {len_objh}')
    SaveHandlesHexToFile(opPath, operationhandles)
    SaveHandlesHexToFile(objPath, objecthandles)

def infer_address(_handler_file,_handler_size,_pointer_width:int):
    def cmp_entropy_order(a,b):
        return a[1] - b[1]
    def cmp_output_order(a,b):
        return a[2] - b[2]


    result_log = [] # [log, entropy, output index, entropy rank]

    for i in range(_handler_size//_pointer_width):
        handler_numbers = []
        with open(_handler_file,'r',encoding='utf8') as hf:
            for line in hf:
                handler_numbers.append(split_number(line,i*_pointer_width,_pointer_width))
        e = calculate_entropy(handler_numbers)
        log = f'entropy [{i*_pointer_width:02d}:{(i+1)*_pointer_width-1:02d}] = {e:1.18f}'
        result_log.append([log,e,i])
    result_log.sort(key=functools.cmp_to_key(cmp_entropy_order),reverse=True)
    rank = 0
    prev_e = 0
    for ind,item in enumerate(result_log):
        if rank == 0:
            rank = 1
        elif prev_e != item[1]:
            rank = ind+1
        item.append(rank)
        prev_e = item[1]
    result_log.sort(key=functools.cmp_to_key(cmp_output_order))
    for i in result_log:
        print(i[0],f'  rank {i[3]: 4d}')

def handler_diff(filename,slice_len):
    result = {} # slice -> different number
    with open(filename, 'r', encoding='utf8') as f:
        for line in f:
            for i in range(0,len(line),slice_len): # slice
                inds = i//2
                inde = i//2+slice_len//2-1
                ind = f'[{inds}:{inde}]'
                result.setdefault(ind,{})
                result[ind].setdefault(line[i:i+slice_len],0)
                result[ind][line[i:i+slice_len]] += 1

    return result

if __name__ == '__main__':
    # generate_handlers_file(68187,72,True) #mTower
    generate_handlers_file(8602,64,True) #TinyTEE
    res = handler_diff(opPath,8)
    print('ophandlers:')
    for k in res:
        print(len(res[k]),k,res[k])
    print('='*20)
    res = handler_diff(objPath, 8)
    print('objhandlers:')
    for k in res:
        print(len(res[k]), k, res[k])
