# SyzTrust
<p><a href="https://www.computer.org/csdl/proceedings-article/sp/2024/313000a070/1RjEaG9OpTa"><img alt="SyzTrust thumbnail" align="right" width="200" src="https://github.com/SyzTrust/syztrust/blob/main/Docs/Images/syztrust_thumbnail.png"></a></p>
SyzTrust is an on-device fuzzing project that enables fuzzing Trusted OSes on boards as well as tracking state and code coverage non-invasively.

SyzTrust is designed for fuzzing Trusted OSes provided by IoT vendors and assumes that (i) a TA can be installed in the
Trusted OS, and (ii) target devices have ETM enabled.

The idea of this project is to fuzz closed-source, proprietary Trusted OSes on development boards. We decouple execution to offload heavy-weight tasks (e.g., ETM packet decoder, branch and state coverage calculation, seed preservation, seed selection, and mutation) to the PC. Then, we utilize a debug probe to track the instruction traces and state variable values using the Real Time Transfer (RTT) protocol. Based on the instruction traces and state variable values, we can calculate the branch and state coverage, which will be utilized to guide seed preservation and selection in the fuzzing procedure.

<!---The idea of this project is to ---> 

Our [paper](https://www.computer.org/csdl/proceedings-article/sp/2024/313000a070/1RjEaG9OpTa) from Oakland '24 explains the system in more detail.



## SyzTrust Components from Implementation Perspective
SyzTrust is built on Syzkaller. We added a board controller to control a debug probe for instruction trace collection and state variable monitoring. We replace the original executor in Syzkaller with our designed CA and TA. Moreover, we implemented our designed corpus, seed preservation and seed selection components.

# Installation

## Prerequisites

* OS version as the base system: Windows (Linux should work. We use Windows because Segger has better support for Windows).
* Install Golang. Please refer to [Offical Go Installation](https://go.dev/doc/install) and [Installing Multiple Go Versions](https://go.dev/doc/manage-install). Recommend version: go1.17. (SyzTrust is written in Golang and based on Syzkaller).
* python 3.10.1 for board controller (set up a Python virtual environment named `syztrust`)
    * requirements.txt is in `${project_root_dir}/`.
    * Recommend JLink SDK version: `JLink_Windows_SDK_V766`. Please use pip to install `jlinksdk-7.66.0-py3-none-any.whl.`
* ETM version v3.5

## Configuration

Fill in `config.ini` in the board_manager directory. An example of `config.ini` is below.

```ini
[DEFAULT]
;JTrace. Replace the serial number with your J-Trace’s serial number.
serial_number = 933001215
;Select target TEE among the following TEEs
target_TEE = M2351-mTower
;Set the project dir; No need to change
project_root_dir = D:/syztrust
;Set the path of python; Please set up a python virtual environment
command_python = ${project_root_dir}/syztrust/Scripts/python
;Set the workdir for each fuzzing campaign; No need to change
workdir = ${project_root_dir}/workdir
; [CONFIG] Set the config file for board controller and go project; No need to change
config_path = ${project_root_dir}/board_manager/config.ini
go_mycfg = ${project_root_dir}/my.cfg
;Set the address of the script, which will be used in the go project; No need to change
board_controller = ${project_root_dir}/board_manager/main.py
trace_extraction = ${project_root_dir}/board_manager/TraceExtraction.py
protector_value = 0xfadebeef


;[Fuzzing configuration]
;[Log-related]
api_log = False
logfile = ./api-log.txt
;[Interaction-related] Configuration for communication between the fuzzer and the board controller; No need to change
net_addr = 127.0.0.1
net_port = 5000
;[Sleep and Clients]
sleep_sep = 0.001
long_sleep_sep = 0.5
payload_timeout_cnt = 400
max_clients = 3
;[Fuzzing mode] Todo: add explanation of those fuzzing mode
state_flag = 6
;[Delete trace file after parsing]
parse_delete = True
;[Save all branch information of every syscall]
branch_log_file = False
;[Save payload execution information in the file]
payload_log_file = True
;[Measure the execution time cost]
timing = True


;[CONFIG] Set the address of middle results; No need to change
raw_trace_rootdir = ${workdir}/Temp/
payload_root_dir = ${workdir}/Temp/
sigcovstate_dir = ${workdir}/fuzz_data/sig_cov_states/
timer_log = ${workdir}/fuzz_data/payload_log/timer_log.txt
corpus_file = ${workdir}/fuzz_data/payload_log/seeds.txt
trace_id = ${workdir}/fuzz_data/trace_files/trace_id.txt
temp_result_file = ${workdir}/fuzz_data/payload_log/temp_result.txt
progs_dir = ${workdir}/fuzz_data/progs
generated_payload_root_dir = ${workdir}/fuzz_data/generated_payloads/
sig_cov_states_root_dir = ${workdir}/fuzz_data/sig_cov_states/
execution_file_root_dir = ${workdir}/fuzz_data/payload_log/
payload_log_file_root_dir = ${workdir}/fuzz_data/payload_log/
execution_file = ${workdir}/fuzz_data/payload_log/execution_file.txt
trace_input = ${workdir}/fuzz_data/trace_files/trace_input.txt
trace_output = ${workdir}/fuzz_data/trace_files/trace_output.txt
pickle_file = ${workdir}/fuzz_data/payloads.pickle


;[CONFIG] Configuration for specific TEE OS and MCU
[M2351-mTower]
scriptfile = ScriptFile=${DEFAULT:project_root_dir}/board_manager/Nuvoton_M2351.JLinkScript
target_device = M2351KIAAE
speed = 6000
sleep_time = 0.001
;[Trust OS-related] Configuration for state variables.
handle_size = [72,72]
handle_division = [[[0,31],[40,43],[48,51],[52,55],[56,59],[60,63],[64,67]],[[8,35],[36,39],[40,43],[48,51],[60,63]]]
;[MCU-related] Configuration for ETM registers
ETMCR = 0xE0041000
ETMCCR = 0xE0041004
DEMCR = 0xE000EDFC
DFSR  = 0xE000ED30
SFAR  = 0xE000EDE8
SFSR  = 0xE000EDE4
SHCSR = 0xE000ED24
CFSR  = 0xE000ED28
MMFAR = 0xE000ED34
;Configuration for interaction between the PC and MCU. Please double-check.
;[Info] Before fuzzing, run RTTUtils.py and input "check address" to check the following addresses.
;[Info] The virtual com port will output the address values.
payload_buf_addr     = 0x3000cbc4
payload_size_addr    = 0x3000cbc0
data_event_s_addr    = 0x20000f40
execute_info_s_addr  = 0x20000f44
state_variables_addr = 0x20001348
protector_start_addr = 0x20000f3c
protector_end_addr   = 0x20001368
```

**When using RTTUtils.py to check the address, you should get similar outputs as follows.**

![RTT-Sample](https://github.com/SyzTrust/syztrust/blob/main/Docs/Images/pic-rtt-sample.png)

## How to use (Take mTower as an example)

1. Use Nuvoton M2351 and connect J-Trace pro with M2351 and PC. **[Configure the hardware]: Turn on TXD, RXD, VCOM; Turn off MSG.**
    <img src="https://github.com/SyzTrust/syztrust/blob/main/Docs/Images/settings.png"  width="50%" height="30%">
2. Use Nuvoton ICP tool to load mtower_s_176.bin and mtower_ns_176.bin on M2351 board; then disconnect with ICP tool.
3. Activate `syztrust` virtual environment.
4. In `${project_root_dir}/board_manager` directory, run the following command to update the scripts in `board_manager` and generate `my.cfg` in `${project_root_dir}/` directory.
    ```shell
    python patcher.py
    ```
5. Build syztrust in `${project_root_dir}/` directory. For Windows:
    ```shell
    go build -o ./bin/trusty_arm/syztrust_fuzzer.exe ./syz-fuzzer
    go build -o ./bin/syztrust_manager.exe ./syz-manager
    ```
    For Linux (To be updated).
6. Run syztrust in `${project_root_dir}/` directory. Before running a fuzzing campaign, you should clean the workdir directory.
    ```shell
    python clean.py
    ```
    For windows:
    ```shell
    .\bin\syztrust_manager -config=.\my.cfg
    ```
    For Linux (To be updated).




# Bug Analysis
To be updated




# Citing the Paper
```
@inproceedings{wang2024syztrust,
    author = {Qinying, Wang and Boyu, Chang and Shouling, Ji and Yuan, Tian and Xuhong, Zhang and Binbin, Zhao and Gaoning, Pan and Chenyang, Lyu and Mathias, Payer and Wenhai, Wang and Reheem, Beyah},
    title = {SyzTrust: State-aware Fuzzing on {Trusted OS} Designed for {IoT} Devices},
  booktitle={2024 IEEE Symposium on Security and Privacy (SP)},
  year={2024},
  organization={IEEE}
}
```

# Found Bugs? Let us know!
In case you found bugs using SyzTrust, feel free to let us know!

<!-----
# How to Contribute
As a researcher, time for coding is finite. This is why there are still TODOs which could make the SyzTrust implementation better (even if we had infinite time, there would always be more things to improve, of course). If you are interested, here are some sample projects to work on for hacking on SyzTrust:

1. 
>
