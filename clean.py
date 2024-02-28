import os
import shutil

directories_to_remove = [
    "./workdir/fuzz_data/progs",
    "./workdir/fuzz_data/generated_payloads",
    "./workdir/fuzz_data/sig_cov_states",
    "./workdir/fuzz_data/payload_log",
    "./workdir/corpus.db"
]

for path in directories_to_remove:
    full_path = os.path.abspath(path)
    if os.path.exists(full_path):
        if os.path.isdir(full_path):
            shutil.rmtree(full_path)
        elif os.path.isfile(full_path):
            os.remove(full_path)
