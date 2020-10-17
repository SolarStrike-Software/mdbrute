import argparse
import concurrent.futures
import json
import logging
import math
import os

import psutil

from privileges import *
from worker import Worker

CONFIG_FILENAME = 'config.json'
__PROCESS_NAME = "Client.exe"
__PROCESS_CHILD_NAME = "wbp.exe"

DEFAULT_WORKERS = 8
DEFAULT_CHUNK_SIZE = "0x400"
DEFAULT_ITEM_ID = 540000
DEFAULT_ITEM_NAME = ["Attack", "Angreifen", "Ataque", "Attaque", "Atak"]
DEFAULT_START_ADDRESS = "0x00620000"
DEFAULT_END_ADDRESS = '0x00650000'
DEFAULT_MODULE_BASE_ADDRESS = '0x400000'

__log_filename = './log.txt'
__logger = logging.getLogger()
__logger.setLevel(logging.DEBUG)

fileHandler = logging.FileHandler(__log_filename, 'w')
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fileHandler.setFormatter(formatter)
__logger.addHandler(fileHandler)

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Brute force search for memdatabase base address')
    parser.add_argument('--first-only', action='store_true', default=False,
                        help='Stop and return the first result immediately as soon as it is found.')

    options = parser.parse_args()

    debug_set = set_privilege("SeDebugPrivilege")
    print("Debug privileges set:", debug_set)
    if not debug_set:
        raise Exception("Failed to set SeDebugPrivilege. Please try running with admin privileges.")


    def get_proc_id() -> int:
        for proc in psutil.process_iter():
            if __PROCESS_NAME in proc.name():
                # If this really is the RoM client, it should have a child name wbp.exe
                process = psutil.Process(proc.pid)
                children_names = [_.name() for _ in process.children()]

                if __PROCESS_CHILD_NAME in children_names:
                    return proc.pid
        raise Exception(f"Could not locate process for `{__PROCESS_NAME}`")


    def get_default_config() -> dict:
        return {
            'workers': DEFAULT_WORKERS,
            'chunk_size': DEFAULT_CHUNK_SIZE,
            'item_id': DEFAULT_ITEM_ID,
            'item_name': DEFAULT_ITEM_NAME,
            'start_address': DEFAULT_START_ADDRESS,
            'end_address': DEFAULT_END_ADDRESS,
            'module_base_address': DEFAULT_MODULE_BASE_ADDRESS
        }


    def create_default_config_file():
        output = json.dumps(get_default_config(), indent=2)
        with open(CONFIG_FILENAME, 'w') as file:
            file.write(output)


    def get_config(key: str, default=None):
        if key not in config:
            print(f"{key} not in config")
            return default
        print(f"{key} = {config[key]}")
        return config[key]


    try:
        config = get_default_config()
        if not os.path.exists(CONFIG_FILENAME):
            create_default_config_file()
        else:
            with open(CONFIG_FILENAME, 'r') as file:
                config = json.load(file)

        workers = get_config('workers', DEFAULT_WORKERS)
        item_id = get_config('item_id', DEFAULT_ITEM_ID)
        item_name = get_config('item_name', DEFAULT_ITEM_NAME)

        chunk_size = int(get_config('chunk_size', DEFAULT_CHUNK_SIZE), 0)
        module_base_address = int(get_config('module_base_address', DEFAULT_MODULE_BASE_ADDRESS), 0)
        start_address = int(get_config('start_address', DEFAULT_START_ADDRESS), 0)
        end_address = int(get_config('end_address', DEFAULT_END_ADDRESS), 0)

        if workers <= 0 or workers > 128:
            msg = "Error: Config 'workers' must be between 1 and 128.";
            logging.getLogger().error(msg)
            print(msg)
            exit(-1)

        pid = get_proc_id()

        print("Worker count:", workers)
        print("Item ID:", item_id)
        print("Item name:", item_name)
        print("PID:", pid)
        print(f"Scan range: 0x{start_address:08x} - 0x{end_address:08x}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            pending = []
            tmp_pending = [_ for _ in range(start_address, end_address + 4, chunk_size)]

            # Bisect and reorganize so that the center of this range is prioritized
            while len(tmp_pending) > 0:
                mid_index = int(math.floor(len(tmp_pending) / 2))
                pending.append(tmp_pending.pop(mid_index))

            all_results = []
            futures = []
            for item in pending:
                chunk_start = item
                chunk_end = item + chunk_size - 4

                worker = Worker(options, pid, module_base_address, chunk_start, chunk_end, item_id, item_name)
                future = executor.submit(worker.work)
                futures.append(future)

            for future in concurrent.futures.as_completed(futures):
                all_results.extend(future.result())

                if options.first_only:
                    break

        for address in all_results:
            msg = f"Found address 0x{address:08x}"
            print(msg)
            logging.getLogger().info(msg)

    except Exception as e:
        logging.getLogger().exception(e, exc_info=True)
        raise e

    exit(0)
