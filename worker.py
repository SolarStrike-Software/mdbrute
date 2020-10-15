import ctypes
import logging
from threading import Lock

OpenProcess = ctypes.windll.kernel32.OpenProcess
ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory

mutex = Lock()


class BranchItemInfo(ctypes.Structure):
    _fields_ = [
        ("unused0", ctypes.c_int),
        ("branch_id", ctypes.c_int),
        ("unused1", ctypes.c_byte * 14),
        ("address", ctypes.c_int),
        ("unused2", ctypes.c_int),
        ("unused2", ctypes.c_int),
    ]


class Worker:
    __LOWEST_BRANCH = 0x6c
    __HIGHEST_BRANCH = 0x348

    __MEMDATABASE_OFFSET = 0xd4

    __BRANCH_ITEMSET_ID = 0x4
    __BRANCH_SIZE = 999
    __BRANCH_INFO_SIZE = 0x24
    __BRANCH_ITEMSET_ADDRESS = 0x18
    __BRANCH_ITEM_NAME_OFFSET = 0xc

    PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)

    __pid: int
    __chunk_start: int
    __chunk_end: int
    __item_id: int
    __item_name: str
    __module_base_address: int

    def __init__(self, pid: int, module_base_address: int, chunk_start: int, chunk_end: int, item_id: int,
                 item_name):
        self.__pid = pid
        self.__module_base_address = module_base_address
        self.__chunk_start = chunk_start
        self.__chunk_end = chunk_end
        self.__item_id = item_id

        if isinstance(item_name, str):
            item_name = [item_name]
        self.__item_name = item_name

    def say(self, *args, **kwargs):
        mutex.acquire()
        try:
            print(*args, **kwargs)
            logging.getLogger().info(*args)
        finally:
            mutex.release()

    def work(self) -> list:
        found_results = []
        handle = OpenProcess(self.PROCESS_ALL_ACCESS, False, self.__pid)

        count = int((self.__chunk_end - self.__chunk_start) / 4 + 4)
        branch_list_pointers = self.__read_array(handle, self.__module_base_address + self.__chunk_start, ctypes.c_int,
                                                 count)

        for index, branch_list_pointer in enumerate(branch_list_pointers):
            try:
                if (branch_list_pointer == 0):
                    continue

                branch_list_address = self.__read_int(handle, branch_list_pointer + self.__MEMDATABASE_OFFSET)

                if branch_list_address is None or branch_list_address == 0:
                    # Branch list is invalid, so all containing branches would also be invalid
                    continue

                for branch in range(self.__LOWEST_BRANCH, self.__HIGHEST_BRANCH, 4):
                    found = self.__scan_branch(handle, branch_list_address, branch)

                    if found:
                        address = self.__chunk_start + index * ctypes.sizeof(ctypes.c_int)
                        self.say(f"Found potential match at 0x{address:08x}, branch 0x{branch:03x}")
                        found_results.append(address)
            except Exception as e:
                mutex.acquire()
                try:
                    print(e)
                    logging.getLogger().exception(e)
                finally:
                    mutex.release()

        return found_results

    def __read_ptr(self, closure, handle: int, address: int, offset: int):
        result = self.__read_int(handle, address)
        if result is None or result == 0:
            return None

        return closure(handle, result + offset)

    def __read_int(self, handle: int, address: int) -> int or None:
        buffer = ctypes.c_ulong()
        result = None

        try:
            result = ReadProcessMemory(handle, address, ctypes.byref(buffer), ctypes.sizeof(buffer), None)
        except ctypes.ArgumentError as e:
            return None

        if result == 0:
            return None

        return (int)(buffer.value)

    def __read_array(self, handle: int, address: int, type, count: int):
        buffer = (type * count)()
        bytes_read = ctypes.c_ulonglong(0)
        result = ReadProcessMemory(handle, address, buffer, ctypes.sizeof(buffer), ctypes.byref(bytes_read))
        if result == 0:
            return None

        if bytes_read.value != ctypes.sizeof(buffer):
            return None

        return buffer

    def __read_string(self, handle: int, address: int, max_length: int = 255) -> None or bytes:
        buffer = ctypes.create_string_buffer(max_length)
        result = ReadProcessMemory(handle, address, ctypes.byref(buffer), max_length, None)
        if result == 0:
            return None

        return buffer.value

    def __scan_branch(self, handle: int, branch_list_address: int, branch: int) -> bool:
        branch_address = self.__read_int(handle, branch_list_address + branch)
        if branch_address is None or branch_address == 0 or branch_address == 0xffffffff:
            return False

        branch_item_infos = self.__read_array(handle, branch_address, BranchItemInfo, self.__BRANCH_SIZE)
        if branch_item_infos is None:
            return False

        for index, branch_item_info in enumerate(branch_item_infos):
            if branch_item_info.branch_id != index:
                # If we read an branch ID that's different from our expected outcome (index),
                # then this doesn't appear valid. Exit early
                continue

            if branch_item_info.address is None or branch_item_info.address == 0:
                continue

            # Item ID mismatch
            item_id = self.__read_int(handle, branch_item_info.address)
            if item_id is None or item_id != self.__item_id:
                continue

            # Check whether the name appears to match or not
            name_address = self.__read_int(handle, branch_item_info.address + self.__BRANCH_ITEM_NAME_OFFSET)
            item_name = self.__read_string(handle, name_address)
            if item_name is None:
                continue

            item_name = item_name.decode('utf-8')
            if item_name in self.__item_name:
                return True

        return False
