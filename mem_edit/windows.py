"""
Implementation of Process class for Windows
"""

from math import floor
from os import strerror
import os.path
import ctypes
import ctypes.wintypes
import logging

from .abstract import Process as AbstractProcess
from .utils import ctypes_buffer_t, MemEditError


logger = logging.getLogger(__name__)


# Process handle privileges
privileges = {
    'PROCESS_QUERY_INFORMATION': 0x0400,
    'PROCESS_VM_OPERATION': 0x0008,
    'PROCESS_VM_READ': 0x0010,
    'PROCESS_VM_WRITE': 0x0020,
    }
privileges['PROCESS_RW'] = (
    privileges['PROCESS_QUERY_INFORMATION']
    | privileges['PROCESS_VM_OPERATION']
    | privileges['PROCESS_VM_READ']
    | privileges['PROCESS_VM_WRITE']
    )

# Memory region states
mem_states = {
    'MEM_COMMIT': 0x1000,
    'MEM_FREE': 0x10000,
    'MEM_RESERVE': 0x2000,
    }

# Memory region permissions
page_protections = {
    'PAGE_EXECUTE': 0x10,
    'PAGE_EXECUTE_READ': 0x20,
    'PAGE_EXECUTE_READWRITE': 0x40,
    'PAGE_EXECUTE_WRITECOPY': 0x80,
    'PAGE_NOACCESS': 0x01,
    'PAGE_READWRITE': 0x04,
    'PAGE_WRITECOPY': 0x08,
    }
# Custom (combined) permissions
page_protections['PAGE_READABLE'] = (
    page_protections['PAGE_EXECUTE_READ']
    | page_protections['PAGE_EXECUTE_READWRITE']
    | page_protections['PAGE_READWRITE']
    )
page_protections['PAGE_READWRITEABLE'] = (
    page_protections['PAGE_EXECUTE_READWRITE']
    | page_protections['PAGE_READWRITE']
    )

# Memory types
mem_types = {
    'MEM_IMAGE': 0x1000000,
    'MEM_MAPPED': 0x40000,
    'MEM_PRIVATE': 0x20000,
    }

# C struct for VirtualQueryEx
class MEMORY_BASIC_INFORMATION32(ctypes.Structure):
    _fields_ = [
        ('BaseAddress', ctypes.wintypes.DWORD),
        ('AllocationBase', ctypes.wintypes.DWORD),
        ('AllocationProtect', ctypes.wintypes.DWORD),
        ('RegionSize', ctypes.wintypes.DWORD),
        ('State', ctypes.wintypes.DWORD),
        ('Protect', ctypes.wintypes.DWORD),
        ('Type', ctypes.wintypes.DWORD),
        ]

class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
    _fields_ = [
        ('BaseAddress', ctypes.c_ulonglong),
        ('AllocationBase', ctypes.c_ulonglong),
        ('AllocationProtect', ctypes.wintypes.DWORD),
        ('__alignment1', ctypes.wintypes.DWORD),
        ('RegionSize', ctypes.c_ulonglong),
        ('State', ctypes.wintypes.DWORD),
        ('Protect', ctypes.wintypes.DWORD),
        ('Type', ctypes.wintypes.DWORD),
        ('__alignment2', ctypes.wintypes.DWORD),
        ]


PTR_SIZE = ctypes.sizeof(ctypes.c_void_p)
MEMORY_BASIC_INFORMATION: type[ctypes.Structure]
if PTR_SIZE == 8:       # 64-bit python
    MEMORY_BASIC_INFORMATION = MEMORY_BASIC_INFORMATION64
elif PTR_SIZE == 4:     # 32-bit python
    MEMORY_BASIC_INFORMATION = MEMORY_BASIC_INFORMATION32

ctypes.windll.kernel32.VirtualQueryEx.argtypes = [
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.LPCVOID,
    ctypes.c_void_p,
    ctypes.c_size_t]
ctypes.windll.kernel32.ReadProcessMemory.argtypes = [
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.LPCVOID,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_void_p]
ctypes.windll.kernel32.WriteProcessMemory.argtypes = [
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.LPCVOID,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_void_p]

# C struct for GetSystemInfo
class SYSTEM_INFO(ctypes.Structure):
    _fields_ = [
        ('wProcessorArchitecture', ctypes.wintypes.WORD),
        ('wReserved', ctypes.wintypes.WORD),
        ('dwPageSize', ctypes.wintypes.DWORD),
        ('lpMinimumApplicationAddress', ctypes.c_void_p),
        ('lpMaximumApplicationAddress', ctypes.c_void_p),
        ('dwActiveProcessorMask', ctypes.c_void_p),
        ('dwNumberOfProcessors', ctypes.wintypes.DWORD),
        ('dwProcessorType', ctypes.wintypes.DWORD),
        ('dwAllocationGranularity', ctypes.wintypes.DWORD),
        ('wProcessorLevel', ctypes.wintypes.WORD),
        ('wProcessorRevision', ctypes.wintypes.WORD),
        ]


class Process(AbstractProcess):
    process_handle: int | None

    def __init__(self, process_id: int) -> None:
        process_handle = ctypes.windll.kernel32.OpenProcess(
            privileges['PROCESS_RW'],
            False,
            process_id
            )

        if not process_handle:
            raise MemEditError(f'Couldn\'t open process {process_id}')

        self.process_handle = process_handle

    def close(self) -> None:
        ctypes.windll.kernel32.CloseHandle(self.process_handle)
        self.process_handle = None

    def write_memory(self, base_address: int, write_buffer: ctypes_buffer_t) -> None:
        try:
            ctypes.windll.kernel32.WriteProcessMemory(
                self.process_handle,
                base_address,
                ctypes.byref(write_buffer),
                ctypes.sizeof(write_buffer),
                None
                )
        except (BufferError, ValueError, TypeError) as err:
            raise MemEditError(f'Error with handle {self.process_handle}:  {self._get_last_error()}') from err

    def read_memory(self, base_address: int, read_buffer: ctypes_buffer_t) -> ctypes_buffer_t:
        try:
            ctypes.windll.kernel32.ReadProcessMemory(
                self.process_handle,
                base_address,
                ctypes.byref(read_buffer),
                ctypes.sizeof(read_buffer),
                None
                )
        except (BufferError, ValueError, TypeError) as err:
            raise MemEditError(f'Error with handle {self.process_handle}: {self._get_last_error()}') from err

        return read_buffer

    @staticmethod
    def _get_last_error() -> tuple[int, str]:
        err = ctypes.windll.kernel32.GetLastError()
        return err, strerror(err)

    def get_path(self) -> str | None:
        max_path_len = 260
        name_buffer = (ctypes.c_char * max_path_len)()
        rval = ctypes.windll.psapi.GetProcessImageFileNameA(
            self.process_handle,
            name_buffer,
            max_path_len,
            )

        if rval <= 0:
            return None
        return name_buffer.value.decode()

    @staticmethod
    def list_available_pids() -> list[int]:
        # According to EnumProcesses docs, you can't find out how many processes there are before
        #  fetching the list. As a result, we grab 100 on the first try, and if we get a full list
        #  of 100, repeatedly double the number until we get fewer than we asked for.

        nn = 100
        returned_size = ctypes.wintypes.DWORD()
        returned_size_ptr = ctypes.byref(returned_size)

        while True:
            pids = (ctypes.wintypes.DWORD * nn)()
            size = ctypes.sizeof(pids)
            pids_ptr = ctypes.byref(pids)

            success = ctypes.windll.Psapi.EnumProcesses(pids_ptr, size, returned_size_ptr)
            if not success:
                raise MemEditError(f'Failed to enumerate processes: nn={nn}')

            num_returned = floor(returned_size.value / ctypes.sizeof(ctypes.wintypes.DWORD))

            if nn != num_returned:
                break
            nn *= 2

        return pids[:num_returned]

    @staticmethod
    def get_pid_by_name(target_name: str) -> int | None:
        for pid in Process.list_available_pids():
            try:
                logger.debug(f'Checking name for pid {pid}')
                with Process.open_process(pid) as process:
                    path = process.get_path()
                if path is None:
                    continue

                name = os.path.basename(path)
                logger.debug(f'Name was "{name}"')
                if path is not None and name == target_name:
                    return pid
            except ValueError:
                pass
            except MemEditError as err:
                logger.debug(repr(err))

        logger.info(f'Found no process with name {target_name}')
        return None

    def list_mapped_regions(self, writeable_only: bool = True) -> list[tuple[int, int]]:
        sys_info = SYSTEM_INFO()
        sys_info_ptr = ctypes.byref(sys_info)
        ctypes.windll.kernel32.GetSystemInfo(sys_info_ptr)

        start = sys_info.lpMinimumApplicationAddress
        stop = sys_info.lpMaximumApplicationAddress

        def get_mem_info(address: int) -> MEMORY_BASIC_INFORMATION:
            """
            Query the memory region starting at or before 'address' to get its size/type/state/permissions.
            """
            mbi = MEMORY_BASIC_INFORMATION()
            mbi_ptr = ctypes.byref(mbi)
            mbi_size = ctypes.sizeof(mbi)

            success = ctypes.windll.kernel32.VirtualQueryEx(
                self.process_handle,
                address,
                mbi_ptr,
                mbi_size)

            if success != mbi_size:
                if success == 0:
                    raise MemEditError('Failed VirtualQueryEx with handle '
                                       + f'{self.process_handle}: {self._get_last_error()}')
                raise MemEditError('VirtualQueryEx output too short!')

            return mbi

        regions = []
        page_ptr = start
        while page_ptr < stop:
            page_info = get_mem_info(page_ptr)
            if (page_info.Type == mem_types['MEM_PRIVATE']
                    and page_info.State == mem_states['MEM_COMMIT']
                    and page_info.Protect & page_protections['PAGE_READABLE'] != 0
                    and (page_info.Protect & page_protections['PAGE_READWRITEABLE'] != 0
                         or not writeable_only)):
                regions.append((page_ptr, page_ptr + page_info.RegionSize))
            page_ptr += page_info.RegionSize

        return regions
