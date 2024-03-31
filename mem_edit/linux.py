"""
Implementation of Process class for Linux
"""

from os import strerror
import os
import os.path
import signal
import ctypes
import ctypes.util
import logging

from .abstract import Process as AbstractProcess
from .utils import ctypes_buffer_t, MemEditError


logger = logging.getLogger(__name__)


ptrace_commands = {
    'PTRACE_GETREGS': 12,
    'PTRACE_SETREGS': 13,
    'PTRACE_ATTACH': 16,
    'PTRACE_DETACH': 17,
    'PTRACE_SYSCALL': 24,
    'PTRACE_SEIZE': 16902,
    }


# import ptrace() from libc
_libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
_ptrace = _libc.ptrace
_ptrace.argtypes = (ctypes.c_ulong,) * 4
_ptrace.restype = ctypes.c_long


def ptrace(
        command: int,
        pid: int = 0,
        arg1: int = 0,
        arg2: int = 0,
        ) -> int:
    """
    Call ptrace() with the provided pid and arguments. See `man ptrace`.
    """
    logger.debug(f'ptrace({command}, {pid}, {arg1}, {arg2})')
    result = _ptrace(command, pid, arg1, arg2)
    if result == -1:
        err_no = ctypes.get_errno()
        if err_no:
            raise MemEditError(f'ptrace({command}, {pid}, {arg1}, {arg2})'
                               + f' failed with error {err_no}: {strerror(err_no)}')
    return result


class Process(AbstractProcess):
    pid: int | None

    def __init__(self, process_id: int) -> None:
        ptrace(ptrace_commands['PTRACE_SEIZE'], process_id)
        self.pid = process_id

    def close(self) -> None:
        os.kill(self.pid, signal.SIGSTOP)
        os.waitpid(self.pid, 0)
        ptrace(ptrace_commands['PTRACE_DETACH'], self.pid, 0, 0)
        os.kill(self.pid, signal.SIGCONT)
        self.pid = None

    def write_memory(self, base_address: int, write_buffer: ctypes_buffer_t) -> None:
        with open(f'/proc/{self.pid}/mem', 'rb+') as mem:
            mem.seek(base_address)
            mem.write(write_buffer)

    def read_memory(self, base_address: int, read_buffer: ctypes_buffer_t) -> ctypes_buffer_t:
        with open(f'/proc/{self.pid}/mem', 'rb+') as mem:
            mem.seek(base_address)
            mem.readinto(read_buffer)
        return read_buffer

    def get_path(self) -> str | None:
        try:
            with open(f'/proc/{self.pid}/cmdline', 'rb') as ff:
                return ff.read().decode().split('\x00')[0]
        except FileNotFoundError:
            return None

    @staticmethod
    def list_available_pids() -> list[int]:
        pids = []
        for pid_str in os.listdir('/proc'):
            try:
                pids.append(int(pid_str))
            except ValueError:
                continue
        return pids

    @staticmethod
    def get_pid_by_name(target_name: str) -> int | None:
        for pid in Process.list_available_pids():
            try:
                logger.debug(f'Checking name for pid {pid}')
                with open(f'/proc/{pid}/cmdline', 'rb') as cmdline:
                    path = cmdline.read().decode().split('\x00')[0]
            except FileNotFoundError:
                continue

            name = os.path.basename(path)
            logger.debug(f'Name was "{name}"')
            if path is not None and name == target_name:
                return pid

        logger.info(f'Found no process with name {target_name}')
        return None

    def list_mapped_regions(self, writeable_only: bool = True) -> list[tuple[int, int]]:
        regions = []
        with open(f'/proc/{self.pid}/maps', 'r') as maps:
            for line in maps:
                bounds, privileges = line.split()[0:2]

                if 'r' not in privileges:
                    continue

                if writeable_only and 'w' not in privileges:
                    continue

                start, stop = (int(bound, 16) for bound in bounds.split('-'))
                regions.append((start, stop))
        return regions
