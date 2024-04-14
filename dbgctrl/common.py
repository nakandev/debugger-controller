import os

from dbgctrl.gdb import GDBController
from dbgctrl.lldb import LLDBController


def controller(path):
    if not os.path.exists(path):
        raise IOError(f'debugger not exists: {path}')

    if 'gdb' in path:
        return GDBController(path)
    elif 'lldb' in path:
        return LLDBController(path)
    else:
        raise Exception(f'Unknown debugger: {path}')
