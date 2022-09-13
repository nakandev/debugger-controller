import sys
import os
import argparse
if True:
    selfdir = os.path.dirname(__file__)
    rootdir = os.path.join(selfdir, '..')
    sys.path.insert(0, rootdir)
from dbgctrl.lldb import LLDBController


def main():
    argparser = argparse.ArgumentParser()
    argparser.add_argument('--debugger', '-d', default='/usr/bin/lldb')
    argparser.add_argument('elf')
    args = argparser.parse_args()

    lldb = LLDBController(args.debugger)
    lldb.load(args.elf)
    lldb.run_stop_at_start()
    regs = lldb.reg_read()
    print(regs)
    pc = lldb.read_pc()
    mem = lldb.mem_read(4, pc)
    print(hex(mem))
    lldb.quit()


if __name__ == '__main__':
    main()
