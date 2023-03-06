import sys
import os
import argparse
from pprint import pprint
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
    regs = lldb.read_reg()
    pprint(regs)
    pc = lldb.read_pc()
    mems = lldb.read_mem(pc, size=4, count=10)
    pprint([hex(m) for m in mems])
    lldb.quit()


if __name__ == '__main__':
    main()
