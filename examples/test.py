import sys
import os
import argparse
from pprint import pprint
if True:
    selfdir = os.path.dirname(__file__)
    rootdir = os.path.join(selfdir, '..')
    sys.path.insert(0, rootdir)
import dbgctrl


def main():
    argparser = argparse.ArgumentParser()
    argparser.add_argument('--debugger', '-d', default='/usr/bin/lldb')
    argparser.add_argument('elf')
    args = argparser.parse_args()

    dbg = dbgctrl.controller(args.debugger)
    dbg.load(args.elf)
    dbg.run_stop_at_start()
    regs = dbg.read_reg()
    pprint(regs)
    pc = dbg.read_pc()
    mems = dbg.read_mem(pc, size=4, count=10)
    pprint([hex(m) for m in mems])
    dbg.quit()


if __name__ == '__main__':
    main()
