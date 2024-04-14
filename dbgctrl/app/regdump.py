import sys
import os
import re
import time
import argparse
from collections import namedtuple

import dbgctrl
from dbgctrl.logging import logging
from dbgctrl import __version__

NAMESPACE = 'dbgctrl'

logger = logging.getLogger()
logger.setLevel(logging.INFO)

RegName = namedtuple('RegName', ['type', 'names'])
# PcRange = namedtuple('PcRange', ['type', 'name', 'start', 'end'])
class PcRange():
    _attrs = ['type', 'name', 'start', 'end']

    def __init__(self, *args):
        if len(args) != len(PcRange._attrs):
            raise ValueError()
        for i, key in enumerate(PcRange._attrs):
            setattr(self, key, args[i])


def arg_parse():
    argparser = argparse.ArgumentParser(
        prog=NAMESPACE,
    )
    argparser.add_argument(
        '--version', '-v', action='version',
        version='{} {}'.format(NAMESPACE, __version__),
        help='display version and exit')
    argparser.add_argument(
        '--debugger', '-d', metavar='PATH', default=None,
        help='debugger path')
    argparser.add_argument(
        '--regname', '-n', metavar='NAMES', default=None,
        help='regisger name list')
    argparser.add_argument(
        '--range', '-r', metavar='RANGE', default=None,
        help='range of program counter to dump')
    argparser.add_argument(
        '--exit', '-e', metavar='CONDITION', default='reach', choices=['reach', 'out'],
        help='debugger exit condition')
    argparser.add_argument(
        '--step', '-s', metavar='STEP', default='ni', choices=['s', 'si', 'n', 'ni'],
        help='debugger step command')
    argparser.add_argument(
        '--max', '-M', metavar='COUNT', default=1000,
        help='max operator count')
    argparser.add_argument(
        '--output', '-o', metavar='FILE', default=None,
        help='output file')
    argparser.add_argument(
        'input',
        help='input file')
    args = argparser.parse_args()

    return args


def regname_parse(dbg, regname):
    regname = regname or ''
    m = re.match(r'(l|r|f):(.+)', regname)
    if m:
        tp = m.group(1)
        if tp == 'l':
            _regname = RegName('list', m.group(2).split(','))
        elif tp == 'r':
            regs = dbg.read_reg()
            names = []
            for v in regs:
                m2 = re.match(r'{}$'.format(m.group(2)), v)
                if m2:
                    names.append(v)
            _regname = RegName('regular', tuple(names))
        else:
            regfpath = m.group(2)
            if not os.path.exists(regfpath):
                raise ValueError('regname file not exists: {}'.format(regfpath))
            _regname = RegName('file', [])
    else:
        regs = dbg.read_reg()
        _regname = RegName('regular', tuple(regs.keys()))
    return _regname


def range_parse(dbg, pc_range):
    pc_range = pc_range or 'main'
    m = re.match(r'0x([0-9A-Fa-f]+),0x([0-9A-Fa-f]+)', pc_range)
    if m:
        _pc_range = PcRange('pc', '-', int(m.group(1), 16), int(m.group(2), 16))
    # elif m := re.match(r'\d+,\d+', pc_range):
    #     _pc_range = PcRange('cycle', '-', int(m.group(1)), int(m.group(2)))
    else:
        _pc_range = PcRange('func', pc_range, -1, -1)
    return _pc_range


def main():
    args = arg_parse()
    dbg = dbgctrl.controller(args.debugger)
    dbg.load(args.input)

    dbg.run_stop_at_start()
    time.sleep(2)

    # set breakpoint before running program
    pcrange = range_parse(dbg, args.range)
    if pcrange.type == 'pc':
        dbg.exec_command('b {}'.format(hex(pcrange.start)))
    else:
        dbg.exec_command('b {}'.format(pcrange.name))

    # run and break at start
    regname = regname_parse(dbg, args.regname)
    dbg.exec_command('c', timeout=20)

    if pcrange.type == 'func':
        pcrange.start = dbg.read_pc()
        pcrange.end = dbg.read_return_address()
    print('reached start: {}'.format(hex(pcrange.start)))

    # step and write register values
    if args.output:
        fout = open(args.output, 'w')
    else:
        fout = sys.stdout

    maxcount = max(args.max, 10)
    logger.info('maxcount: {}'.format(maxcount))
    prev_progress, progress = 0, 0
    print('No.,pc,dis,{}'.format(','.join([n for n in regname.names])), file=fout)
    for count in range(1, maxcount + 1):
        prev_progress = progress
        progress = count * 100 // maxcount
        if progress != prev_progress:
            logger.info('count: {}'.format(count))
        try:
            pc = dbg.read_pc()
        except Exception:
            break
        regs = dbg.read_reg(names=regname.names)
        regvalues = [reg['value'] for reg in regs.values()]
        dis = dbg.read_disasm()
        print('{},{},"{}",{}'.format(
            count, hex(pc), dis, ','.join([hex(v) for v in regvalues])),
            file=fout)
        if args.exit == 'reach' and pc == pcrange.end:
            print('reached end  : {}'.format(hex(pcrange.end)))
            break
        elif args.exit == 'out' and (pc < pcrange.start or pcrange.end <= pc):
            print('out range: [{}, {}]'.format(hex(pcrange.start), hex(pcrange.end)))
            break
        if args.step == 'ni':
            dbg.step_over(inst=True)
        elif args.step == 'n':
            dbg.step_over(inst=False)
        elif args.step == 'si':
            dbg.step_in(inst=True)
        else:
            dbg.step_in(inst=False)
        count += 1

    if args.output:
        fout.close()

    dbg.quit()


if __name__ == '__main__':
    sys.exit(main())
