import os
import re
import select
import subprocess
import time

import fcntl


class LLDBController():
    pattern_pc = re.compile(r'\-\> +([0-9a-fA-Fx]+)')
    pattern_reg_category = re.compile(r'^(.+): *$')
    pattern_reg_namevalue = re.compile(r' +([^ ]+) += +([0-9a-fA-Fx]+) *.*$')
    pattern_mem_value = re.compile(r'[0-9a-fA-Fx]+: +([0-9a-fA-Fx]+)')

    def __init__(self, lldbpath):
        self.lldbpath = lldbpath
        self.elfpath = None
        self._process = None
        self._stdout = None
        self.check_debugger_exists()
        self.exec_lldb()

    def check_debugger_exists(self):
        if os.path.exists(self.lldbpath):
            return
        raise Exception('debugger not found: {}'.format(self.lldbpath))

    def exec_lldb(self):
        self._process = subprocess.Popen(
            self.lldbpath,
            shell=False,
            stdout=subprocess.PIPE,
            stdin=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )
        self.stdout = self._process.stdout
        # self.stderr = self._process.stderr
        fcntl.fcntl(self.stdout.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)
        # fcntl.fcntl(self.stderr.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)
        print('lldb start up.')

    def exec_command(self, cmd, timeout=1):
        self._process.stdin.write(f'{cmd}\n'.encode())
        self._process.stdin.flush()
        return self.get_response(timeout=timeout)

    def load(self, elfpath):
        self.elfpath = elfpath
        self.exec_command(f'file {elfpath}')

    def quit(self):
        self.exec_command('q')

    def get_response(self, timeout=1):
        timeout_time = time.time() + timeout
        res = []
        while True:
            select_timeout = timeout_time - time.time()
            if select_timeout <= 0:
                select_timeout = 0
            rready, wready, xready = select.select(
                [self._process.stdout.fileno()], [], [],
                select_timeout
            )
            # local_res = None
            if rready:
                for fileno in rready:
                    if fileno == self._process.stdout.fileno():
                        self._process.stdout.flush()
                        res += [self._process.stdout.read()]
                    else:
                        raise Exception("Unknown fd: {}".format(fileno))
            if timeout == 0:
                break
            elif time.time() > timeout_time:
                break
        response = ''.join([r.decode() for r in res])
        return response

    def run_stop_at_start(self):
        return self.exec_command('pr la -s')

    def read_pc(self):
        response = self.exec_command('dis -pc -c 1')
        for line in response.splitlines():
            m = self.pattern_pc.match(line)
            if m:
                return str2int(m.group(1))
        raise Exception("not found pc")

    def reg_read(self, names=None):
        response = self.exec_command('reg read -a', timeout=3)
        regs = self._parse_read_reg(response)
        if names is not None:
            regs = {k: v for k, v in regs.items() if k in names}
        return regs

    def _parse_read_reg(self, response):
        registers = {}
        category = ''
        for line in response.splitlines():
            m = self.pattern_reg_category.match(line)
            if m:
                category = m.group(1)
                continue
            m = self.pattern_reg_namevalue.match(line)
            if m:
                regname = m.group(1)
                value = str2int(m.group(2))
                registers[regname] = {'category': category, 'value': value}
        return registers

    def mem_read(self, addr, size=4, count=1):
        if type(addr) == int:
            addr = hex(addr)
        response = self.exec_command(f'mem read -s{size} -fx -c{count} {addr}')
        mems = []
        for line in response.splitlines()[1:]:
            nums = line.strip().split(' ')
            addr = str2int(nums[0][:-1])
            mems += [str2int(m) for m in nums[1:]]
        return mems


def str2int(s):
    return int(s, 16) if s[:2] == '0x' else int(s)
