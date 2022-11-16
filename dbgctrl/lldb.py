import os
import re
import select
import subprocess
import time

import fcntl


class LLDBController():
    DEFAULT_TIMEOUT = 1.0
    DEFAULT_ROUNDUP_TIME = 0.2

    pattern_exited = re.compile(r'.+ exited with')
    pattern_invalid = re.compile(r'error: invalid process')
    pattern_dis = re.compile(r'[^:]+:\s(.+)')
    pattern_pc = re.compile(r'\-\> +([0-9A-Fa-fx]+)')
    pattern_reg_category = re.compile(r'^(.+): *$')
    pattern_reg_namevalue = re.compile(r'\s*([^ ]+)\s*=\s*([0-9A-Fa-fx]+)\s*.*$')
    pattern_mem_value = re.compile(r'[0-9A-Fa-fx]+:\s+([0-9A-Fa-fx]+)')

    def __init__(self, lldbpath):
        self.lldbpath = lldbpath
        self.elfpath = None
        self._process = None
        self._stdout = None
        self.roundup_time = LLDBController.DEFAULT_ROUNDUP_TIME
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

    def exec_command(self, cmd, timeout=None):
        self._process.stdin.write(f'{cmd}\n'.encode())
        self._process.stdin.flush()
        return self.get_response(timeout=timeout)

    def load(self, elfpath, timeout=None):
        self.elfpath = elfpath
        self.exec_command(f'file {elfpath}', timeout=timeout)

    def quit(self):
        self.exec_command('q')
        print('lldb exited.')
        if self._process:
            self._process.terminate()
            self._process.wait()
            self._process.communicate()
            self._process = None

    def get_response(self, timeout=None):
        if timeout is None:
            timeout = LLDBController.DEFAULT_TIMEOUT
        timeout_time = time.time() + timeout
        responses = []
        while True:
            select_timeout = timeout_time - time.time()
            if select_timeout <= 0:
                select_timeout = 0
            rready, wready, xready = select.select(
                [self._process.stdout.fileno()], [], [],
                select_timeout
            )
            res = None
            if rready:
                for fileno in rready:
                    if fileno == self._process.stdout.fileno():
                        self._process.stdout.flush()
                        res = self._process.stdout.read()
                        responses += [res]
                    else:
                        raise Exception("Unknown fd: {}".format(fileno))
            if timeout == 0:
                break
            elif res and (self.roundup_time > 0):
                timeout_time = min(time.time() + self.roundup_time, timeout_time)
            elif time.time() > timeout_time:
                break
        response = ''.join([r.decode() for r in responses])
        return response

    def run_stop_at_start(self, timeout=None):
        return self.exec_command('pr la -s', timeout=timeout)

    def read_pc(self, timeout=5):
        response = self.exec_command('dis -pc -c 1', timeout=timeout)
        for line in response.splitlines():
            m = self.pattern_pc.match(line)
            if m:
                return str2int(m.group(1))
        raise Exception("not found pc")

    def reg_read(self, names=None, timeout=5):
        response = self.exec_command('reg read -a', timeout=timeout)
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

    def mem_read(self, addr, size=4, count=1, timeout=3):
        if type(addr) == int:
            addr = hex(addr)
        response = self.exec_command(f'mem read -s{size} -fx -c{count} {addr}', timeout=timeout)
        mems = []
        for line in response.splitlines()[1:]:
            nums = line.strip().split(' ')
            addr = str2int(nums[0][:-1])
            mems += [str2int(m) for m in nums[1:]]
        return mems


def str2int(s):
    return int(s, 16) if s[:2] == '0x' else int(s)
