import os
import re
import select
import subprocess
import time

import fcntl


class LLDBController():
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

    def exec_command(self, cmd, timeout=10):
        self._process.stdin.write(f'{cmd}\n'.encode())
        self._process.stdin.flush()
        return self.get_response()

    def load(self, elfpath):
        self.elfpath = elfpath
        self.exec_command(f'file {elfpath}')

    def quit(self):
        self.exec_command('q')

    def get_response(self, timeout=3):
        # print('len:', len(self._process.stdout))
        # poll_result = self._stdout_pollobj.poll(timeout)
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
                    if rready[0] == self._process.stdout.fileno():
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
            m = re.match(r'\-\> +([0-9a-fA-Fx]+)', line)
            if m:
                return str2int(m.group(1))
        raise Exception("not found pc")

    def reg_read(self):
        response = self.exec_command('reg read -a')
        return self._parse_read_reg(response)

    def _parse_read_reg(self, response):
        registers = {}
        category = ''
        for line in response.splitlines():
            m = re.match(r'^(.+): *$', line)
            if m:
                category = m.group(1)
                continue
            m = re.match(r' +([^ ]+) += +([0-9a-fA-Fx]+) *.*$', line)
            if m:
                regname = m.group(1)
                value = str2int(m.group(2))
                registers[regname] = {'category': category, 'value': value}
        return registers

    def mem_read(self, size, addr):
        if type(addr) == int:
            addr = hex(addr)
        response = self.exec_command(f'mem read -s{size} -fx -c1 {addr}')
        for line in response.splitlines():
            m = re.search(r'[0-9a-fA-Fx]+: +([0-9a-fA-Fx]+)', line)
            if m:
                return int(m.group(1), 16)
        return None


def str2int(s):
    return int(s, 16) if s[:2] == '0x' else int(s)
