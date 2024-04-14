# debugger-controller
gdb/lldb debugging automation

## Requirements

* python >= 3.8

## Installation

```sh
pip install git+https://github.com/nakandev/debugger-controller.git
```

## Module

```python
import dbgctrl

dbg = dbgctrl.controller('/usr/bin/lldb')
dbg.load('examples/test.elf')
dbg.run_stop_at_start()
regs = dbg.read_reg()
print(regs)
dbg.quit()
```

## Application

* `dbgctrl-regdump`

  Run the program and dump registers at the specified address range.
