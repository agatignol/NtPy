import icebox
from nt_types import *
import logging

logging = '/home/user/dev/handle_tracer/handle_tracer.log'
vm = icebox.attach("win10")
proc = vm.processes.current()
addr = proc.symbols.address("nt!ObpCreateHandle")

objects = []

outfile = open(logging, 'w+')


def on_break():
    p = vm.processes.current()
    p.symbols.load_modules()

    _object = nt_Object(p, vm.registers.rdx)

    outfile.write(nt_Process(proc, proc.native()).__str__())
    outfile.write(_object.get_object_information().__str__())
    outfile.write(_object.get_object_security().__str__())
    outfile.write("\nCallstack:\n")
    for addr in p.callstack():
        outfile.write("\t" + p.symbols.string(addr) + "\n")
    outfile.write("\n--------------------------------\n")
    objects.append(_object)


while True:
    with vm.break_on(addr, on_break):
        vm.exec()
