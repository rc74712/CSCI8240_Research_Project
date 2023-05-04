import angr

# loads the project
proj = angr.Project('./specrand_base.i386', load_options={'auto_load_libs': False})
# print(proj.arch)                                            # prints architecture: <Arch X86 (LE)>
# print(hex(proj.entry))                                      # prints the address of the entry point: 0x80484f3
# print(proj.filename)                                        # prints file name: ./specrand_base.i386
# print(proj.loader)                                          # loads the project: <Loaded specrand_base.i386, maps [0x8048000:0x8407fff]>
# print(proj.loader.main_object)                              # loads the main binary: <ELF Object specrand_base.i386, maps [0x8048000:0x804a02f]>
# print(proj.loader.all_objects)                              # <ELF Object specrand_base.i386, maps [0x8048000:0x804a02f]>, <ExternObject Object cle##externs, maps [0x8100000:0x810000c]>
# print(proj.loader.shared_objects)
# print(proj.loader.all_elf_objects)                          # loads all ELF files: [<ELF Object specrand_base.i386, maps [0x8048000:0x804a02f]>]
# print(proj.loader.extern_object)                            # addresses of unresolved imports and angr internals: <ExternObject Object cle##externs, maps [0x8100000:0x810000c]>
# print(proj.loader.kernel_object)                            # addresses of emulated syscalls: <KernelObject Object cle##kernel, maps [0x8400000:0x8407fff]>
# print(proj.loader.find_object_containing(0x8048000))        # get reference to object at address

m_obj = proj.loader.main_object                             # direct interaction to extract metadata
# print(hex(m_obj.entry), hex(m_obj.min_addr), hex(m_obj.max_addr))
# print(m_obj.segments)
# print(m_obj.sections)

# basic blocks
block = proj.factory.block(proj.entry)                      # get block from entry point
# block.pp()                                                  # pretty print disassembly to stdout
# print(block.instructions)                                   # prints # of instructions: 13
# for i in block.instruction_addrs:                           # address of instrcutions in .pp()
#     print(hex(i))

# states
state = proj.factory.entry_state()                          # project only represents "initialization image" of program
                                                            # when working with program execution, working with a simulated program state
                                                            # contains program's memory, registers, filesystem data... any "living" data
# print(state)                                                # <SimState @ 0x80484f3>
# print(state.regs.eip)                                       # get the current instruction pointer: <BV32 0x80484f3>
# print(state.regs.ax)                                        # <BV16 0x1c>
# print(state.mem[proj.entry].int.resolved)                   # interpret the memory at the entry point as a C int: <BV32 0x8949ed31>
                                                            # these are bitvectors, not Python ints
# bv = state.solver.BVV(0x1234, 32)                           # create a 32-bit wide bitvector with value 0x1234
# print(bv)                                                   # <BV32 0x1234>
# print(hex(state.solver.eval(bv)))                           # converts back to Python int: 0x1234
x = state.solver.BVS('x', 64)                               # symbolic variables: name_increment_length
y = state.solver.BVS('y', 64)
# print(x, y)                                                 # <BV64 x_0_64> <BV64 y_1_64>
# state.solver.add(x > y)
# state.solver.add(y > 2)
# state.solver.add(10 > x)
# print(state.solver.eval(x))                                 # prints any number 10 > x > y = 2
# input = state.solver.BVS('input', 64)
# print(input)                                                # <BV64 input_2_64>
# operation = (((input + 4) * 3) >> 1) + input
# print(operation)                                            # <BV64 ((input_2_64 + 0x4) * 0x3 >> 0x1) + input_2_64>
# output = 200
# state.solver.add(operation == output)
# print(hex(state.solver.eval(input)))                        # 0x3333333333333381

# simulation managers                                       # used to get sim state to the next point in time
simgr = proj.factory.simulation_manager(state)
# print(simgr)                                                # <SimulationManager with 1 active>
simgr.active                                                # [<SimState @ 0x80484f3>] <-- same
# print(simgr.active[0])                                      # [<SimState @ 0x80484f3>]
simgr.step()                                                # bb's worth of SE. Updated active stash, but not out original state
# print(simgr.active)                                         # [<SimState @ 0x8048370>]
# print(simgr.active[0].regs.eip)                             # <BV32 0x8048370>
# print(state.regs.eip)                                       # <BV32 0x80484f3> <-- same
# while(len(simgr.active) == 1):
#     simgr.step()
# print(simgr)                                                # <SimulationManager with 1 deadended>
# print(simgr.active)                                         # []
# simgr.run()
# print(simgr)                                                # <SimulationManager with 1 deadended>

# generated the CFG
cfg = proj.analyses.CFG()
# print(dict(proj.kb.functions))
# print(type(cfg.graph))

# dynamic CFG
d_cfg = proj.analyses.CFGEmulated(keep_state=True, state_add_options=angr.sim_options.refs)

# view information
print("This is the graph: ", cfg.graph)
print("This is the graph with %d nodes and %d edges" % (len(cfg.graph.nodes()), len(cfg.graph.edges())))

# grabs *any* node at the given location
entry_node = cfg.get_any_node(proj.entry)
entry_func = cfg.kb.functions[proj.entry]
print(entry_node)
print(entry_func.name, hex(entry_func.addr))

# this grabs every node
print("There were %d context(s) for the entry block" % len(cfg.get_all_nodes(proj.entry)))
print(cfg.graph.nodes)

# predecessors and successors
print("Predecessors of the entry point:", entry_node.predecessors)
print("Successors of the entry point:", entry_node.successors)
print("Successors (and type of jump) of the entry point:", [ jumpkind + " to " + str(hex(node.addr)) for node,jumpkind in cfg.get_successors_and_jumpkind(entry_node) ])

# generate CDG
# cdg = proj.analyses.CDG(d_cfg)

# generate DDG *might take a while
# ddg = proj.analyses.DDG(d_cfg)

# supply target to backwards slice
# target_func = d_cfg.kb.functions.function(name='exit')
# target_node = d_cfg.get_any_node(target_func.addr) # ERROR AttributeError: 'NoneType' object has no attribute 'addr'

# generate the backwards slice
# bs = proj.analyses.BackwardSlice(d_cfg, cdg=cdg, ddg=ddg, targets=[(target_node, -1)])
# print(bs)
# bs = proj.analyses.BackwardSlice(cfg, control_flow_slice=True)
# print(bs)

# import os
# os.environ["PATH"] += os.pathsep + 'C:/Program Files (x86)/Graphviz2.38/bin/'

# import angr
# from angrutils import *
# proj = angr.Project("./specrand_base.i386", load_options={'auto_load_libs':False})
# main = proj.loader.main_object.get_symbol("main")
# start_state = proj.factory.blank_state(addr=main.rebased_addr)
# cfg = proj.analyses.CFGEmulated(fail_fast=True, starts=[main.rebased_addr], initial_state=start_state)
# plot_cfg(cfg, "test images/ais3_cfg", asminst=True, remove_imports=True, remove_path_terminator=True)