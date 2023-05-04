import angr

from angrutils import *

# CHANGE BOTH OF THESE
sample = './testing inputs/test.o'
target = '[esp + 0x20]'

# sample = './testing inputs/test1.o'
# target = '[esp + 0x24]'

# tree
class BinaryTree:
    def __init__(self, name, data):
        self.name = name
        self.data = data
        self.leftChild = None
        self.rightChild = None
    
    def hasLeftChild(self):
        return self.leftChild
    
    def hasRightChild(self):
        return self.rightChild

def angr_cfg(sample):
    # load project
    proj = angr.Project(sample, load_options={'auto_load_libs': False})
    main = proj.loader.main_object.get_symbol('main')
    address = main.rebased_addr

    # states
    head = proj.factory.blank_state(addr=address)

    # cfg
    cfg = proj.analyses.CFGEmulated(starts=[address], initial_state=head)
    for addr, func in proj.kb.functions.items():
        if func.name in ['main']:
            plot_cfg(cfg, './test images/%s_before_cfg' % (func.name), asminst=True, func_addr={address:True}, remove_imports=True, remove_path_terminator=True)

    # reading instructions
    f = open('./instruction files/temp.txt', 'w')
    for n in cfg.graph.nodes():
        if n.name is not None and 'main' in n.name:
            block = proj.factory.block(n.addr)
            cap = block.capstone
            f.write(str(hex(cap.addr)) + '\n')
            for i in cap.insns:
                if ('mov' in i.insn.mnemonic or
                    'fild' in i.insn.mnemonic or 
                    'cmp' in i.insn.mnemonic or 
                    'fucomip' in i.insn.mnemonic or 
                    'jle' in i.insn.mnemonic or
                    'add' in i.insn.mnemonic or
                    'sub' in i.insn.mnemonic):
                    f.write(str(hex(i.insn.address)) + ' ' + i.insn.mnemonic + ' ' + i.insn.op_str + '\n')
    f.close()

    # removing duplicate lines
    lines_seen = set()
    out_f = open('./instruction files/instructions.txt', 'w')
    for line in open('./instruction files/temp.txt', 'r+'):
        if line not in lines_seen:
            out_f.write(line)
            lines_seen.add(line)
    out_f.close()

    # building the SE Tree
    root = 0
    final = 0
    bb_addr = 0
    tree_data = []
    var = 0
    counter = 0
    with open('./instruction files/instructions.txt', 'r+') as in_f:
        lines = in_f.readlines()
        for i in range(0, len(lines)):
            line = lines[i]
            addr_len = len(lines[0])
            if len(line) == len(lines[0]):
                if (i + 1) < len(lines):
                    if len(lines[i+1]) == addr_len:
                        continue
                bb_addr = line.strip()
                tree_data = []
            if 'dword' in line:
                var = '[' + line.strip().partition('[')[2]
                tree_data.append(var)
            if 'add' in line or 'sub' in line:
                var = line[9:].strip()
                tree_data.append(var)
            if 'cmp' in line or 'fucomip' in line:
                if 'jle' in lines[i+1].strip():
                    tree_data = []
                    continue
                if root == 0:
                    root = BinaryTree(bb_addr, tree_data)
                else:
                    curr = root
                    while curr.hasLeftChild() is not None:
                        curr = curr.leftChild
                    new = BinaryTree(bb_addr, tree_data)
                    curr.leftChild = new
                    beg = i + 1
                    if (beg + 1) >= len(lines) - 1:
                        end = beg
                    else: 
                        end = beg + 1
                    while len(lines[end]) != addr_len:
                        end += 1
                    read_addr = lines[beg].strip()
                    read_data = []
                    for j in range(beg + 1, end):
                        new_data = '[' + lines[j].strip().partition('[')[2]
                        read_data.append(new_data)
                    new = BinaryTree(read_addr, read_data)
                    curr.rightChild = new
            if target in line:
                if counter == 0:
                    final = root
                    while final.hasLeftChild() is not None:
                        final = final.leftChild
                    new = BinaryTree(bb_addr, tree_data)
                    final.leftChild = new
                    tree_data = []
                    counter += 1
                elif final.leftChild.name != bb_addr:
                    new = BinaryTree(bb_addr, tree_data)
                    final.rightChild = new
                    tree_data = []
                    counter = 0
    
    # logging possible paths
    p_paths = []
    depth = 0
    curr = root
    entries_seen = set()
    for i in range(0, len(curr.leftChild.data) - 1):
        if (curr.leftChild.name, curr.leftChild.data[i]) not in entries_seen:
            entries_seen.add((curr.leftChild.name, curr.leftChild.data[i]))
    while curr.hasLeftChild() is not None and curr.hasRightChild() is not None:
        for i in range(0, len(curr.leftChild.data) - 1):
            if (curr.leftChild.name, curr.leftChild.data[i]) not in entries_seen:
                entries_seen.add((curr.leftChild.name, curr.leftChild.data[i]))
        curr = curr.leftChild
        depth += 1
    for i in range(0, 2**(depth+1)):
        b = bin(i)[2:].zfill(depth + 1)
        p_paths.append(b)
    cnt = 0
    curr = root
    seen = [''] * len(p_paths)
    for i in range(0, len(p_paths)):
        if p_paths[i][0] == '0':
            seen[i] += '|'+ curr.name + ' ' + curr.data[-1]
        else:
            seen[i] += '|' + curr.name + ' !' + curr.data[-1]
    cnt += 1

    # logging the entries
    from_node = []
    to_node = []
    from_addr = []
    to_addr = []
    # print(curr.name, curr.data)
    while curr.hasLeftChild() is not None and curr.hasRightChild() is not None:
        for i in range(0, len(p_paths)):
            if p_paths[i][cnt:cnt+1] == '0':
                seen[i] += '|'+ curr.leftChild.name + ' ' + curr.leftChild.data[-1]
                for x in entries_seen:
                    if curr.leftChild.data[-1] in x[1]:
                        from_addr.append(int(x[0], 16))
                        to_addr.append(int(curr.leftChild.leftChild.name, 16))
            else:
                seen[i] += '|' + curr.rightChild.name + ' !' + curr.leftChild.data[-1]
        # print(curr.leftChild.name, curr.leftChild.data)
        # print(curr.rightChild.name, curr.rightChild.data)
        cnt +=1
        curr = curr.leftChild
    # for x in from_addr:
    #     print(hex(x))
    # for x in to_addr:
    #     print(hex(x))
    
    # creating the edge
    for n in cfg.graph.nodes():
        if 'main' in n.name:
            if n.addr in from_addr:
                for i in range(0, len(from_addr)):
                    if from_addr[i] == n.addr:
                        from_node.append(n)
            if n.addr in to_addr:
                for i in range(0, len(to_addr)):
                    if to_addr[i] == n.addr:
                        to_node.append(n)

    for i in range(0, len(from_node)):
        # print(from_node[i], to_node[i])
        cfg.graph.add_edge(from_node[i], to_node[i])

    for addr, func in proj.kb.functions.items():
        if func.name in ['main']:
            plot_cfg(cfg, './test images/%s_after_cfg' % (func.name), asminst=True, func_addr={address:True}, remove_imports=True, remove_path_terminator=True)

if __name__ == '__main__':
    angr_cfg(sample)