from binaryninja import *
def get_func_containing(bv, addr):
    """ 根据地址查找对应函数 """
    funcs = bv.get_functions_containing(addr)
    return funcs[0] if funcs else None
def dump_mlil(bv: BinaryView, address: int):
    func: Function = get_func_containing(bv, address)
    cur: MediumLevelILInstruction = func.get_low_level_il_at(address).medium_level_il
    print("当前指令2311133:", cur)
    print("\t指令开始地址:", hex(cur.address))
    print("\t操作符:", cur.operation)
    print("\t操作数:", cur.operands)
    try:
        print("\t操作数中的表达式:", cur.operands[1])
        print("\t\t操作符:", cur.operands[1].operation)
        print("\t\t操作数:", cur.operands[1].operands)
    except Exception as e:
        print(e)
