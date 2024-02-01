from binaryninja import *
from pprint import *
from ctypes import *
from struct import *
def get_func_containing(bv, addr):
    """ 根据地址查找对应函数 """
    funcs = bv.get_functions_containing(addr)
    return funcs[0] if funcs else None

class Definition:
    def __init__(self,bt:BranchType,val:c_int32) -> None:
        self._bt=bt
        self._val=val
        
class fuckObf:   
    def __init__(self,mfunc) -> None:
        self.m_func=mfunc
        
    def find_control_value_in_medium(self, main_dispatcher: BasicBlock) -> Optional[Variable]:
        m_block = self.find_m_block(main_dispatcher)
        if m_block is None:
            raise Exception
        set_var = m_block[0]
        if isinstance(set_var, MediumLevelILSetVar):
            return set_var.src.operands[0]
        return None
    
    def resolve_set_var(self, var_obj) -> Dict[int, List[Definition]]:
        if isinstance(var_obj, MediumLevelILConst):
            return {var_obj.il_basic_block.source_block.start: [Definition(BranchType.UnconditionalBranch,
                                                                        c_int32(var_obj.constant).value)]}
        elif isinstance(var_obj, MediumLevelILVar):
            result = {}
            definition: MediumLevelILSetVar
            for definition in self.m_func.get_var_definitions(var_obj.src):
                tmp = self.resolve_set_var(definition.src)
                condition = definition.il_basic_block.incoming_edges[0].type
                for block_start, value in tmp.items():
                    for _ in value:
                        _.condition = condition
                    if block_start in result:
                        result[block_start] += value
                    else:
                        result[block_start] = value
            return result
        raise Exception

class Cmp(object):
    class Operation(Enum):
        EQ = 0
        NE = 1
        GT = 2
        GE = 3
        LT = 4
        LE = 5
        UN = 6

    def __init__(self, operation: Operation, constant_operand: int):
        self.operation = operation
        self.constant_operand = constant_operand
        self.true = None
        self.false = None

    def set_true(self, true: "Cmp"):
        self.true = true

    def set_false(self, false: "Cmp"):
        self.false = false

    def eval(self, x: int) -> Optional[bool]:
        match self.operation:
            case self.Operation.EQ:
                return x == self.constant_operand
            case self.Operation.NE:
                return x != self.constant_operand
            case self.Operation.GT:
                return x > self.constant_operand
            case self.Operation.GE:
                return x >= self.constant_operand
            case self.Operation.LT:
                return x < self.constant_operand
            case self.Operation.LE:
                return x <= self.constant_operand
            case self.Operation.UN:
                return None

    def __str__(self):
        result = ""
        if self.operation != self.Operation.UN:
            result += "x"
            match self.operation:
                case self.Operation.EQ:
                    result += " == "
                case self.Operation.NE:
                    result += " != "
                case self.Operation.GT:
                    result += " > "
                case self.Operation.GE:
                    result += " >= "
                case self.Operation.LT:
                    result += " < "
                case self.Operation.LE:
                    result += " <= "
        result += "0x%08x" % c_uint32(self.constant_operand).value
        return result

    def __repr__(self):
        return str(self)

def resolve_set_var(mlil, var_obj) -> Dict[int, List[Definition]]:
        if isinstance(var_obj, MediumLevelILConst):
            return {var_obj.il_basic_block.source_block.start: [Definition(BranchType.UnconditionalBranch,
                                                                        c_int32(var_obj.constant).value)]}
        elif isinstance(var_obj, MediumLevelILVar):
            result = {}
            definition: MediumLevelILSetVar
            for definition in mlil.get_var_definitions(var_obj.src):
                tmp = resolve_set_var(mlil,definition.src)
                condition = definition.il_basic_block.incoming_edges[0].type

                for block_start, value in tmp.items():
                    for _ in value:
                        _.condition = condition
                    if block_start in result:
                        result[block_start] += value
                    else:
                        result[block_start] = value
            return result
        raise Exception

def compute_backbone_map(bv, mlil, state_var):
    """ Recover the map of state values to backbone blocks

    This will generate a map of
    {
        state1 => BasicBlock1,
        state2 => BasicBlock2,
        ...
    }

    Where BasicBlock1 is the block in the backbone that will dispatch to
    an original block if the state is currently equal to state1

    Args:
        bv (BinaryView)
        mlil (MediumLevelILFunction): The MLIL for the function to be deflattened
        state_var (Variable): The state variable in the MLIL

    Returns:
        dict: map of {state value => backbone block}
    """
    backbone = {}

    # The state variable itself isn't always the one referenced in the
    # backbone blocks, they may instead use another pointer to it.
    # Find the variable that all subdispatchers use in comparisons
    var=None
    if isinstance(state_var,MediumLevelILVar):
        var = state_var.src
    else:
        var = state_var

    uses = mlil.get_var_uses(var)
    # The variable with >2 uses is probable the one in the backbone blocks
    while len(uses) <= 2:
        var = mlil[uses[-1]].dest
        uses = mlil.get_var_uses(var)
    uses += mlil.get_var_definitions(var)
    blks=[];
    # Gather the blocks where this variable is used
    # blks = (b for idx in uses for b in mlil.basic_blocks if b.start <= idx < b.end)
    '''
    for idx in uses:
        # print("used address:{%x} {}"%idx.instr_index)
        print(idx)
        for b in mlil.basic_blocks:
            # print("bb:{%x}{%x}"%(b.start,b.end))
            if b.start <= idx.instr_index < b.end:
                blks.append(b)
                # print("{%x}{%s}"%(b[0].address,b[0]))
            # if b.function.address_ranges[0].start<=idx.address <b.function.address_ranges[0].end:
                # blks.append(b)
    '''
    switch_case_values = {}
    set_var: MediumLevelILSetVar
    for set_var in uses:
        tmp={}
        if isinstance(set_var,MediumLevelILSetVar):
            tmp=resolve_set_var(mlil,set_var.src)
        elif isinstance(set_var,MediumLevelILCall):
            tmp=resolve_set_var(mlil,set_var.params[1])
        for block_start, values in tmp.items():
            if block_start in switch_case_values:
                switch_case_values[block_start] += values
            else:
                switch_case_values[block_start] = values




    # In each of these blocks, find the value of the state
    '''
    set_var = blks[0]
    if isinstance(set_var[0], MediumLevelILSetVar):
        srsc= set_var[0]
        # .src.operands[0]
        print(srsc)
    ''' 
    
    '''
    for bb in blks:
        # Find the comparison
        mlil_if = bb[-1]
        cmp_il = mlil_if.condition

        print(cmp_il.right)
        # .src
        # cmp_il = mlil[mlil.get_var_definitions(cmp_var.right)[0]]

        # Pull out the state value
        state = cmp_il.right.constant
        backbone[state] = bv.get_basic_blocks_at(bb[0].address)[0]
    '''
    return backbone


def resolve_switch_var_definitions(m_func_mlil ,switch_var: Variable) -> Dict[int, List[Definition]]:
    switch_case_values = {}
    switch_case_definitions = m_func_mlil.get_var_definitions(switch_var)
    set_var: MediumLevelILSetVar
    for set_var in switch_case_definitions:
        tmp = resolve_set_var(m_func_mlil,set_var.src)
        for block_start, values in tmp.items():
            if block_start in switch_case_values:
                switch_case_values[block_start] += values
            else:
                switch_case_values[block_start] = values
    may_definitions = m_func_mlil.get_var_uses(switch_var)
    for may_definition in may_definitions:
        if isinstance(may_definition, MediumLevelILSetVar):
            continue
        elif isinstance(may_definition, MediumLevelILCall):
            value = unpack("<i", bytes(may_definition.params[1].operands[0].data))[0]
            switch_case_values[may_definition.il_basic_block.source_block.start] = [
                Definition(BranchType.UnconditionalBranch, value)]
        else:
            raise Exception
    return switch_case_values



def dump_mlil(bv: BinaryView, address: int):
    func: Function = get_func_containing(bv, address)
    mlil=func.medium_level_il
    cur: MediumLevelILInstruction = func.get_low_level_il_at(address).medium_level_il
    state_var=cur.src
    print("当前指令Fuck:", cur.dest)
    print("\t指令开始地址:", hex(cur.address))
    print("\t操作符:", cur.operation)
    print("\t操作数:", cur.operands)
    # backbone = compute_backbone_map(bv,mlil,state_var)
    sw=resolve_switch_var_definitions(mlil,state_var.src)



    print( '[+] Computed backbone:{%d}'%len(sw))
    pprint(sw)
    

    try:
        print("\t操作数中的表达式:", cur.operands[1])
        print("\t\t操作符:", cur.operands[1].operation)
        print("\t\t操作数:", cur.operands[1].operands)
    except Exception as e:
        print(e)
