import angr
import claripy


def hook_demo(state):
    state.regs.eax = 0


p = angr.Project("./issue", load_options={"auto_load_libs": False})
# hook函数：addr为待hook的地址
# hook为hook的处理函数，在执行到addr时，会执行这个函数，同时把当前的state对象作为参数传递过去
# length 为待hook指令的长度，在执行完 hook 函数以后，angr 需要根据 length 来跳过这条指令，执行下一条指令
# hook 0x08048485处的指令（xor eax,eax），等价于将eax设置为0
# hook并不会改变函数逻辑，只是更换实现方式，提升符号执行速度
p.hook(addr=0x08048485, hook=hook_demo, length=2)

#指定开始的位置
state = p.factory.blank_state(addr=0x0804846B, add_options={"SYMBOLIC_WRITE_ADDRESSES"})
# 定义符号变量
u = claripy.BVS("u", 8)
state.memory.store(0x0804A021, u)
sm = p.factory.simulation_manager(state)
# 存在分支，不用avoid
sm.explore(find=0x080484DB)

st = sm.found[0]

print(repr(st.solver.eval(u)))