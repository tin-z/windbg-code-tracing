import pykd
import re
import argparse
import sys


class FB_windbg :
  """
    Function block windbg rapresentation
  """

  match_jmp_sym = r"^([0-9A-f]+) [0-9A-f]+[ ]+(j[A-z]+)[ ]+.*\(([0-9A-f]+)\)$"
  match_jmp_addr = r"^([0-9A-f]+) [0-9A-f]+[ ]+(j[A-z]+)[ ]+([0-9A-f]+)$"
  match_call_sym = r"^([0-9A-f]+) [0-9A-f]+[ ]+(call[A-z]*)[ ]+.*\(([0-9A-f]+)\)$"
  match_call_addr = r"^([0-9A-f]+) [0-9A-f]+[ ]+(call[A-z]*)[ ]+([0-9A-f]+)$"
  match_ret = r"^([0-9A-f]+) [0-9A-f]+[ ]+(ret[A-z]*)[ ]*.*$"

  skip = 0
  is_jmp = 1
  is_call = 2
  is_ret = 4

  match_list = [
    (match_jmp_sym, is_jmp) ,\
    (match_jmp_addr, is_jmp) ,\
    (match_call_sym, is_call) ,\
    (match_call_addr, is_call) ,\
    (match_ret, is_ret)
  ]

  def __init__(self, addr, is_BB=False):
    """
      'is_BB' : is not function block but only basic block, so do not search for return address
    """
    self.addr = addr
    self.is_BB = is_BB
    self.calls = {}
    self.jmps = {}
    self.rets = []
    if not self.is_BB :
      self.__resolve_disasm()
      self.eaddr = max(self.rets)
    else :
      # TODO stuff here
      v1 = pykd.loadDWords(self.addr, 1)
      print("HERE: ", v1)


  def __resolve_disasm(self):
    cmd = "uf 0x{:x}".format(self.addr)
    disas = pykd.dbgCommand(cmd)
    for x in disas.split('\n') :
      self.__find_instr_pattern(x)

  def __find_instr_pattern(self, instr):
    action = FB_windbg.skip

    for x,typ in FB_windbg.match_list :

      rets = re.match(x, instr)
      if rets :
        action = typ
        ret_value = rets.groups()
        break

    if action :
      addr = int(ret_value[0], 16)
      
      if action & FB_windbg.is_ret :
        self.rets.append(addr)

      else :
        target = int(ret_value[2], 16)

        if action & FB_windbg.is_jmp :
          self.jmps.update({target:(addr, ret_value[1])})

        else :
          self.calls.update({target:(addr, ret_value[1])})
      

class cfe_flow(pykd.eventHandler):

  def __init__( 
      self, binary_name, old_baddr, source_point,
      sink_point, control_flow_list, do_not_dec=False, 
      stop_after_reaching_sink=False, debug=False,
      sink_is_bb = False
    ):

    self.binary_name = binary_name
    self.old_baddr = old_baddr
    self.source_point = source_point
    self.sink_point = sink_point
    self.control_flow_list = control_flow_list
    self.FB_dict = {}
    self.do_not_dec = do_not_dec
    self.stop_after_reaching_sink = stop_after_reaching_sink
    self.debug = debug
    self.sink_is_bb = sink_is_bb
    #
    self.__fix_baddr__()
    #
    self.__set_FB()
    #
    self.__set_cf__()
    #
    self.__fix_jmp_noreturn()


  def __set_FB(self) :

    tmp_list = [self.source_point, self.sink_point]

    for x in self.control_flow_list :
      tmp_list += x
    tmp_list = set(tmp_list)

    if self.sink_is_bb :
      tmp_list.remove(self.sink_point)
      self.stop_after_reaching_sink = True
      self.FB_dict.update({self.sink_point: FB_windbg(self.sink_point, is_BB=True)})

    for addr in set(tmp_list) :
      self.FB_dict.update({addr: FB_windbg(addr)})


  def __fix_baddr__(self):

    def fix_addr(x):
      return (x - self.old_baddr) + self.baddr

    info = pykd.dbgCommand("!address {}".format(self.binary_name))
    ret = [x for x in info.split('\n') if x.startswith("Allocation Base:")]
    if not ret :
      raise Exception(
        "Can't find base address of the process spawned from binary '{}'".format(
          self.binary_name
        )
      )
    self.baddr = int(ret[0].split(":")[1].strip(), 16)

    self.source_point = fix_addr(self.source_point)
    self.sink_point = fix_addr(self.sink_point)
 
    for i, x in enumerate(self.control_flow_list) :
      for j, addr in enumerate(x) :
        self.control_flow_list[i][j] = fix_addr(addr)


  def __set_cf__(self):
    self.bp_dict = {}
    self.bp_action = {}
    self.counters = []

    self.backtrace_path = False
    if self.control_flow_list == [] :
      self.backtrace_path = True
      self.control_flow_list = [[self.source_point, self.sink_point]]

    for i, x in enumerate(self.control_flow_list) :
      self.counters.append([])

      for j, addr in enumerate(x) :
        self.counters[-1].append(0)

        if addr not in self.bp_dict :

          enter_action = self.enc_counter(addr, addr == self.sink_point)

          pykd.setBp(addr, enter_action)
          self.bp_dict.update({addr:[]})
          self.bp_action.update({addr:{"enter":enter_action, "leave":[]}})

          if not self.do_not_dec or (addr in [self.source_point,self.sink_point]) :
            FB_now = self.FB_dict[addr]
            eaddr = FB_now.rets

            if not eaddr and not FB_now.is_BB :
              print("[!] Can't find last address of the function located at 0x{:x}.\nInsert it (if multiple use ',' as the separator):".format(addr))
              eaddr = input("")

              if isinstance(eaddr, tuple):
                eaddr = list(eaddr)

              elif isinstance(eaddr, int) or isinstance(eaddr, long):
                eaddr = [eaddr]

              elif isinstance(eaddr, str):
                for eaddr_now in eaddr.strip().split(",") :
                  eaddr_now = eaddr_now.strip()
                  base = 16 if eaddr_now.startswith("0x") else 10
                  eaddr.append(int(eaddr_now, base))

              else :
                raise Exception("[X] Can't parse the input given")

              FB_now.rets = eaddr

            for eaddr_now in eaddr :
              leave_action = self.dec_counter(addr, addr == self.source_point)
              pykd.setBp(eaddr_now, leave_action)
              self.bp_action[addr]["leave"].append(leave_action)

        self.bp_dict[addr].append((i,j))


  def __fix_jmp_noreturn(self) :        
    for i, x in enumerate(self.control_flow_list) :
      prec_FB = self.FB_dict[x[0]]
      for j, addr in enumerate(x) :
        FB_now = self.FB_dict[addr]
        if j == 0 :
          continue

        # addr was run using a jmp
        if addr not in prec_FB.calls :
          output_addr = []
          output_prec_addr = []

          for prec_i, prec_j in self.bp_dict[prec_FB.addr] :
            if i == prec_i :
              output_addr.append((prec_i, prec_j))
            else :
              output_prec_addr.append((prec_i, prec_j))

          self.bp_dict[prec_FB.addr] = output_prec_addr
          self.bp_dict[addr] += output_addr


  def check_counter(self, index_i, index_j, cc, addr, is_ret=False):
    if (cc < 0):
      print("[x] Index counters:({},{}). Invalid counter '{}' on address '0x{:x}' (is_ret:{})".format(
        index_i, index_j, cc, addr, is_ret
      ))
      print(self.counters)
      print(self.bp_dict)
      raise Exception()


  def enc_counter(self, addr, is_sink_point=False):
    def _enc_counter(bp):

      if self.debug :
        print("[enter] 0x{:x} hit (is_sink_point:{})".format(addr, is_sink_point))

      for i,j in self.bp_dict[addr] :
        self.check_counter(i,j, self.counters[i][j], addr)
        self.counters[i][j] += 1
      if is_sink_point :
        self.print_counters()
      return False

    return _enc_counter


  def dec_counter(self, addr, is_source_point=False):
    def _dec_counter(bp):

      if self.debug :
        print("[return] 0x{:x} hit".format(addr))

      for i,j in self.bp_dict[addr] :
        self.counters[i][j] -= 1
        self.check_counter(i,j,self.counters[i][j], addr, is_ret=True)
      if is_source_point :
        self.reset_counters()
      return False

    return _dec_counter

  def reset_counters(self):
    for addr in self.bp_dict :
      for i,j in self.bp_dict[addr] :
        self.check_counter(i,j,self.counters[i][j], addr)
        self.counters[i][j] = 0

  def print_counters(self):
    if self.backtrace_path :
      return self.print_backtrace()

    output = []
    for i,x in enumerate(self.counters) :
      if sum([1 for y in x if y > 0]) == len(x) :
        output.append(i)

    if not output :
      print("[-] No path found yet")
    else :
      print("[+] Path reached:")
      for i in output :
        print(" \---> '{}'".format(", ".join([hex(x) for x in self.control_flow_list[i]])))
    print("")
    
    if self.stop_after_reaching_sink :
      self.disable_bp()


  def print_backtrace(self):
    if self.counters[0][0] == 0 :
      print("[-] No path found yet")
    else :
      print("[+] Path reached:")
      print(pykd.dbgCommand("k"))
    print("")
    if self.stop_after_reaching_sink :
      self.disable_bp()


  def disable_bp(self):
    cmd = "bd *"
    pykd.dbgCommand(cmd)


if __name__ == "__main__":
  parser = argparse.ArgumentParser(description="Trace control flow executed from source to sink point")
  parser.add_argument("--source", required=True, help="Source point address")
  parser.add_argument("--sink", required=True, help="Sink point address")
  parser.add_argument("--binary_name", required=True, help="Binary file name")
  parser.add_argument("--old_baddr", required=True, help="Base address used on the variable 'chains' which does represent addresses to trace")
  parser.add_argument("--chains", required=True, help="List of addresses (path) to trace")
  parser.add_argument("--sink_is_bb", default=False, action="store_true", help="Sink point is a basic block (BB) and not a function block (FB)")
  parser.add_argument("--debug", default=False, action="store_true", help="increase output verbosity (default: False)")
  parser.add_argument("--stop", default=True, action="store_false", help="Stop after reachng sink point (default: True)")
  parser.add_argument("--dec", default=True, action="store_false", help=
    "Do not decrement counters after leaving a FB, this can put less pressure on control-flow path restrictions (default: True)"
  )
  args=parser.parse_args()
  source = args.source

  sink = args.sink
  binary_name = args.binary_name.strip()
  old_baddr = args.old_baddr
  chains = args.chains
  
  regular_hex = r"([ 0-9xXA-f]+)"
  regular_hex_list = r"([ ,0-9\[\]xXA-f]+)"

  for x in ["source", "sink", "old_baddr", "chains"] :
    reg_now = regular_hex if x != "chains" else regular_hex_list
    var_now = globals()[x]

    if len(re.match(reg_now, var_now).groups()[0]) != len(var_now) :
      print("[x] Invalid argument '--{}' ..quit".format(x))
      sys.exit(-1)

    globals()[x] = eval(var_now)

  cfe_flow_now = cfe_flow(
    binary_name, old_baddr, source, sink, chains, do_not_dec=args.dec, 
    stop_after_reaching_sink=args.stop, debug=args.debug,
    sink_is_bb = args.sink_is_bb
  )

  pykd.go()


