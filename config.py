import argparse
import sys
import netifaces
from util import get_iface_name_by_addr
import random
from copy import deepcopy

from rules import Rule


#mode 3 filter protocols
PROTOCOLS = { 0:"HOTOPT", 1:"ICMP", 4:"IPv4", 6:"TCP", 17:"UDP", 132:"SCTP", 999:"ALL" }


class FilterConfig:
	"""
	A base class for all filter mode configurations
	"""
	def __init__(self, args_parse_results):

		self.in_ip     = args_parse_results.in_ip
		self.out_ip    = args_parse_results.out_ip
		self.in_iface  = args_parse_results.in_iface
		self.out_iface = args_parse_results.out_iface
		self.mode      = args_parse_results.mode

	def update(self):
		pass

	def update_timeout(self):
		"""
		set a new timeout
		"""
		pass

	def update_rules(self):
		pass

	def __str__(self):
		return \
			"    %-30s:%s\n    %-30s:%s\n    %-30s:%s\n    %-30s:%s\n" %\
			('IN_IP', self.in_ip, 'OUT_IP', self.out_ip, 'IN_IFACE',\
				self.in_iface, 'OUT_IFACE', self.out_iface)

class ModeZeroFilterConfig(FilterConfig):
	"""
	Mode 0 (Gateway) configurations

	- In this mode, the filter acts as a gateway (forwards packets without applying any rules)
	"""
	def __init__(self, args_parse_results):
		super(ModeZeroFilterConfig, self).__init__(args_parse_results)
		self.mode_name = 'GATEWAY - MODE 0'

	def __str__(self):
		return \
			"%s    %-30s:%s" % \
			(super(ModeZeroFilterConfig, self).__str__(), 'MODE', self.mode_name)

class ModeOneFilterConfig(FilterConfig):
	"""
	MOde 1 (Normal/Static mode) configurations

	- This is the simplest mode. To run the filter in this mode, '1' should 
	  be provided as argument to -m option. In this mode, the filter receives a list
	  of rule numbers from the user and uses those rules throughout the filtering session.
	- For instance,
		python3 main.py -m 1 -i 192.168.1.1 -o 192.168.1.2 -n 5 -l 4,7,9,11,55
	"""
	def __init__(self, args_parse_results):
		super(ModeOneFilterConfig, self).__init__(args_parse_results)

		# a list of rules
		self.mode_name   = 'NORMAL/STATIC - MODE 1'
		self.rules       = args_parse_results.rules
		self.rule_nums   = args_parse_results.rule_nums
		self.rules_count = args_parse_results.rules_count

	def __str__(self):
		return \
			"%s    %-30s:%s\n    %-30s:%s\n    %-30s:%d" % \
			(super(ModeOneFilterConfig, self).__str__(), 'MODE', self.mode_name,\
				'RULE NUMBERS', ' '.join(map(str,self.rule_nums)),\
				'NO. OF RULES', self.rules_count)

class ModeTwoFilterConfig(FilterConfig):
	"""
	Mode 2 (Random mode) configurations

	- This is mode two. Just like the name suggests, the rules used are generated randomly.
	  Its also possible to provide TIMEOUT (in seconds), after which new rules are generated 
	  again randomly. To disable timing, use 0 seconds for the TIMEOUT or fail to provide -t at start up.
	- If timing is disabled, the rules are never renewed throughtout the filtering session.
	- The following are somethe ways the filter can be run in random mode.
	  	python3 main.py -m 2 -i 192.168.1.1 -o 192.168.1.2 -t 20 -n 5 
	"""
	def __init__(self, args_parse_results):
		super(ModeTwoFilterConfig, self).__init__(args_parse_results)
		self.mode_name   = 'RANDOM - MODE 2'
		self.timeout     = args_parse_results.timeout
		self.rules_count = args_parse_results.rules_count
		self.rules       = args_parse_results.rules
		self.rule_nums   = args_parse_results.rule_nums

	def update(self):
		self.update_rules()

	def update_rules(self):
		"""
		create a new list of random rules.
		"""
		self.rule_nums   = Rule.get_rules_randomly(self.rules_count)
		print('    # initializing rules.', end=' ')
		self.rules       = Rule.get_rules_from_nums(self.rule_nums)

	def __str__(self):
		return \
			"%s    %-30s:%s\n    %-30s:%s\n    %-30s:%d\n    %-30s:%d s" % \
			(super(ModeTwoFilterConfig, self).__str__(), 'MODE', self.mode_name,\
				'CURRENT RULE NUMBERS', ' '.join(map(str,self.rule_nums)),\
				'NO. OF RULES', self.rules_count,'TIMEOUT', self.timeout)

class ModeThreeFilterConfig(FilterConfig):
	"""
	Mode 3 (Increment randomly) configurations

	- There are times the user would like to extend the capabilities of mode two.
	- Mode 3 makes it possible to increase the rules being used instead of
	  renewing them after TIMEOUT. In mode three, its also possible to increase the rules
	  after a certain no. of packets of type -prt PROTOCOL have hit the filter.
	- This mode expects the user to specify -prt PROTOCOL, -pkt NO_OF_PKTS and 
	  -r NO_OF_INCR_RULES or provide them from STDIN during filter execution. NO_OF_PKTS 
	  take priority i.e if the TIMEOUT elapses before NO_OF_PKTS number of packets hit the 
	  filter, the timer continues to wait for a signal (event) from the packet counter.

	- To simplify how mode 3 works, I'll use the following example.
		python3 main.py -m 3 -i 192.168.1.1 -o 192.168.1.2 -n 5 -I 2 -t 20 -P 1 -pn 50 
	"""
	def __init__(self, args_parse_results):
		super(ModeThreeFilterConfig, self).__init__(args_parse_results)
		self.mode_name        = 'INCREMENT_RANDOMLY - MODE 3'
		self.rules_count      = args_parse_results.rules_count
		self.rules            = args_parse_results.rules
		self.rule_nums        = args_parse_results.rule_nums
		self.timeout          = args_parse_results.timeout
		# no. of rules to be chosen(and added to curr_rules) randomly after timeout
		self.incr_rules_count = args_parse_results.incr_rules_count
		# the max. no of packets expected before the filter adds more self.incr_rules_count rules
		self.max_pkts_count   = args_parse_results.max_pkts_count
		# protocol to be considered when counting packets
		self.proto            = args_parse_results.proto

	def update(self):
		self.update_rules()

	def update_rules(self):

		print('\n    ' + '#'*90)
		new_rule_nums = Rule.get_new_rules_randomly(\
			self.incr_rules_count, self.rule_nums)

		#new_rule_nums.sort()

		#add new rule numbers to self._rule_nums
		print("    # adding", self.incr_rules_count, " more rule(s)")

		#instantiate new rules, add them to self._rules
		[ self.rule_nums.append(rn) for rn in new_rule_nums ]
		print('    # initializing rules.', end=' ')
		[ self.rules.append(r) for r in Rule.get_rules_from_nums(new_rule_nums) ]

		self.rule_nums.sort()
		self.rules_count = len(self.rule_nums)

		#self._rule_nums.sort()
		print("    # rules added ==> ", ' '.join(map(str, new_rule_nums)))
		print("    # new rules list ==> %s" % ' '.join(map(str, self.rule_nums)))
		print("    # new rules count ==> %d" % self.rules_count)

	def __str__(self):
		return \
			"%s    %-30s:%s\n    %-30s:%s\n    %-30s:%d\n    %-30s:%d s\n    %-30s:%d\n    %-30s:%d\n    %-30s:%s" % \
			(super(ModeThreeFilterConfig, self).__str__(), 'MODE', self.mode_name,\
				'CURRENT RULE NUMBERS', ' '.join(map(str,self.rule_nums)),\
				'CURRENT NO. OF RULES', self.rules_count,'TIMEOUT', self.timeout,\
				'NO. OF INCR RULES', self.incr_rules_count, 'MAX. PACKETS COUNT', self.max_pkts_count, \
				'PROTOCOL', self.proto)

class ModeFourFilterConfig(FilterConfig):
	"""
	Mode 4 (Random Dynamic) configurations

	- This is an extension of mode 2 (Random). Mode 2 picks some defined no. of rules
	  at start up and maintains that list of rules throughout the entire filter operation.
	- Mode 4 (Random Dynamic) on the other hand picks some defined no. of rules randomly at start up
	  and updates the list with some random rules after a randomly set timeout.
	- The timeout is updated to a random value every time the rules are updated too.
	- For instance:
		python3 main.py -i 192.168.1.1 -o 192.168.1.2 -m 4 -tr 2-5 -nr 3-5
	"""
	def __init__(self, args_parse_results):
		super(ModeFourFilterConfig, self).__init__(args_parse_results)
		self.mode_name         = 'RANDOM_DYNAMIC - MODE 4'
		self.timeout_range     = args_parse_results.timeout_range
		self.rules_count_range = args_parse_results.rules_count_range
		self.timeout           = args_parse_results.timeout
		self.rules_count       = args_parse_results.rules_count
		self.rules             = args_parse_results.rules
		self.rule_nums         = args_parse_results.rule_nums


	def __str__(self):
		return \
			"%s    %-30s:%s\n    %-30s:%s\n    %-30s:%d\n    %-30s:%d s\n    %-30s:%s (s)\n    %-30s:%s" % \
			(super(ModeFourFilterConfig, self).__str__(), 'MODE', self.mode_name,\
				'CURRENT RULE NUMBERS', ' '.join(map(str,self.rule_nums)),\
				'CURRENT NO. OF RULES', self.rules_count,'CURRENT TIMEOUT', self.timeout,\
				'TIMEOUT RANGE', ' - '.join(map(str, self.timeout_range)),\
				'RULES COUNT RANGE', ' - '.join(map(str, self.rules_count_range)))


	def update(self):
		self.update_timeout()
		self.update_rules()

	def update_timeout(self):
		"""
		set a new timeout
		"""
		print('    # generating new timeout.')
		self.timeout = random.randint(self.timeout_range[0], self.timeout_range[1])

	def update_rules(self):
		"""
		Set rules count to a new random value and create a new list
		of random rules.
		"""
		print('    # generating new rules count.')
		self.rules_count = random.randint(self.rules_count_range[0], self.rules_count_range[1])
		#print('    # generating %d r')
		self.rule_nums   = Rule.get_rules_randomly(self.rules_count)
		print('    # initializing rules.', end=' ')
		self.rules       = Rule.get_rules_from_nums(self.rule_nums)

class ModeFiveFilterConfig(FilterConfig):

	def __init__(self, parse_res):
		super(ModeFiveFilterConfig, self).__init__(parse_res)
		self.win_size       = parse_res.win_size
		self.t_win_trig     = parse_res.t_win_trig
		self.inactive_cp    = parse_res.inactive_cp
		self.inactive_set   = parse_res.inactive_set
		self.init_ia_set    = deepcopy(parse_res.inactive_set)
		self.inactive_rules = parse_res.inactive_rules
		self.active_p       = parse_res.active_p
		self.active_set     = parse_res.active_set
		self.init_a_set     = deepcopy(parse_res.active_set)
		self.active_rules   = parse_res.active_rules
		self.mode_name      = "ADAPTIVE | MODE 5"

	def __str__(self):
		return "%s    %-30s:%s\n    %-30s:%s s\n    %-30s:%s\n    %-30s:%s\n    %-30s:%s\n    %-30s:%s\n    %-30s:%s\n    %-30s:%s\n    %-30s:%s\n" %\
			(super().__str__(), "MODE", self.mode_name, "WINDOW_SIZE", self.win_size, "THRESHOLD_WIN_TRIG", self.t_win_trig,\
				"INITIAL INACTIVE_SET", self.inactive_set, "INITIAL ACTIVE_SET", self.active_set,\
				"INACTIVE_SET / TOTAL (%)", self.inactive_cp, "ACTIVE_SET / TOTAL (%)", self.active_p, "CURRENT INACTIVE_SET",\
				self.init_ia_set, "CURRENT ACTIVE_SET", self.init_a_set)

###############################################################################
# UTILITY PARSE FUNCTIONS
###############################################################################
def get_mode_zero_config(p_result):
	return ModeZeroFilterConfig(p_result)

def get_mode_one_config(parser, p_result):

	issues = ''
	if not p_result.rules_count:
		issues += "    - no. of rules not provided.\n"

	if not p_result.rule_nums:
		issues += "    - rule numbers (comma-seperated) not provided.\n"

	if issues:
		print('[-] issues:\n' + issues)
		parser.print_usage()
		sys.exit(0)

	if p_result.rules_count == 'all':
		p_result.rules_count = Rule.num_of_rules()
		p_result.rules       = list(Rule.get_all_rules().keys())

	else:
		p_result.rule_nums   = [ int(i) for i in p_result.rule_nums.split(',') if i ]
		p_result.rules_count = len(p_result.rule_nums)
		print('    # initializing rules', end='')
		p_result.rules       = Rule.get_rules_from_nums(p_result.rule_nums)

	return ModeOneFilterConfig(p_result)

def get_mode_two_config(parser, p_result):

	issues = ''

	if not p_result.timeout:
		issues += '    - filter timeout not provided.\n'

	if not p_result.rules_count:
		issues += '    - no. of rules not provided.\n'

	if issues:
		print('[-] issues:\n' + issues)
		parser.print_usage()
		sys.exit(0)

	p_result.rules_count = int(p_result.rules_count)
	p_result.rule_nums   = Rule.get_rules_randomly(p_result.rules_count)
	# adds a new member variable
	print('    # initializing rules', end=' ')
	p_result.rules       = Rule.get_rules_from_nums(p_result.rule_nums)

	return ModeTwoFilterConfig(p_result)
	
def get_mode_three_config(parser, p_result):
	
	issues = ''

	if not p_result.timeout:
		issues += '    - filter timeout not provided.\n'

	if not p_result.rules_count:
		issues += '    - initial no. of rules not provided.\n'
	else:
		p_result.rules_count = int(p_result.rules_count)


	if not p_result.proto:
		issues += '    - protocol not provided.\n'
	elif not p_result.proto in PROTOCOLS.keys():
		issues += '    - invalid protocol.\n'
	else:
		pass

	if not p_result.max_pkts_count:
		issues += '    - max. packet count before incrementing rules not provided.\n'

	if not p_result.incr_rules_count:
		issues += '    - no. of rules to be incremented after timeout not provided.\n'
	elif p_result.rules_count:
		if p_result.incr_rules_count > (Rule.num_of_rules() - p_result.rules_count):
			issues += '    - no. of increment rules too high.\n'
		else:
			pass

	if issues:
		print('[-] issues:\n' + issues)
		parser.print_usage()
		sys.exit(0)

	print('    # generating random rule numbers.')
	p_result.rule_nums   = Rule.get_rules_randomly(p_result.rules_count)
	# adds a new member variable
	print('    # initializing rules', end=' ')
	p_result.rules       = Rule.get_rules_from_nums(p_result.rule_nums)
	p_result.proto       = PROTOCOLS[p_result.proto]

	return ModeThreeFilterConfig(p_result)

def get_mode_four_config(parser, p_result):
	
	issues = ''
	
	if not p_result.rules_count_range:
		issues += '    - rules count range not provided.\n'
	else:
		try:
			nr = [ int(i) for i in p_result.rules_count_range.split('-') ]
			if nr[0] < 1 or nr[1] > Rule.num_of_rules():
				issues += '    - invalid rules count range.\n'
			else:
				# set ranges
				p_result.rules_count_range = tuple(nr)

		except ValueError:
			issues += '    - invalid rules count range.\n'

	if not p_result.timeout_range:
		issues += '    - timeout range not provided.\n'
	else:
		try:
			tr = [ int(i) for i in p_result.timeout_range.split('-') ]
			if tr[0] < 1:
				issues += '    - invalid timeout range.\n'
			else:
				# set ranges
				p_result.timeout_range = tuple(tr)

		except ValueError:
			issues += '    - invalid timeout range.\n'

	if issues:
		print('[-] issues:\n' + issues)
		parser.print_usage()
		sys.exit(0)

	# initial timeout
	print('    # generating random timeout.')
	p_result.timeout     = random.randint(p_result.timeout_range[0], p_result.timeout_range[1])
	# initial rules count - random from range
	print('    # generating random rules count (no. of rules).')
	p_result.rules_count = random.randint(p_result.rules_count_range[0], p_result.rules_count_range[1])
	# initial rule numbers
	print('    # generating rule numbers randomly.')
	p_result.rule_nums   = Rule.get_rules_randomly(p_result.rules_count)
	# adds a new member variable
	# initial list of rules
	print('    # initializing rules.', end=' ')
	p_result.rules       = Rule.get_rules_from_nums(p_result.rule_nums)

	return ModeFourFilterConfig(p_result)

def get_mode_five_config(parser, p_result):
	issues = ''
	if not p_result.t_win_trig:
		issues += "    - THRESHOLD_WIN_TRIG not specified.\n"
	if not p_result.win_size:
		issues += "    - WINDOW_SIZE not specified.\n"
	if not p_result.inactive_cp:
		issues += "    - INACTIVE_CHECKED% not specified.\n"

	if issues:
		print('[-] issues:\n' + issues)
		parser.print_usage()
		sys.exit(0)

	p_result.active_p     = random.randint(1, (100 - p_result.inactive_cp))
	p_result.active_set   = Rule.get_rules_randomly(round(float(Rule.num_of_rules()) * p_result.active_p/100.0))
	print('    # initializing ACTIVE rules.', end=' ')
	rtmp = Rule.get_rules_from_nums(p_result.active_set)
	p_result.active_rules   = {}
	for num, rule in zip(p_result.active_set, rtmp):
		p_result.active_rules[num] = rule

	p_result.inactive_set   = Rule.get_new_rules_randomly(\
		round(float(Rule.num_of_rules()) * p_result.inactive_cp/100.0), p_result.active_set)
	print('    # initializing INACTIVE_CHECKED rules.', end=' ')
	rtmp = Rule.get_rules_from_nums(p_result.inactive_set)
	p_result.inactive_rules = {}
	for num, rule in zip(p_result.inactive_set, rtmp):
		p_result.inactive_rules[num] = rule

	return ModeFiveFilterConfig(p_result)

def get_config(args):
	"""
	Parse command line arguments, initialize configurations
	"""
	parser = argparse.ArgumentParser()
	# add options
	parser.add_argument('-i', action='store', dest='in_ip', required=True, type=str, help='specify the IN_IP')
	parser.add_argument('-o', action='store', dest='out_ip', required=True, type=str, help='specify the OUT_IP')
	#give a list of rules, comma separated and no spaces between
	parser.add_argument('-l', action='store', dest='rule_nums', required=False, type=str,
		help='specify a list of rules, separated by \",\" e.g 2,3,4')
	#specify mode, 1 is for NORMAL , 2 is for RANDOM and 3 is for INCREMENT_RANDOMLY
	parser.add_argument('-m', action='store', dest='mode', required=True, type=int,
		help=\
		"""
		(a) MODE 0(gateway) python3 main.py -m 0 -i 192.168.1.1 -o 192.168.1.2
		(b) MODE 1(static) python3 main.py -m 1 -i 192.168.1.1 -o 192.168.1.2 -n 3 -l 55,3,5
		(c) MODE 2(random) python3 main.py -m 2 -i 192.168.1.1 -o 192.168.1.2 -n 10 -t 30
		(d) MODE 3(dynamic) python3 main.py -m 3 -i 192.168.1.1 -o 192.168.1.2 -n 7 -t 25 -I 3 -P 999 -pn 5
		(e) MODE 4(random dynamic) python3 main.py -m 4 -i 192.168.1.1 -o 192.168.1.2 -tr 2-10 -nr 5-10
		(f) MODE 5(Adaptive) python3 main.py -m 5 -i 192.168.1.1 -o 192.168.1.2 -ws 10 -ic 15 -twt 3
		"""
	)

	#specify the no. of rules, in case you didnt give the --list. the --mode is used to determine the mode of getting
	#the rules, either randomly or from stdin
	parser.add_argument('-n', action='store', dest='rules_count', required=False, type=str, \
		help='specify the no. of rules to use, in case the -l is not specified.\
		     To use all rules, provide "all" as the argument to -n')
	parser.add_argument('-t', action='store', dest='timeout', required=False, type=int,
		help='specify rules reset timeout in seconds')
	parser.add_argument('-pn', action='store', dest='max_pkts_count', required=False, type=int,
		help='(pn - p-number of packets)specify the number of packets to\
		      filter before INCR_RULES more rules are added')
	parser.add_argument('-P', action='store', dest='proto', required=False, type=int,
		help='specify the protocol to be used to filer packets ' \
		+ str({0:'HOPOPT',1:'ICMP',4:'IPv4',6:'TCP',17:'UDP',132:'SCTP',999:'ALL'}))
	parser.add_argument('-I', action='store', dest='incr_rules_count', required=False, type=int,
		help='specify the no. of rules to be incremented in case of MODE 3')
	parser.add_argument('-tr', action="store", dest="timeout_range", required=False, type=str,
		help="(tr - t-range)specify timeout range in the case of mode 4, e.g. -tr 1-20, -tr 7-89")
	parser.add_argument('-nr', action='store', dest='rules_count_range', required=False, type=str,
		help="(nr - n-range)specify rules count range in the case of mode 4, e.g. -nr 1-3")
	parser.add_argument('-ws', action='store', dest='win_size', required=False, type=int,default=None,
		help="the length of the sliding window in seconds (mode 5 only), e.g. -ws 10")
	parser.add_argument('-ic', action='store', dest='inactive_cp', required=False, type=int,default=None,
		help="percentage of initial rules to be used as INACTIVE_CHECKED (mode 5 only), e.g. -ic 10")
	parser.add_argument('-twt', action='store', dest='t_win_trig', required=False, type=int, default=None,
		help="number of timestamps that must be present to move a rule from INACTIVE_CHECKED to ACTIVE (mode 5 only), e.g. -twt 3")

	# parse
	p_res = parser.parse_args(args)

	print('    # resolving network interface names.')
	p_res.in_iface = get_iface_name_by_addr(p_res.in_ip)

	error = False
	if not p_res.in_iface:
		print('[-] error resolving iface name for :', p_res.in_ip)
		error = True

	p_res.out_iface = get_iface_name_by_addr(p_res.out_ip)

	if not p_res.out_iface:
		print('[-] error resolving iface name for :', p_res.out_ip)
		error = True

	if error:
		sys.exit(-1)

	if p_res.mode == 0:
		return get_mode_zero_config(p_res)
	elif p_res.mode == 1:
		return get_mode_one_config(parser, p_res)
	elif p_res.mode == 2:
		return get_mode_two_config(parser, p_res)
	elif p_res.mode == 3:
		return get_mode_three_config(parser, p_res)
	elif p_res.mode == 4:
		return get_mode_four_config(parser, p_res)
	elif p_res.mode == 5:
		return get_mode_five_config(parser, p_res)
	else:
		print("[-] invalid mode.")
		sys.exit(0)