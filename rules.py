
import logging

logging.getLogger('scapy.runtime').setLevel(logging.ERROR)

from scapy.all import IP, Ether, ARP, Packet, conf
import argparse
import random

conf.verb = 0

_RULES_MAP = {
	1:('--type IP --condition flags==128,version==4 --action drop',"drop all IPv4 packets w/ reserved flag set"),
	2:('--type IP --condition id==9999,version==4 --action drop','drop all IPv4 packets w/ id = 9999'),
	3:('--type IP --condition tos==3 --action forward',"forward all ip packets with tos == 3"),
	4:('--type IP --condition flags==32,frag==18 --action drop','drop all IP packets with DF set'),
	5:('--type IP --condition ttl==255,sport==9999 --protocol tcp --action forward','forward all TCP packets w/ sport == 9999 and ttl == 255'),
	6:('--type IP --condition src==201.201.201.201,flags==2 --protocol tcp --action drop','drop TCP packets from 201.201.201.201 with SYN flag set'),
	7:('--type IP --condition payload==Covert.Channel --protocol icmp --action forward','forward all ICMP packets with paylaod == Covert.Channel'),
	8:('--type IP --condition type==3,unused==499 --protocol icmp --action forward','forward ICMP packets of type 3 and w/ unused set to 499'),
	9:('--type IP --condition type==17,id==1 --protocol icmp --action normalise --norm-op unused=0','for all ICMP packets of type 17, set unused to 0'),
	10:('--type IP --condition type==17,seq==1 --protocol icmp --action normalise --norm-op unused=0','for all ICMP packets of type 17, set unused = 0'),
	11:('--type IP --condition type==4,unused==4369 --protocol icmp --action normalise --norm-op unused=0','for all ICMP packets of type 4, set unused = 0'),
	12:('--type IP --condition type==10,unused==4112 --protocol icmp --action normalise --norm-op unused=0','for all ICMP packets of type 10, set unused = 0'),
	13:('--type IP --condition type==11,unused==273 --protocol icmp --action normalise --norm-op unused=0','for all ICMP packets of type 11, set unused = 0'),
	14:('--type IP --condition type==12,reserved==4660 --protocol icmp --action normalise --norm-op unused=0','for all ICMP packets of type 12, set unused = 0'),
	15:('--type IP --condition flags==32,urgptr==6363 --protocol tcp --action drop','drop all TCP packets with URG flag set and urgptr == 6363'),
	16:('--type IP --condition seq==305419896 --protocol tcp --action drop','drop all TCP packets with sequence no. = 305419896'),
	17:('--type IP --condition flags==32,sport==1234 --action drop','drop all TCP packets with DF flag set and sport == 1234'),
	18:('--type IP --condition dport==81,window==512 --protocol tcp --action drop','drop all TCP packets with dest port = 81 and window = 512'),
	19:('--type IP --condition chksum==1 --protocol tcp --action drop','drop all TCP packets with checksum = 1'),
	20:('--type IP --condition ack==2700126895 --protocol tcp --action drop','drop all TCP packets with ack = 2700126895'),
	21:('--type IP --condition chksum==1 --action drop','drop all IP packets with checksum = 1'),
	22:('--type IP --condition sport==9001 --protocol udp --action drop','drop all UDP packets with source port = 9001'),
	23:('--type IP --condition sport==68,dport==67 --protocol udp --action forward','forward all dhcp traffic'),
	24:('--type IP --condition ttl==130 --protocol icmp --action drop','drop all ICMP packets with ttl = 130'),
	25:('--type IP --condition ttl==160 --protocol icmp --action drop','drop all ICMP packets with ttl = 160'),
	26:('--type IP --condition ttl==190 --protocol icmp --action drop','drop all ICMP packets with ttl = 190'),
	27:('--type IP --condition ttl==200 --protocol icmp --action drop','drop all ICMP packets with ttl = 200'),
	28:('--type IP --condition ttl==210 --protocol icmp --action drop','drop all ICMP packets with ttl = 210'),
	29:('--type IP --condition ttl==230 --protocol icmp --action drop','drop all ICMP packets with ttl = 230'),
	30:('--type IP --condition ttl==240 --protocol icmp --action drop','drop all ICMP packets with ttl = 240'),
	31:('--type IP --condition ttl==250 --protocol icmp --action drop','drop all ICMP packets with ttl = 250'),
	32:('--type IP --condition ttl==140 --protocol icmp --action drop','drop all ICMP packets with ttl = 140'),
	33:('--type IP --condition ttl==150 --protocol icmp --action drop','drop all ICMP packets with ttl = 150'),
	34:('--type IP --condition ttl==170 --protocol icmp --action drop','drop all ICMP packets with ttl = 170'),
	35:('--type IP --condition ttl==180 --protocol icmp --action drop','drop all ICMP packets with ttl = 180'),
	36:('--type IP --condition ttl==120 --protocol icmp --action drop','drop all ICMP packets with ttl = 120'),
	37:('--type IP --condition ttl==110 --protocol icmp --action drop','drop all ICMP packets with ttl = 110'),
	38:('--type IP --condition ttl==105 --protocol icmp --action drop','drop all ICMP packets with ttl = 105'),
	39:('--type IP --condition ttl==106 --protocol icmp --action drop','drop all ICMP packets with ttl = 106'),
	40:('--type IP --condition ttl==107 --protocol icmp --action drop','drop all ICMP packets with ttl = 107'),
	41:('--type IP --condition tos==88 --protocol sctp --action normalise --norm-op payload=2020202020202020',\
		'normalise all SCTP packets with tos = 88'),
	42:('--type IP --condition tos==99 --protocol sctp --action normalise --norm-op payload=2020202020202020',\
		'normalise all SCTP packets with tos = 99'),
	43:('--type IP --condition tos==100 --protocol sctp --action normalise --norm-op payload=2020202020202020',\
		'normalise all SCTP packets with tos = 100'),
	44:('--type IP --condition tos==101 --protocol sctp --action normalise --norm-op payload=2020202020202020',\
		'normalise all SCTP packets with tos = 101'),
	45:('--type IP --condition tos==102 --protocol sctp --action normalise --norm-op payload=2020202020202020',\
		'normalise all SCTP packets with tos = 102'),
	46:('--type IP --condition tos==103 --protocol sctp --action normalise --norm-op payload=2020202020202020',\
		'normalise all SCTP packets with tos = 103'),
	47:('--type IP --condition tos==104 --protocol sctp --action normalise --norm-op payload=2020202020202020',\
		'normalise all SCTP packets with tos = 104'),
	48:('--type IP --condition tos==105 --protocol sctp --action normalise --norm-op payload=2020202020202020',\
		'normalise all SCTP packets with tos = 105'),
	49:('--type IP --condition tos==106 --protocol sctp --action normalise --norm-op payload=2020202020202020',\
		'normalise all SCTP packets with tos = 106'),
	50:('--type IP --condition tos==107 --protocol sctp --action normalise --norm-op payload=2020202020202020',\
		'normalise all SCTP packets with tos = 107'),
	51:('--type IP --condition tos==108 --protocol sctp --action normalise --norm-op payload=2020202020202020',\
		'normalise all SCTP packets with tos = 108')
}



"""
A class to manage a rule attributes ==> packet type, condition, whether the condition is needed,
packet field to apply the condition to, action to take if condition is true and parameters to be used
during the execution of the parameter
""" 

class Rule(object):

	"""
	constructor
	"""
	def __init__(self, ptype='', conds=[], action='', protocol='', norm_op='', desc=''):

		#initialise variables
		self._ptype     = ptype #IP, ARP ...
		self._conds_lst = conds #e.g [ ttl>30, src!=192.14.33.2 ]
		self._action    = action #e.g drop, accept and normalise
		self._protocol  = protocol #TCP 
		self._norm_op   = norm_op #normalization operation e.g ttl=126
		self._desc      = desc


	"""
	getter methods
	"""
	def get_ptype(self):
		return self._ptype


	def has_conditions(self):
		return True if(len(self._conds_lst) > 0) else False


	def get_conditions(self):
		return self._conds_lst


	def get_action(self):
		return self._action


	def get_protocol(self):
		return self._protocol


	def get_norm_op(self):
		return self._norm_op


	"""
	override __str__
	"""
	def __str__(self):
		return self._desc

	"""
	utility methods
	"""

	"""
	retrieve a rule string from _RULES_MAP, parse and return a Rule object or None on error
	"""
	@staticmethod
	def get_rule_by_num(rule_no):
		#get a rule string
		rule = _RULES_MAP[rule_no]

		r_string = rule[0]

		#parse the rule string
		r_parser = argparse.ArgumentParser(description = 
			"Rule parser"
			)
		r_parser.add_argument('--type',action='store',dest='ptype',required=True, type=str)
		r_parser.add_argument('--condition',action='store',dest='conds',required=False,type=str, default='', nargs='+')
		r_parser.add_argument('--protocol',action='store',dest='protocol',required=False,type=str, default='any')
		r_parser.add_argument('--action',action='store',dest='action',required=True, type=str)

		#if the action = normalise, --norm-op specifies the normalisation operation
		r_parser.add_argument('--norm-op',action='store',dest='norm_op',required=False,type=str, default='', nargs='+')

		#print("    ##" + (" parsing rule #" + str(rule_no)).ljust(30,'.'), end = '...')

		try:
			result = r_parser.parse_args(r_string.split())
		except:
			return None
		norm_op_str = ' '.join(result.norm_op)
		if result.conds == '':
			return Rule(ptype=result.ptype, action=result.action, \
				protocol=result.protocol.upper(),norm_op=norm_op_str, desc=rule[1])

		conds_str = ' '.join(result.conds)

		return Rule(ptype=result.ptype, conds=conds_str.split(','), action=result.action, \
			protocol=result.protocol.upper(),norm_op=norm_op_str, desc=rule[1])

	"""
	get a given no. of rules randomly
	"""
	@staticmethod
	def get_rules_randomly(no_of_rules):

		print("    # generating",no_of_rules,"rule number(s) randomly.")
		#get all rule no.s
		new_list = random.sample(_RULES_MAP.keys(), no_of_rules)
		new_list.sort()
		return new_list

	"""
	get a given no of random rules, and the rules should not be in the initial list given as a parameter to the method
	"""
	@staticmethod
	def get_new_rules_randomly(no_of_rules, init_rules):
		print("    # generating", no_of_rules,"rule number(s) randomly.")
		#print(available)
		new_list = random.sample(list(set(Rule.get_all_rules().keys()) - set(init_rules)), no_of_rules)
		new_list.sort()
		return new_list

	@staticmethod
	def get_rules_from_nums(rule_nums):
		"""
		Create Rule objects from rule numbers
		"""
		init    = 0
		no_init = 0
		rules   = []
		for rule_num in rule_nums:
			rl = Rule.get_rule_by_num(rule_num)
			if rl != None:
				rules.append(rl)
				init += 1
			else:
				no_init += 1

		print(' | successful: %d, fail: %d' %(init, no_init))
		return rules

	@staticmethod
	def num_of_rules():
		return len(_RULES_MAP)

	@staticmethod
	def get_all_rules():
		return _RULES_MAP