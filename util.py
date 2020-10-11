
import logging

logging.getLogger('scapy.runtime').setLevel(logging.ERROR)

from scapy.all import IP, Ether, ICMP, TCP, UDP, DNS, ARP, Packet, conf
import netifaces
import netfilterqueue


conf.verb = 0

def get_iface_name_by_addr(ip):

	all_ifaces = netifaces.interfaces()

	#resolve ip for each, compare with 'ip'
	for iface in all_ifaces:
		all_addrs = netifaces.ifaddresses(iface)
		if iface is not 'lo' and all_addrs.__contains__(netifaces.AF_INET):
			af_inet = all_addrs[netifaces.AF_INET][0]
			if af_inet.__contains__('addr') and af_inet['addr'] == ip:
				return iface
	return None


def get_cond_operator(cond):
	"""
	get the comparison operator used in the condition
	"""
	all_ops = ['<=','<','==','!=','>=','>']

	for op in all_ops:
		if len(cond.split(op)) > 1:
			return op


def get_net_addr(sub_ip_info, pkt_ip):
	"""
	get the network part of an ip (src/dst) and the network part of a subnet ip
	"""
	sub_addr = sub_ip_info[0].split('.')[:3] if(sub_ip_info[1] >= '24') else \
		sub_ip_info[0].split('.')[:2] if(sub_ip_info[1] >= '16') else sub_ip_info[0].split('.')[:1]
	
	ip_addr  = pkt_ip.split('.')[:3] if(len(sub_addr) == 3) else \
		pkt_ip.split('.')[:2] if(len(sub_addr) == 2) else pkt_ip.split('.')[:1]

	sub_addr_str = ''
	ip_addr_str  = ''

	for i in sub_addr:
		sub_addr_str = sub_addr_str + str(i) + '.'

	for i in ip_addr:
		ip_addr_str = ip_addr_str + str(i) + '.'

	return (ip_addr_str, sub_addr_str)


def bytes_to_str(byts):

	strng = ''
	for i in range(len(byts)):
		j = int(byts[i])
		if j < 127 and j >= 32:
			strng += chr(j)
		else:
			strng += '.'

	return strng


def alter_pkt_attr(pkt, prtcl, norm_op):
	"""
	apply a normalization rule
	"""
	#the attribute to be altered must be separated by '=' from the value
	attr_name = norm_op.split('=')[0]
	attr_val  = norm_op.split('=')[1]
	# search for attributes top-down i.e if we want to alter flags in IP()/TCP(), its really hard to tell whether its tcp or ip
	# flags. The script will have a standard way of handling this TCP layer first then back to IP layer 
	if attr_name == 'payload' and pkt.haslayer(prtcl) and pkt.haslayer('Raw'):
		pkt.getlayer('Raw').setfieldval('load',attr_val)
		return IP(pkt.__bytes__())

	if pkt.haslayer(prtcl):
		try:
			pkt.getlayer(prtcl).getfieldval(attr_name)
			pkt.getlayer(prtcl).setfieldval(attr_name, attr_val if(attr_name == 'dst' or attr_name == 'src') \
				else None if(attr_val == 'NULL') else int(attr_val))

		except AttributeError:
			#this means the attr in question is in the lower layer (IP)
			try:
				pkt.getfieldval(attr_name)
				pkt.setfieldval(attr_name, attr_val if(attr_name == 'dst' or attr_name == 'src') \
					else None if(attr_val == 'NULL') else int(attr_val))
			except:
				pass
	else:
		#protocol ==> ANY
		try:
			pkt.getfieldval(attr_name)
			pkt.setfieldval(attr_name, (attr_val if(attr_name == 'dst' or attr_name == 'src') \
				else None if(attr_val == 'NULL') else int(attr_val)))
		except:
			#this means the attr isnt in the IP layer either
			#make no changes
			pass

	return IP(pkt.__bytes__())


def eval_condition(pkt, cond_list, rule_proto):
	"""
	evaluate the condition
	"""
	rule_applicable = True

	for cond in cond_list:
		new_cond = None
		cond_op = get_cond_operator(cond)
		attr_name = cond.split(cond_op)[0]
		attr_val  = cond.split(cond_op)[1]

		if attr_name == 'dst' or attr_name == 'src':
			rule_ip_info = cond.split(cond_op)[1].split('/')
			if len(rule_ip_info) == 1:
				#not net mask
				new_cond = cond.replace(attr_name, repr(pkt.getfieldval(attr_name)))
				new_cond = new_cond.replace(attr_val, repr(attr_val))

			elif len(rule_ip_info) == 2:
				#subnet
				ip_net, net = get_net_addr(rule_ip_info, pkt.getfieldval(attr_name))
				new_cond = cond.replace(attr_name, repr(ip_net))
				new_cond = new_cond.replace(attr_val, repr(net))
			else:
				pass

		elif attr_name == 'payload' and pkt.haslayer('Raw'):
			#get actual payload value (in string format) 
			new_cond = cond.replace(attr_name, bytes_to_str(pkt.getlayer('Raw').load))
			new_cond = new_cond.replace(attr_val, str(attr_val))

		else:
			if pkt.haslayer(rule_proto):
				try:
					new_cond = cond.replace(attr_name, str(pkt.getlayer(rule_proto).getfieldval(attr_name)))
					new_cond = new_cond.replace(attr_val, str(attr_val))
				
				except AttributeError:
					#not in that layer, check for it the lower layer (IP)
					try:
						new_cond = cond.replace(attr_name, str(pkt.getfieldval(attr_name)))
						new_cond = new_cond.replace(attr_val, str(attr_val))
					except:
						rule_applicable = rule_applicable and False
						continue
			else:
				#any protocol
				try:
					new_cond = cond.replace(attr_name, str(pkt.getfieldval(attr_name)))
					new_cond = new_cond.replace(attr_val, str(attr_val))
				except:
					rule_applicable = rule_applicable and False
					continue
		try:
			rule_applicable = rule_applicable and eval(new_cond)
		except:
			rule_applicable = rule_applicable and False

	#print(new_cond, rule_applicable)
	return rule_applicable

def apply_rule_action(ip_pkt, rule):

	if rule.get_action() == 'drop':
		return (ip_pkt,'D')
	elif rule.get_action() == 'normalise':
		return (alter_pkt_attr(ip_pkt, rule.get_protocol(), rule.get_norm_op()),'N') #N for normalised
	else:
		return (ip_pkt,'F') #F for accepted/forwarded without normalization

def apply_rule(ip_pkt, rule):

	applied = False
	if rule.has_conditions():
		#evaluate condition
		if eval_condition(ip_pkt, rule.get_conditions(), rule.get_protocol()):
			#evaluate protocol
			if (rule.get_protocol()).upper() == netfilterqueue.PROTOCOLS[ip_pkt.proto]:
				#apply a rule's action, return a new IP packet and a char defining the action taken on the packet
				ip_pkt, applied_action = apply_rule_action(ip_pkt, rule)
				if applied_action == 'D':
					return(ip_pkt, 'dropped', False)
				#continue applying rules
				elif applied_action == 'N':
					return(ip_pkt, 'normalised', True)
				else:
					return(ip_pkt, 'forwarded', False)
			else:
				ip_pkt, applied_action = apply_rule_action(ip_pkt, rule)
				if applied_action == 'D':
					#dropped = True
					return(ip_pkt, 'dropped', False)
				#continue applying rules
				elif applied_action == 'N':
					return(ip_pkt, 'normalised', True)
				else:
					return(ip_pkt, 'forwarded', False)
		else:
			# NO MATCH
			return (ip_pkt, "none", False)
	else:
		if (rule.get_protocol()).upper() == netfilterqueue.PROTOCOLS[ip_pkt.proto]:
			#apply a rule's action, return a new IP packet and a char defining the action taken on the packet
			ip_pkt, applied_action = apply_rule_action(ip_pkt, rule)
			if applied_action == 'D':
				return (ip_pkt, 'dropped', False)
			#continue applying rules
			elif applied_action == 'N':
				return(ip_pkt, 'normalised', True)
			else:
				return(ip_pkt, 'forwarded', False)
		else:
			# NO MATCH
			return (ip_pkt, "none", False)

def process_pkt(pkt, rules):
	"""
	packet analyzer
	"""
	ip_pkt  = IP(pkt.get_payload())
	# has been normalized ?
	is_norm = False
	for rule in rules:
		ip_pkt, action, is_norm = apply_rule(ip_pkt, rule)
		if action == "dropped":
			return (ip_pkt, action)
		else:
			# go to next rule
			pass

	if is_norm is True:
		return (ip_pkt, 'normalised')
	return (ip_pkt, 'forwarded')