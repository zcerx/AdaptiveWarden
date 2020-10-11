import util
from rules import Rule
import netfilterqueue
import os
import sys
import psutil
import threading
import time
import queue
from subprocess import PIPE, Popen
import logging
import random
from copy import deepcopy 

logging.getLogger('scapy.runtime').setLevel(logging.ERROR)

from scapy.all import IP, Ether, ICMP, TCP, UDP, DNS, ARP, Packet, conf

conf.verb = 0


##########################################################
# Filter Queue
##########################################################
class FilterQueue(netfilterqueue.NetfilterQueue):
	"""
	Generic filter queue
	"""
	def __init__(self, config):
		super(FilterQueue, self).__init__()
		self.config          = config
		self.all_pkts        = 0
		self.dropped_pkts    = 0
		self.normalised_pkts = 0
		self.forwarded_pkts  = 0
		self.this_process    = psutil.Process(os.getpid())
		self.cpu             = 0.0 #sum(self._this_process.cpu_times())
		self.avg_ram         = 0.0 #(sum(self._this_process.memory_info()) / 1000000)
		self.start           = None

		self.bind(1, self.cb)

	def formatted_uptime(self):

		ft = ''
		if self.start:# start == None
			tm = int(time.time()) - self.start
			rem = None
			if tm >= 3600:
				tm, rem = divmod(tm, 3600)
				ft += "%d h " % tm
			else:
				rem = tm
			if rem >= 60:
				tm, rem = divmod(rem, 60)
				ft += "%d m " % tm

			ft += "%d s" % rem
		else:
			ft += "0 s"
		return ft

	def cb(self, pkt):
		"""
		A callback method
		"""
		pass

	def fifo_process(self):
		pass

	def sched_timeout(self):
		pass


	def init_filter_params(self):
		"""
		Initialize filter parameters -- Threads,...
		"""
		self.set_up_filter()

	def init_resource_usage(self):
		self.start = int(time.time())
		self.cpu   = (sum(self.this_process.cpu_times()) - self.cpu)
		self.avg_ram   = (sum(self.this_process.memory_info()) / 1000000)

	def stats(self):
		return \
			"    %-30s:%s\n    %-30s:%.4f s\n    %-30s:%.4f mbs\n    %-30s:%.4s\n" %\
			('ALL_PACKETS', self.all_pkts, 'FILTER CPU TIME', self.get_cpu_usage(),\
				'AVERAGE MEMORY USAGE', self.avg_ram, 'UPTIME', self.formatted_uptime())

	def get_mem_usage(self):
		mem = (sum(self.this_process.memory_info()) / 1000000)
		self.avg_ram = (mem + self.avg_ram) / 2.0
		return mem

	def get_cpu_usage(self):
		return self.cpu if(self.cpu == 0.0) else (sum(self.this_process.cpu_times()) - self.cpu)


	def set_up_filter(self):
		"""
		create a network bridge between _in_iface and _out_iface
		"""
		bridge_ip = self.config.in_ip if(self.config.in_ip \
					< self.config.out_ip) else self.config.out_ip

		start_cmds = \
		[\
			[\
				'brctl addbr br0','brctl addif br0 ' + self.config.in_iface + ' ' + self.config.out_iface,\
				'brctl stp br0 yes','ifconfig ' + self.config.in_iface + ' 0.0.0.0',\
				'ifconfig ' + self.config.out_iface + ' 0.0.0.0',\
				'ifconfig br0 ' + bridge_ip + ' up',\
			],\
			[\
				"iptables -A INPUT -m physdev --physdev-in " + self.config.in_iface + " -j NFQUEUE --queue-num 1",\
				"iptables -A INPUT -m physdev --physdev-in " + self.config.out_iface + " -j NFQUEUE --queue-num 1",\
				"iptables -A FORWARD -m physdev --physdev-in " + self.config.in_iface + " -j NFQUEUE --queue-num 1",\
				"iptables -A FORWARD -m physdev --physdev-in " + self.config.out_iface + " -j NFQUEUE --queue-num 1"\
			]\
		]

		print('[*] creating a bridge.')

		for cmd in start_cmds[0]:
			cmd = 'sudo ' + cmd
			p = Popen(cmd,shell=True,stdin=PIPE,stderr=PIPE,stdout=PIPE)
			if len(p.stderr.read()) > 0:
				print('    #',cmd.ljust(85) + '[ fail ]')
			else:
				print('    #',cmd.ljust(85) + '[ success ]')

		print('\n[*] configuring iptables.')
		for cmd in start_cmds[1]:
			cmd = 'sudo ' + cmd
			p = Popen(cmd,shell=True,stdin=PIPE,stderr=PIPE,stdout=PIPE)
			if len(p.stderr.read()) > 0:
				print('    #',cmd.ljust(85) + '[ fail ]')
			else:
				print('    #',cmd.ljust(85) + '[ success ]')

	def start_capture(self):
		"""
		start packet capture
		"""

		print('[*] initial filter configuration.')
		print(self.config)

		if self.config.mode == 0:
			print('\n[*] gateway mode activated.')
		else:
			print('\n[*] starting capture.')
		
		print("    ", end = "")
		print("src".ljust(20) + "dst".ljust(20) + "protocol".ljust(10) + "ttl".ljust(10) + "action".ljust(15) + \
			"memory(MBs)".ljust(15) + "cummulative cpu time(secs)")
		print("    ", end = "")
		print(('-'*116))

		try:
			self.run()
		except KeyboardInterrupt:
			#self.print_resources_util()
			self.restore()
			print('\n[*] filter statistics.')
			print(self.stats())
			print('[*] filter configuration.')
			print(self.config)

		finally:
			self.unbind()
			print('\n[*] exit.')
			sys.exit(0)

	def log(self, packet, ip_pkt, action):

		if not ip_pkt.proto in netfilterqueue.PROTOCOLS:
			return

		if action == 'dropped':
			packet.drop()
			self.dropped_pkts += 1
		elif action == 'normalised':
			packet.set_payload(ip_pkt.__bytes__())
			packet.accept()
			self.normalised_pkts += 1
		else:
			packet.accept()
			self.forwarded_pkts += 1

		self.all_pkts += 1
		print("    %-20s%-20s%-10s%-10d%-15s%-15.4f%-.3f" % (ip_pkt.src, ip_pkt.dst, netfilterqueue.PROTOCOLS[ip_pkt.proto],\
			ip_pkt.ttl, action.upper(), self.get_mem_usage(), self.get_cpu_usage()))

	def restore(self):
		"""
		restore the state of the ifaces and remove the network bridge
		"""
		#restore the state of the interfaces
		print("\n[*] restoring interface states.")
		exit_cmds = \
		[\
			[\
				'brctl delif br0 ' + self.config.in_iface + ' ' + self.config.out_iface,\
				'ifconfig br0 down','brctl delbr br0',\
				'ifconfig ' + self.config.in_iface + ' ' + self.config.in_ip + ' up',\
				'ifconfig ' + self.config.out_iface + ' ' + self.config.out_ip + ' up'\
			],\
			[\
				"iptables -D INPUT -m physdev --physdev-in " + self.config.in_iface + " -j NFQUEUE --queue-num 1",\
				"iptables -D INPUT -m physdev --physdev-in " + self.config.out_iface + " -j NFQUEUE --queue-num 1",\
				"iptables -D FORWARD -m physdev --physdev-in " + self.config.in_iface + " -j NFQUEUE --queue-num 1",\
				"iptables -D FORWARD -m physdev --physdev-in " + self.config.out_iface + " -j NFQUEUE --queue-num 1"\
			]\
		]

		for cmd in exit_cmds[0]:
			cmd = 'sudo ' + cmd
			p = Popen(cmd,shell=True,stdin=PIPE,stderr=PIPE,stdout=PIPE)
			if len(p.stderr.read()) > 0:
				print('    #',cmd.ljust(85) + '[ fail ]')
			else:
				print('    #',cmd.ljust(85) + '[ success ]')

		print('\n[*] restoring iptables.')
		for cmd in exit_cmds[1]:
			cmd = 'sudo ' + cmd
			p = Popen(cmd,shell=True,stdin=PIPE,stderr=PIPE,stdout=PIPE)
			if len(p.stderr.read()) > 0:
				print('    #',cmd.ljust(85) + '[ fail ]')
			else:
				print('    #',cmd.ljust(85) + '[ success ]')

class ModeZeroFilterQueue(FilterQueue):
	"""
	Mode 0 filter queue
	"""
	def __init__(self, config):
		super(ModeZeroFilterQueue, self).__init__(config)

	def cb(self, pkt):
		"""
		Over ride callback method to provide different implementaion
		"""
		if not self.all_pkts:
			self.init_resource_usage()
		self.log(pkt, IP(pkt.get_payload()), 'forwarded')

class ModeOneFilterQueue(FilterQueue):
	"""
	Mode 1 filter queue
	"""
	def __init__(self, config):
		super(ModeOneFilterQueue, self).__init__(config)
		self.pkts_queue = queue.Queue()

	def init_filter_params(self):
		# set up filter
		self.set_up_filter()

		print('[*] starting workers.\n    - fifo_process.')
		self.proc = threading.Thread(target=self.fifo_process)
		self.proc.setDaemon(True)
		self.proc.start()

	def stats(self):
		return \
			"    %-30s:%d\n    %-30s:%d\n    %-30s:%d\n%s" % \
			('PACKETS_DROPPED', self.dropped_pkts, 'PACKETS_NORMALIZED',\
				self.normalised_pkts, 'PACKETS_FORWARDED', self.forwarded_pkts,\
				super(ModeOneFilterQueue, self).stats())

	def cb(self, pkt):
		"""
		Over ride callback method to provide different implementaion
		"""
		self.pkts_queue.put(pkt)

	def fifo_process(self):
		"""
		Process packets, one-by-one on a different thread
		"""
		while True:
			#get a packet from the queue
			pkt = self.pkts_queue.get()

			if not self.all_pkts:
				self.init_resource_usage()
			ip_pkt , action = util.process_pkt(pkt, self.config.rules)
			#add to out put queue
			self.log(pkt, ip_pkt, action)

class ModeTwoFilterQueue(FilterQueue):
	"""
	Mode 2 filter queue
	"""
	def __init__(self, config):
		super(ModeTwoFilterQueue, self).__init__(config)
		self.pkts_queue        = queue.Queue()
		self.start_timer_event = threading.Event()
		self.notif_timer_event = threading.Event()
		self.lock              = threading.Lock()
		
	def init_filter_params(self):
		self.set_up_filter()

		print('[*] starting workers.\n    - fifo_process.')
		self.proc = threading.Thread(target=self.fifo_process)
		self.proc.setDaemon(True)
		self.proc.start()

		print('    - timer.')
		self.tmr  = threading.Thread(target=self.sched_timeout)
		self.tmr.setDaemon(True)
		self.tmr.start() 

	def fifo_process(self):
		while True:
			#get a packet from the queue
			pkt = self.pkts_queue.get()

			if not self.all_pkts:
				self.start_timer_event.set()
				self.init_resource_usage()

			#synchronise
			#timer thread usesthe same lock to update rules
			with self.lock:
				ip_pkt , action = util.process_pkt(pkt, self.config.rules)

			#add to out put queue
			self.log(pkt, ip_pkt, action)

	def sched_timeout(self):
		#start timer operations after the filter has started actual filtering
		self.start_timer_event.wait()
		#keep reseting rules until the program exits
		while True:
			#time out
			time.sleep(self.config.timeout)
			with self.lock:
				print('\n    ' + '#'*90)
				print('    # reseting filter rules.')
				
				self.config.update()

				print('    # new rules ==> ', ' '.join(map(str, self.config.rule_nums)) + '.')
				print('    # resuming capture.\n')
				print("    ", end = "")
				print("src".ljust(20) + "dst".ljust(20) + "protocol".ljust(10) + "ttl".ljust(10) + "action".ljust(15) + \
					"memory(MBs)".ljust(15) + "cummulative cpu time(secs)")
				print("    ", end = "")
				print(('-'*116))

	def stats(self):
		return \
			"    %-30s:%d\n    %-30s:%d\n    %-30s:%d\n%s" % \
			('PACKETS_DROPPED', self.dropped_pkts, 'PACKETS_NORMALIZED',\
				self.normalised_pkts, 'PACKETS_FORWARDED', self.forwarded_pkts,\
				super(ModeTwoFilterQueue, self).stats())

	def cb(self, pkt):
		"""
		Over ride callback method to provide different implementaion
		"""
		self.pkts_queue.put(pkt)

class ModeThreeFilterQueue(FilterQueue):
	"""
	Mode 3 filter queue
	"""
	def __init__(self, config):
		super(ModeThreeFilterQueue, self).__init__(config)

		self.pkt_count         = 0
		self.pkts_queue        = queue.Queue()
		self.start_timer_event = threading.Event()
		self.notif_timer_event = threading.Event()
		self.lock              = threading.Lock()

	def init_filter_params(self):
		self.set_up_filter()

		print('[*] starting workers.\n    - fifo_process')
		self.proc = threading.Thread(target=self.fifo_process)
		self.proc.setDaemon(True)
		self.proc.start()

		print('    - timer')
		self.tmr  = threading.Thread(target=self.sched_timeout)
		self.tmr.setDaemon(True)
		self.tmr.start()

	def fifo_process(self):

		while True:
			#get a packet from the queue
			pkt = self.pkts_queue.get()

			if not self.all_pkts:
				#start timer
				self.start_timer_event.set()
				self.init_resource_usage()

			#synchronise
			#timer thread usesthe same lock to update rules
			with self.lock:
				ip_pkt , action = util.process_pkt(pkt, self.config.rules)

			#add to out put queue
			self.log(pkt, ip_pkt, action)

			if self.config.proto == 'ALL' or self.config.proto == netfilterqueue.PROTOCOLS[ip_pkt.proto]:
				self.pkt_count += 1

			if self.pkt_count >= self.config.max_pkts_count:
				#send signal to timer
				self.notif_timer_event.set()

	def sched_timeout(self):
		#start timer operations after the filter has started actual filtering
		self.start_timer_event.wait()
		while True:
			#wait
			time.sleep(self.config.timeout)
			#wait for signal from main thread: the signal is send if the specified no. of packets is met
			self.notif_timer_event.wait()
			if self.config.rules_count < Rule.num_of_rules():
				with self.lock:
					self.config.incr_rules_count = 	\
						self.config.incr_rules_count if((Rule.num_of_rules() - self.config.rules_count) > self.config.incr_rules_count) \
							else (Rule.num_of_rules() - self.config.rules_count)

					self.config.update()
					#clear event
					self.notif_timer_event.clear()
					#reset pkt_count
					self.pkt_count = 0

					if self.config.rules_count == Rule.num_of_rules():
						print("    # all rules defined have been added.")
						#stop timer incase all rules have been added to self._rules

					#resume capture
					print('    # resuming capture.\n')
					print("    ", end = "")
					print("src".ljust(20) + "dst".ljust(20) + "protocol".ljust(10) + "ttl".ljust(10) + "action".ljust(15) + \
						"memory(MBs)".ljust(15) + "cummulative cpu time(secs)")
					print("    ", end = "")
					print(('-'*116))
			else:
				#stop timer, all defined rules have been added
				break

	def stats(self):
		return \
			"    %-30s:%d\n    %-30s:%d\n    %-30s:%d\n%s" % \
			('PACKETS_DROPPED', self.dropped_pkts, 'PACKETS_NORMALIZED',\
				self.normalised_pkts, 'PACKETS_FORWARDED', self.forwarded_pkts,\
				super(ModeThreeFilterQueue, self).stats())

	def cb(self, pkt):
		"""
		Over ride callback method to provide different implementaion
		"""
		self.pkts_queue.put(pkt)

class ModeFourFilterQueue(FilterQueue):
	"""
	Mode 0 filter queue
	"""
	def __init__(self, config):
		super(ModeFourFilterQueue, self).__init__(config)

		self.pkt_count         = 0
		self.pkts_queue        = queue.Queue()
		self.start_timer_event = threading.Event()
		self.notif_timer_event = threading.Event()
		self.lock              = threading.Lock()

	def init_filter_params(self):
		self.set_up_filter()
		print('[*] starting workers.\n    - fifo_process.')
		self.proc = threading.Thread(target=self.fifo_process)
		self.proc.setDaemon(True)
		self.proc.start()

		print('    - timer.')
		self.tmr  = threading.Thread(target=self.sched_timeout)
		self.tmr.setDaemon(True)
		self.tmr.start()

	def fifo_process(self):
		while True:
			#get a packet from the queue
			pkt = self.pkts_queue.get()

			if not self.all_pkts:
				self.start_timer_event.set()
				self.init_resource_usage()
			#synchronise
			#timer thread usesthe same lock to update rules
			with self.lock:
				ip_pkt , action = util.process_pkt(pkt, self.config.rules)

			#add to out put queue
			self.log(pkt, ip_pkt, action)

	def sched_timeout(self):
		#start timer operations after the filter has started actual filtering
		self.start_timer_event.wait()
		#keep reseting rules until the program exits
		while True:
			#time out
			time.sleep(self.config.timeout)
			with self.lock:
				print('\n    ' + '#'*90)
				print('    # reseting filter rules and timeout.')
				
				self.config.update()
				
				print('    # new timeout ==>', self.config.timeout)
				print('    # new rules count ==>', self.config.rules_count)
				print('    # new rule numbers ==>', ' '.join(map(str, self.config.rule_nums)))
				print('    # resuming capture.\n')
				print("    ", end = "")
				print("src".ljust(20) + "dst".ljust(20) + "protocol".ljust(10) + "ttl".ljust(10) + "action".ljust(15) + \
					"memory(MBs)".ljust(15) + "cummulative cpu time(secs)")
				print("    ", end = "")
				print(('-'*116))

	def stats(self):
		return \
			"    %-30s:%d\n    %-30s:%d\n    %-30s:%d\n%s" % \
			('PACKETS_DROPPED', self.dropped_pkts, 'PACKETS_NORMALIZED',\
				self.normalised_pkts, 'PACKETS_FORWARDED', self.forwarded_pkts,\
				super(ModeFourFilterQueue, self).stats())

	def cb(self, pkt):
		"""
		Over ride callback method to provide different implementaion
		"""
		self.pkts_queue.put(pkt)

class ModeFiveFilterQueue(FilterQueue):

	def __init__(self, config):
		super(ModeFiveFilterQueue, self).__init__(config)
		self.pkts_in_q     = queue.Queue()
		self.sync_lock     = threading.Lock()
		self.win_counter   = {}
		# workers
		self.prcssr        = threading.Thread(target = self.fifo_process)
		self.tmr           = threading.Thread(target = self.sched_timeout)
		self.is_first_pkt  = True

		# initialize WINDOW_COUNTER
		for rule_num in self.config.inactive_set:
			self.win_counter[rule_num] = []

		self.prcssr.setDaemon(True)
		self.tmr.setDaemon(True)
		self.prcssr.start()

	def stats(self):
		return \
			"    %-30s:%d\n    %-30s:%d\n    %-30s:%d\n%s" % \
			('PACKETS_DROPPED', self.dropped_pkts, 'PACKETS_NORMALIZED',\
				self.normalised_pkts, 'PACKETS_FORWARDED', self.forwarded_pkts,\
				super(ModeFiveFilterQueue, self).stats())

	def count_entries(self, rule):
		return len(self.win_counter[rule])

	def cb(self, pkt):
		self.pkts_in_q.put(pkt)
		if self.is_first_pkt:
			self.start = time.time()
			self.cpu   = sum(self.this_process.cpu_times())
			self.tmr.start()
			self.is_first_pkt = False

	def sched_timeout(self):
		while True:
			time.sleep(1)
			right_now = time.time()
			with self.sync_lock:
				for rule_num in self.win_counter.keys():
					# remove all entries older than WINDOW_SIZE for each rule
					i = None
					for index, tstamp in enumerate(self.win_counter[rule_num]):
						if (right_now - tstamp) < self.config.win_size:
							i = index
							break
					if i:
						# slice
						self.win_counter[rule_num] = self.win_counter[rule_num][i:]

	def fifo_process(self):
		"""
		The not recently used (NRU) page replacement algorithm is an algorithm that favours 
		keeping pages in memory that have been recently used. This algorithm works on the 
		following principle: when a page is referenced, a referenced bit is set for that page, 
		marking it as referenced. Similarly, when a page is modified (written to), a modified 
		bit is set. The setting of the bits is usually done by the hardware, although it is 
		possible to do so on the software level as well.

		In the context of the ADAPTIVE filter mode, the algorithm is used for rule replacement.
		Unlike in the case of page replacement, replacing rules does not require setting the
		referenced or modified bit. Instead, a list of recently applied rules and a list of rules
		that could not match a packet. A rule is selected randomly from the list of rules that
		were not applied. If the list is empty, the FIFO algorithm is used.

		FIFO lgorithm is a low-overhead algorithm that requires little bookkeeping on the part
		of the operating system. In the context of the ADAPTIVE filter mode, a queue is implememnted using a list i.e.
		all active rules a stored in a normal list. The first rule in the list is always picked for replacement.
		New replacements from the INACTIVE_CHECKED set are appended to the ACTIVE set. 
		"""
		# process one packet at a time
		while True:
			nxt_pkt     = self.pkts_in_q.get()
			ip_pkt      = IP(nxt_pkt.get_payload())
			matched     = False
			unmatched_r = []
			actions     = []
			for rule_num in self.config.active_set:
				ip_pkt, action, is_norm = util.apply_rule(ip_pkt, self.config.active_rules[rule_num])
				actions.append(action)
				print(action)
				if action != "none":
					matched = True
				else:
					unmatched_r.append(rule_num)

			if not matched:
				# INACTIVE_CHECKED
				inact_ip_pkt = IP(nxt_pkt.get_payload())
				with self.sync_lock:
					rm_set  = set()
					add_set = set()
					for rule_num in self.config.inactive_set:
						inact_ip_pkt, action, is_norm = util.apply_rule(ip_pkt, self.config.inactive_rules[rule_num])
						if action != "none":
							self.win_counter[rule_num].append(time.time())
							# if there are more entries in the triggerlist than THRESHOLD_WIN_TRIG
							if len(self.win_counter[rule_num]) > self.config.t_win_trig:
								to_rm  = None
								if len(unmatched_r):
									# NRU
									to_rm = random.choice(unmatched_r)
								else:
									# FIFO
									to_rm = self.config.active_set[0]
								# remove from INACTIVE_CHECKED, add to ACTIVE
								rm_set.put(rule_num)
								# remove from ACTIVE, add to INACTIVE_CHECKED
								add_set.put(to_rm)
					# COMMIT
					for from_act in add_set:
						self.config.inactive_set.append(from_act)
						self.config.inactive_rules[from_act] = self.config.active_rules[from_act]
						self.config.active_set.remove(from_act)
						del self.config.active_rules[from_act]

					for from_inact in rm_set:
						self.config.active_set.append(from_inact)
						self.config.active_rules[from_inact] = self.config.inactive_rules[from_inact]
						self.config.inactive_set.remove(from_inact)
						del self.config.inactive_rules[from_inact]

			action = "forwarded"
			if "dropped" in actions:
				action = "dropped"
			elif "normalised" in actions:
				action = "normalised"
			else:
				pass
			self.log(nxt_pkt, ip_pkt, action)


##########################################################################
# UTILITY FUNCTION
##########################################################################
def get_filter_queue(config):
	if config.mode == 0:
		return ModeZeroFilterQueue(config)
	elif config.mode == 1:
		return ModeOneFilterQueue(config)
	elif config.mode == 2:
		return ModeTwoFilterQueue(config)
	elif config.mode == 3:
		return ModeThreeFilterQueue(config)
	elif config.mode == 4:
		return ModeFourFilterQueue(config)
	else:
		return ModeFiveFilterQueue(config)