import sys
#import argparse
import config, pfilter, rules



#start execution
if __name__ == "__main__":

	print('[*] initializing filter.')
	confg   = config.get_config(sys.argv[1:])

	print('[*] configuring filter queue.')
	f_queue = pfilter.get_filter_queue(confg)

	f_queue.init_filter_params()

	# FIRE!
	f_queue.start_capture()