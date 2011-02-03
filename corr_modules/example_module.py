#!/usr/bin/python

# Example correlation index in Python
# It simply does nothing (both the correlation index
# and the correlation weight are zero), use it as
# track for writing your own correlation modules

# Go to pymodule and run
# $ python setup.py build
# $ [sudo] python setup.py install
# in order to build and install the snortai Python module
import snortai

# Function that takes two alerts as arguments (arguments of
# alert object: 
# id, gid, sid, rev, description, priority, classification,
# timestamp, src_addr, dst_addr, src_port, dst_port, latitude,
# longitude) and returns a correlation index between 0 and 1
# expressing how correlated these two alerts are

def AI_corr_index ( alert1, alert2 ):
	# alerts = snortai.alerts()
	# for alert in alerts:
	# 	do_something
	#
	# print alert1.gid, alert1.sid, alert1.rev
	# print alert2.gid, alert2.sid, alert2.rev
	return 0.0

# Return the weight of this index, between 0 and 1

def AI_corr_index_weight():
	return 0.0

