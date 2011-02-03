#!/usr/bin/python

# Example correlation index in Python

# XXX You may have an 'undefined reference to PyNone_Struct
# after running Snort with your module, you're facing an
# annoying bug due to the dynamically linked Python library.
# I'm sorry, but I'm still looking for a solution for this,
# and anyway it only happens when you import the module
# 'snortai'

# import snortai

# Function that takes two alerts as arguments (arguments of
# alert object: 
# id, gid, sid, rev, description, priority, classification,
# timestamp, from, to, from_port, to_port, latitude,
# longitude, alerts_count) and returns a correlation index
# between 0 and 1 expressing how correlated these two alerts are

def AI_corr_index ( alert1, alert2 ):
	return 0.0

# Return the weight of this index, between 0 and 1

def AI_corr_index_weight():
	return 0.0

