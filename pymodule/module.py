#!/usr/bin/python

# Compile snortai module by typing, in pymodule directory:
# $ python setup.py build
# $ [sudo] python setup.py install
import snortai

# Get the alerts from Snort module as tuple
# (IMPORTANT: Snort and SnortAI module, as well as
# the web server running on top of the module, must
# be running in order to have this call successful)
alerts = snortai.alerts()

# Navigate the tuple of alerts
# Fields:
# id, gid, sid, rev, description, priority, classification,
# timestamp, from, to, from_port, to_port, latitude,
# longitude, alerts_count
for alert in alerts:
	print alert.gid, alert.sid, alert.rev, alert.description

