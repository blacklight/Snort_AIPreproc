#!/usr/bin/python

import snortai

alerts = snortai.alerts()

for alert in alerts:
	print alert.gid, alert.sid, alert.rev
