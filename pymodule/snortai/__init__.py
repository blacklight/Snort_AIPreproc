#!/usr/bin/python

import urllib
import xml.dom.minidom as xml

class alert:
	"""Class that models a Snort alert type"""
	def __init__ ( self, id = None, gid = None, sid = None, rev = None,
			priority = None, classification = None, description = None,
			src_addr = None, dst_addr = None, src_port = None, dst_port = None,
			latitude = None, longitude = None, ):
		self.id = id
		self.gid = gid
		self.sid = sid
		self.rev = rev
		self.priority = priority
		self.latitude = latitude
		self.longitude = longitude
		self.description = description
		self.classification = classification
		self.src_addr = src_addr
		self.dst_addr = dst_addr
		self.src_port = src_port
		self.dst_port = dst_port

resource_url = 'http://localhost:7654/alerts.cgi'
response_text = None;

def alerts():
	url = urllib.urlopen ( resource_url )
	response_text = url.read()
	document = xml.parseString ( response_text )
	alerts = []

	for element in document.getElementsByTagName ( 'alert' ):
		a = alert()

		for attr in element.attributes.keys():
			if attr in ['id', 'gid', 'sid', 'rev', 'priority', 'latitude', 'longitude', 'classification']:
				setattr ( a, attr, element.attributes[attr].value )
			elif attr == 'date':
				setattr ( a, 'timestamp',  element.attributes[attr].value )
			elif attr == 'label':
				setattr ( a, 'description', element.attributes[attr].value )
			elif attr == 'from':
				setattr ( a, 'src_addr', element.attributes[attr].value )
			elif attr == 'to':
				setattr ( a, 'dst_addr', element.attributes[attr].value )
			elif attr == 'from_port':
				setattr ( a, 'src_port', element.attributes[attr].value )
			elif attr == 'to_port':
				setattr ( a, 'dst_port', element.attributes[attr].value )

		alerts.append ( a )

	return alerts

