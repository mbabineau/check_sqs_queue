#!/usr/bin/env python
# encoding: utf-8
"""
sqsmon.py

Created by Mike Babineau <michael.babineau@gmail.com>.
Copyright (c) 2009 ShareThis. All rights reserved.
"""

import os, ConfigParser, boto
from optparse import OptionParser
from boto.sqs.connection import SQSConnection

def get_queue_count(queue, aws_id, aws_key):
	# Create connection to specified queue
	conn = boto.connect_sqs(aws_id, aws_key)
	if conn.get_queue(queue):
		q = conn.create_queue(queue)
	else:
		print 'Error: Queue "%s" does not exist.' % queue 
		exit()
	
	# Count and return the number of messages in queue
	count = q.count()
	return count


def main():
	# Parse arguments
	parser = OptionParser()
	parser.add_option("-c", "--config", dest="configfile", help="configuration file", metavar="FILE")
	parser.add_option("-q", "--queue", dest="queue", help="SQS queue name", metavar="NAME")
	parser.add_option("-m", "--max", dest="max", help="maximum allowable queue length (alert if length is greater than this)", metavar="N", default='100')
	(options, args) = parser.parse_args()
	configfile = options.configfile
	queue = options.queue
	max = options.max
	
	# Make sure queue was specified
	if not queue:
		print "Error: No queue specified"
		exit(1)
	
	# Make sure max is a number
	try:
		int(max)
	except ValueError:
		print 'Error: "%s" does not appear to be numerical.  Argument -m (--max) expects a number.' % max
		exit(1)
		
	# Parse config file
	if configfile:
		config = ConfigParser.ConfigParser()
		config.read(configfile)

	# Set aws_id and aws_key according to first match in:
	# 1) Specified config file
	# 2) Environment variable
	# 3) Boto config (first "~/.boto", then "/etc/boto.cfg")
	if configfile and config.get("Credentials", "aws_access_key_id"): aws_id = config.get("Credentials", "aws_access_key_id")
	elif os.getenv('AWS_ACCESS_KEY_ID'): aws_id = os.getenv('AWS_ACCESS_KEY_ID')
	elif boto.config.get('Credentials', 'aws_access_key_id'): aws_id = boto.config.get('Credentials', 'aws_access_key_id')

	else:
		print "Error: AWS_ACCESS_KEY_ID is not defined."
		exit(1)
	
	if configfile and config.get("Credentials", "aws_secret_access_key"): aws_key = config.get("Credentials", "aws_secret_access_key")
	elif boto.config.get('Credentials', 'aws_secret_access_key'): aws_key = boto.config.get('Credentials', 'aws_secret_access_key')
	elif os.getenv('AWS_SECRET_ACCESS_KEY'): aws_key = os.getenv('AWS_SECRET_ACCESS_KEY')
	else:
		print "Error: AWS_SECRET_ACCESS_KEY is not defined."
		exit(1)
		
	# Check queue
	count = get_queue_count(queue, aws_id, aws_key)
	
	# Compare queue length to specified max
	if int(count) > int(max):
		print 'Alert! Queue "%s" has %s messages in it (exceeds threshold of %s).' % (queue, count, max)
		# do stuff
	else:
		print 'All is well. Queue "%s" has %s messages in it (below threshold of %s).' % (queue, count, max)
		# do stuff


if __name__ == '__main__':
	main()

