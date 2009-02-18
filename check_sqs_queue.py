#!/usr/bin/env python
# encoding: utf-8
"""
check_sqs_queue.py

Nagios plugin for checking the length of an Amazon SQS queue.  This can also be run as a 
stand-alone monitoring script and email recipients directly.

Requirements:
-boto, a Python interface for Amazon Web Services (http://code.google.com/p/boto/).
-AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, read in from same-named environment 
variables, from boto.cfg (see boto manual), or from a specified config file (see README).

Created by Mike Babineau <michael.babineau@gmail.com>.
Copyright (c) 2009 ShareThis. All rights reserved.
"""

import os, sys, ConfigParser, boto, smtplib
from optparse import OptionParser
from boto.sqs.connection import SQSConnection

USAGE = """\nUsage: check_sqs_queue.py -q <queue name> [-w <warning threshold>] -c <critical threshold> [-n <recipient(s)>] [-f <config file] [-h]"""
config = ConfigParser.ConfigParser()

def validate_thresholds(warn, crit):
	"""Perform sanity checks on threshold values"""
	# Verify thresholds are numeric
	for i in ('-w (--warning)', warn), ('-c (--critical)', crit):
		try: 
			int(i[1])
		except ValueError:
			print 'Error: "%s" does not appear to be numeric.  Argument "%s" expects a number.' % (i[1], i[0])
			sys.exit(3)
	
	if int(warn) > int(crit):
		print 'Error: Warning threshold %s exceeds critical threshold %s.' % (warn, crit)
		print USAGE
		sys.exit(3)
		
def get_queue_count(queue, aws_id, aws_key):
	"""Count the number of messages in a queue"""
	# Create connection to specified queue
	conn = boto.connect_sqs(aws_id, aws_key)
	if conn.get_queue(queue):
		q = conn.create_queue(queue)
	else:
		print 'Error: Queue "%s" does not exist.' % queue 
		print USAGE
		sys.exit(3)
	
	count = q.count()
	return count

def get_config(section, option):
	try:
		config.get(section, option)
	except (ConfigParser.NoSectionError, ConfigParser.NoOptionError, NameError):
		print 'Error: Option "%s" not defined in configuration file.' % option
		print USAGE
		sys.exit(3)
	else:
		return config.get(section, option)

def alert_by_email(queue, count, recipients):
	# Parse config settings
	smtp_server = get_config('SMTP', 'smtp_server')
	smtp_port = get_config('SMTP', 'smtp_port')
	smtp_user = get_config('SMTP', 'smtp_user')
	smtp_password = get_config('SMTP', 'smtp_password')
	
	# Connect to SMTP server
	server = smtplib.SMTP(smtp_server, smtp_port)
	server.set_debuglevel(0)
	server.ehlo(smtp_user)
	server.starttls()
	server.ehlo(smtp_user)
	server.login(smtp_user, smtp_password)
	
	# Build and send message
	msg_subject = 'Queue CRITICAL: "%s" contains %s messages' % (queue, count)
	msg_body = '"%s" contains %s messages' % (queue, count)
	recipientlist = recipients.split(',')
	for recipient in recipientlist:
		msg = 'Subject: %s\nTo: %s\n\n%s' % (msg_subject, recipient, msg_body)
		server.sendmail(smtp_user, recipient, msg)
	server.quit()

def main():
	# Parse arguments
	parser = OptionParser()
	parser.add_option("-f", "--config", dest="configfile", metavar="FILE", help="configuration file")
	parser.add_option("-q", "--queue", dest="queue", help="Amazon SQS queue name (name only, not the URL)")
	parser.add_option("-w", "--warning", dest="warn", help="warning threshold")
	parser.add_option("-c", "--critical", dest="crit", help="critical threshold")
	parser.add_option("-n", "--notify", dest="recipients", metavar='RECIPIENT(s)', help="comma-separated list of email addresses to notify")
	(options, args) = parser.parse_args()
	configfile = options.configfile
	queue = options.queue
	warn = options.warn
	crit = options.crit
	recipients = options.recipients
	
	if not crit:
		print "Error: No critical threshold specified."
		print USAGE
		sys.exit(3)
	
	if not warn:
		warn = crit
	
	# Perform sanity checks on thresholds
	validate_thresholds(warn, crit)
	
	if not queue:
		print "Error: No queue specified."
		print USAGE
		sys.exit(3)
		
	# Parse config file
	if configfile:
		config.read(configfile)

	# Set aws_id and aws_key according to first match in:
	# 1) Specified config file
	# 2) Environment variable
	# 3) Boto config (first "~/.boto", then "/etc/boto.cfg")	
	try:
		aws_id = config.get("AWS", "aws_access_key_id")
	except (ConfigParser.NoSectionError, ConfigParser.NoOptionError, NameError):
		aws_id = None
	
	if not aws_id: 
		if os.getenv('AWS_ACCESS_KEY_ID'): aws_id = os.getenv('AWS_ACCESS_KEY_ID')
		elif boto.config.get('Credentials', 'aws_access_key_id'): aws_id = boto.config.get('Credentials', 'aws_access_key_id')
		else:
			print "Error: AWS_ACCESS_KEY_ID is not defined."
			print USAGE
			sys.exit(3)

	try:
		aws_key = config.get("AWS", "aws_secret_access_key")
	except (ConfigParser.NoSectionError, ConfigParser.NoOptionError, NameError):
		aws_key = None
	
	if not aws_key: 
		if os.getenv('AWS_SECRET_ACCESS_KEY'): aws_key = os.getenv('AWS_SECRET_ACCESS_KEY')
		elif boto.config.get('Credentials', 'aws_secret_access_key'): aws_key = boto.config.get('Credentials', 'aws_secret_access_key')
		else:
			print "Error: AWS_SECRET_ACCESS_KEY is not defined."
			print USAGE
			sys.exit(3)

	# Get queue length, compare to thresholds, and take appropriate action
	count = get_queue_count(queue, aws_id, aws_key)
	if int(count) < int(warn):
		print 'Queue OK: "%s" contains %s messages' % (queue, count)
		sys.exit(0)
	elif int(count) >= int(crit):
		if recipients: alert_by_email(queue, count, recipients)
		print 'Queue CRITICAL: "%s" contains %s messages' % (queue, count)
		sys.exit(2)
	else:
		print 'Queue WARNING: "%s" contains %s messages' % (queue, count)
		sys.exit(1)
	
if __name__ == '__main__':
	main()