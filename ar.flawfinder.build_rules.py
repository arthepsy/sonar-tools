#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
   The MIT License (MIT)
   
   Copyright (C) 2014 Andris Raugulis (moo@arthepsy.eu)
   
   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:
   
   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.
   
   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
   THE SOFTWARE.
"""
from __future__ import print_function
from tempfile import mkstemp
from shutil import copyfile
import sys, os, re, signal

TEMPFILE = None
PRIORITIES = ['INFO', 'MINOR', 'MAJOR', 'CRITICAL', 'BLOCKER']

def _err(*objs):
	print(*objs, file=sys.stderr)
	sys.exit(1)

def _out(*objs):
	print(*objs, file=sys.stdout)

def get_priority(level):
	if level == 0:
		level = 1
	p = level - 1
	if p >= 0 and p < 5:
		return PRIORITIES[p]
	else:
		raise Exception('Could not convert level %s to priority' % level)

def remove_tempfile():
	if TEMPFILE and os.path.isfile(TEMPFILE):
		os.remove(TEMPFILE)
		if os.path.isfile(TEMPFILE + 'c'):
			os.remove(TEMPFILE + 'c')

def signal_exit(signum, frame):
	remove_tempfile()
	sys.exit(signum)

def clean_text(txt):
	return re.sub(r'\s+', ' ', txt).replace(' .', '.').strip()

def get_issue_type(key, cat, name):
	issue_type = None
	if cat == 'race':
		issue_type = 'race'
	elif cat == 'crypto':
		issue_type = 'crypto'
	elif cat == 'obsolete':
		issue_type = 'obsolete'
	elif cat == 'random':
		issue_type = 'random'
	elif cat == 'shell':
		issue_type = 'shell'
	elif cat == 'integer':
		issue_type = 'integer'
	elif cat == 'tmpfile':
		issue_type = 'tmpfile'
	elif cat == 'format':
		issue_type = 'format'
	elif cat == 'input':
		issue_type = 'input'
	elif cat == 'access':
		issue_type = 'access'
	elif cat == 'buffer':
		if name.startswith('Environment') or ' environment ' in name:
			issue_type = 'env'
		else:
			issue_type = 'buffer'
	elif cat == 'free':
		issue_type = 'avoid'
	elif cat == 'misc':
		if key == 'getpass':
			issue_type = 'obsolete'
		elif key in ['getlogin', 'cuserid', 'EnterCriticalSection', 'InitializeCriticalSection']:
			issue_type = 'avoid'
		elif key in ['open', 'fopen']:
			issue_type = 'race'
		elif key in ['chroot', 'AddAccessAllowedAce', 'LoadLibrary', 'LoadLibraryEx', 'SetSecurityDescriptorDacl']:
			issue_type = 'examine'
	if issue_type is None:
		raise Exception('No issue type found for "%s"' % key)
	return issue_type

def get_rule_name(key, issue_type):
	name = None
	if issue_type == 'race':
		name = 'Race condition using function "%s"' % key
	elif issue_type == 'crypto':
		name = 'Insecure cryptography using function "%s"' % key
	elif issue_type == 'obsolete':
		name = 'Obsolete function "%s"' % key
	elif issue_type == 'random':
		name = 'Insecure random function "%s"' % key
	elif issue_type == 'shell':
		name = 'Program execution using function "%s"' % key
	elif issue_type == 'integer':
		name = 'Integer overflow could occur using function "%s" ' % key
	elif issue_type == 'tmpfile':
		name = 'Temporary file vulnerability using function "%s" ' % key
	elif issue_type == 'format':
		name = 'Format string vulnerability using function "%s" ' % key
	elif issue_type == 'input':
		name = 'Input from outside program using function "%s" ' % key
	elif issue_type == 'access':
		name = 'Unsafe privileges could occur using function "%s"' % key
	elif issue_type == 'env':
		name = 'Environment variable input using function "%s"' % key
	elif issue_type == 'buffer':
		name = 'Buffer overflow using function "%s"' % key
	elif issue_type == 'avoid':
		name = 'Avoid usage of function "%s"' % key
	elif issue_type == 'examine':
		name = 'Examine usage of function "%s"' % key
	if name is None:
		raise Exception('No rule name could be created for "%s"' % key)
	return name

def get_rule(key, rule_data):
	pri = get_priority(rule_data[1])
	cat = rule_data[4]
	name = rule_data[2].strip()
	desc = rule_data[3].strip()
	
	issue_type = get_issue_type(key, cat, name)
	desc = clean_text(name.rstrip('.') + ".\n\n" + desc)
	name = get_rule_name(key, issue_type)
	key = 'flawfinder.' + key
	
	return (key, pri, name, cat, desc)

def main():
	global TEMPFILE
	if len(sys.argv) != 2:
		_err('usage: %s <path-to-flawfinder>' % sys.argv[0])
	ff_path = os.path.abspath(sys.argv[1])
	if not os.path.isfile(ff_path):
		_err('err: file "%s" does not exists.' % ff_path)
	
	signal.signal(signal.SIGTERM, signal_exit)
	signal.signal(signal.SIGINT, signal_exit)
	
	(fh, fn) = mkstemp(suffix='.py', dir='.')
	TEMPFILE = fn
	os.close(fh)
	copyfile(ff_path, fn)
	module = os.path.splitext(os.path.basename(fn))[0]
	sys.path.append(os.path.realpath('.'))
	ff = __import__(module)
	remove_tempfile()
	
	ruleset = ff.c_ruleset
	ff.expand_ruleset(ruleset)
	sortedkeys = ruleset.keys()
	sortedkeys.sort()
	
	_out("<?xml version='1.0' encoding='UTF-8'?>")
	_out('<rules>')
	for key in sortedkeys:
		(rule_key, rule_pri, rule_name, rule_cat, rule_desc) = get_rule(key, ruleset[key])
		_out('\t<rule>')
		_out('\t\t<key>%s</key>' % rule_key)
		_out('\t\t<name><![CDATA[%s]]></name>' % rule_name)
		_out('\t\t<priority>%s</priority>' % rule_pri)
		_out('\t\t<configKey><![CDATA[%s@FLAWFINDER]]></configKey>' % rule_key)
		_out('\t\t<category name="%s" />' % rule_cat)
		_out('\t\t<description><![CDATA[%s]]></description>' % rule_desc)
		_out('\t</rule>')
	_out('</rules>')

if __name__ == '__main__':
	main()
