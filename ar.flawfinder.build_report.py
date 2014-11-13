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
from xml.sax.saxutils import quoteattr
import sys, re, os

def _err(*objs):
	print(*objs, file=sys.stderr)
	sys.exit(1)

def _out(*objs):
	print(*objs, file=sys.stdout)

def main():
	_out("<?xml version='1.0' encoding='UTF-8'?>")
	_out('<results>')
	lines = sys.stdin.readlines()
	for line in lines:
		mx = re.match(r'^([^:]+):([0-9]+):[0-9]* +\[([0-9]+)\] +\(([^(]*)\) +([^:]+): +(.*)$', line.strip())
		if mx is None: continue
		(issue_file, issue_line, issue_level, issue_category, issue_key, issue_text) = mx.groups()
		issue_file = os.path.realpath(issue_file)
		issue_text = quoteattr(issue_text)
		_out('\t<error file="%s" line="%s" id="flawfinder.%s" msg=%s />' % (issue_file, issue_line, issue_key, issue_text))
	_out('</results>')

if __name__ == '__main__':
	main()
