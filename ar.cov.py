#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
   The MIT License (MIT)
   
   Copyright (C) 2015 Andris Raugulis (moo@arthepsy.eu)
   
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
import sys, os, errno, re, glob
import click
from lxml import etree

from inspect import getmembers
from pprint import pprint

class SonarCoverage():
	VERSION = 1
	
	def create_tree(self, f):
		oroot_tag = 'coverage' if f == 'coverage' else 'unitTest'
		oroot = etree.XML('<%s version="%d"></%s>' % (oroot_tag, self.VERSION, oroot_tag))
		return etree.ElementTree(oroot)
	
	def get_cov_type(self, cov_format):
		if cov_format in ['junit', 'sgc-unit']:
			return 'tests'
		elif cov_format in ['cobertura', 'jacoco']:
			return 'coverage'
		else:
			raise TypeError('coverage format not valid', cov_format)
		
	@staticmethod
	def guess_format(src):
		if not os.path.isfile(src):
			return None
		itree = etree.parse(src)
		iroot = itree.getroot()
		if iroot.tag == 'testsuites' or iroot.tag == 'testsuite':
			return 'junit'
		elif itree.docinfo.root_name == 'coverage':
			return 'cobertura'
		elif itree.docinfo.root_name == 'report':
			return 'jacoco'
		elif iroot.tag == 'coverage':
			version = Utils.parse_int(iroot.get('version') or 0)
			if version == SonarCoverage.VERSION:
				return 'sgc-cov'
		elif iroot.tag == 'unitTest':
			version = Utils.parse_int(iroot.get('version') or 0)
			if version == SonarCoverage.VERSION:
				return 'sgc-unit'
		return None
	
	@staticmethod
	def find_class_file(classpath, source_dirs, depth = 0):
		files_found = []
		sclasspath = classpath.strip('.').split('.')
		if len(sclasspath) == 1 and len(sclasspath[0].strip()) == 0:
			raise ValueError('incorrect classpath "%s" ' % classpath);
		for source_dir in source_dirs:
			check_dir = os.path.join(source_dir, *sclasspath[:-1])
			for ext in ['.java', '.scala', '.groovy', '.py', '.as']:
				file_path = os.path.join(check_dir, sclasspath[-1:][0] + ext)
				if os.path.isfile(file_path):
					files_found.append(file_path)
			if len(files_found) == 0:
				for ext in ['.java', '.scala', '.groovy', '.py', '.as']:
					file_path = check_dir + ext
					if os.path.isfile(file_path):
						files_found.append(file_path)
		c = len(files_found)
		if c == 0:
			# check nested class in classpath
			if depth == 0 and len(sclasspath) > 1:
				return SonarCoverage.find_class_file('.'.join(sclasspath[:-1]), source_dirs, depth + 1)
		elif c == 1:
			return files_found[0]
		elif c > 1:
			# print files_found
			raise NotImplementedError('found multiple source files: %s' % (files_found))
		else:
			raise KeyError('did not find any source file for "%s" in %s' % (classpath, source_dirs))
	
	def convert(self, cfg):
		if cfg is None or not isinstance(cfg, Config):
			raise TypeError('config not valid', cfg)
		itree = etree.parse(cfg.src_file)
		otree = None
		
		parser = SonarCoverage.Parser(itree, cfg.root_dir, cfg.source_dirs, cfg.full_path)
		parser.verbose = cfg.verbose;
		
		cov_type = self.get_cov_type(cfg.src_format)
		if cov_type == 'coverage':
			coverage = parser.parse(cfg.src_format, cfg.dst_format)
			if coverage is not None:
				otree = self.create_tree(cov_type)
				self.fill_cov_tree(otree, coverage)
		else:
			tests = parser.parse(cfg.src_format, cfg.dst_format)
			if tests is not None:
				otree = self.create_tree(cov_type)
				self.fill_tst_tree(otree, tests)
		
		if otree is not None:
			otree.write(cfg.dst_file, pretty_print=True, encoding='UTF-8', xml_declaration=True)
		else:
			raise Exception('could not convert %s -> %s.' % (cfg.src_format, cfg.dst_format))
	
	def merge(self, cfg):
		if cfg is None or not isinstance(cfg, Config):
			raise TypeError('config not valid', cfg)
		otree = None
		
		cov_type = self.get_cov_type(cfg.src_format)
		if cov_type == 'coverage':
			raise Exception('not implemented')
		else:
			tests_merged = {}
			for src_file in cfg.src_file:
				#print src_file
				itree = etree.parse(src_file)
				parser = SonarCoverage.Parser(itree, cfg.root_dir, cfg.source_dirs)
				parser.verbose = cfg.verbose;
				tests = parser.parse(cfg.src_format, 'sonar')
				if tests is None:
					raise Exception('could not parse "%s"' % src_file)
				#print tests
				for test_filepath, test_cases in tests.iteritems():
					if test_cases is None or len(test_cases) == 0: continue
					if not test_filepath in tests_merged:
						tests_merged[test_filepath] = {}
					test_name_cache = {}
					for test_name, test_data in test_cases.iteritems():
						if test_data is None: continue
						test_time = abs(Utils.parse_int(test_data['duration']))
						if test_name in test_name_cache:
							test_name_cache[test_name] += 1
							test_name = "%s%d" % (test_name, test_name_cache[test_name])
						else:
							test_name_cache[test_name] = 1
						tests_merged[test_filepath][test_name] = {'duration': test_time}
						for node_name in ['error', 'failure', 'skipped']:
							for suffix in ['.txt', '.msg']:
								node_name_full = node_name + suffix
								if node_name_full in test_data:
									tests_merged[test_filepath][test_name][node_name_full] = test_data[node_name_full]
			otree = self.create_tree(cov_type)
			self.fill_tst_tree(otree, tests_merged)
		
		if otree is not None:
			otree.write(cfg.dst_file, pretty_print=True, encoding='UTF-8', xml_declaration=True)
		else:
			raise Exception('could not merge %s.' % (cfg.src_files))
	
	def fill_tst_tree(self, otree, tests):
		if otree is None or not isinstance(otree, etree._ElementTree):
			raise TypeError('tree not valid xml tree', otree)
		if tests is None or not isinstance(tests, dict):
			raise TypeError('tests not valid', tests)
		oroot = otree.getroot()
		for fp, test_cases in tests.iteritems():
			if test_cases is None or len(test_cases) == 0: continue
			ofile = etree.SubElement(oroot, 'file')
			ofile.set('path', fp)
			for test_name, test_data in test_cases.iteritems():
				if test_data is None: continue
				if 'duration' in test_data:
					test_time = abs(Utils.parse_int(test_data['duration']))
				else:
					test_time = 0
				otc = etree.SubElement(ofile, 'testCase')
				otc.set('name', test_name)
				otc.set('duration', str(test_time))
				for node_name in ['error', 'failure', 'skipped']:
					if node_name + '.txt' in test_data:
						onode = etree.SubElement(otc, node_name)
						onode.text = test_data[node_name + '.txt']
						# message is required
						if node_name + '.msg' in test_data:
							onode.set('message', test_data[node_name + '.msg'] or node_name)
						else:
							onode.set('message', node_name)
	
	def fill_cov_tree(self, otree, coverage):
		if otree is None or not isinstance(otree, etree._ElementTree):
			raise TypeError('tree not valid xml tree', otree)
		if coverage is None or not isinstance(coverage, dict):
			raise TypeError('coverage not valid', coverage)
		oroot = otree.getroot()
		for fp, lines in coverage.iteritems():
			if lines is None or len(lines) == 0: continue
			ofile = etree.SubElement(oroot, 'file')
			ofile.set('path', fp) 
			for line_nr, cov_data in lines.iteritems():
				if cov_data is None: continue
				if not line_nr > 0: continue
				oline = etree.SubElement(ofile, 'lineToCover')
				oline.set('lineNumber', str(line_nr))
				oline.set('covered', 'true' if cov_data['lhits'] > 0 else 'false')
				bcount = cov_data['bcount']
				bhits = cov_data['bhits']
				if bcount > 0:
					oline.set('branchesToCover', str(bcount))
				if bhits > 0:
					oline.set('coveredBranches', str(bhits))
	
	class Parser():
		def __init__(self, itree, root_dir = None, source_dirs = [], set_full_path = False):
			if itree is None or not isinstance(itree, etree._ElementTree):
				raise TypeError('tree not valid xml tree', itree)
			self.itree = itree
			self.root_dir = Utils.strip_dir(root_dir or '')
			self.source_dirs = Utils.parse_dirs(root_dir, source_dirs, reduced=False, existing=True)
			self.verbose = False
			self.set_full_path = set_full_path
		
		def parse(self, src_format, dst_format):
			if dst_format == 'sonar':
				if src_format == 'cobertura':
					return self.from_cobertura()
				elif src_format == 'junit':
					return self.from_junit()
				elif src_format == 'jacoco':
					return self.from_jacoco()
				elif src_format == 'sgc-unit':
					return self.from_sgc_unit()
			return None
		
		def strip_root(self, fn):
			spl = len(self.root_dir or '')
			if spl > 0:
				fn = fn[spl + 1:]
			return fn
		
		def from_sgc_unit(self):
			tests = {}
			iroot = self.itree.getroot()
			for ifile in iroot.iter('file'):
				test_filepath = ifile.get('path')
				if not test_filepath: continue
				if not test_filepath in tests:
					tests[test_filepath] = {}
				for test_node in ifile.iter('testCase'):
					test_name = test_node.get('name') or ''
					if not test_name: continue
					test_time = Utils.parse_int(test_node.get('duration') or '0')
					tests[test_filepath][test_name] = {'duration': test_time}
					for node_name in ['error', 'failure', 'skipped']:
						inode = test_node.find(node_name)
						if inode is not None:
							node_txt = (inode.text or '').strip()
							node_msg = (inode.get('message') or '').strip()
							if len(node_txt) > 0 or len(node_msg) > 0:
								tests[test_filepath][test_name][node_name + '.txt'] = node_txt
							if len(node_msg) > 0:
								tests[test_filepath][test_name][node_name + '.msg'] = node_msg
			return tests
		
		def from_junit(self):
			tests = {}
			cache = {}
			testfile_nodes = {}
			iroot = self.itree.getroot()
			for its in iroot.iter('testsuite'):
				package = its.get('package')
				name = its.get('name')
				testsuite_classpath = '.'.join([(package or '').strip(),(name or '').strip()]).strip('.')
				if testsuite_classpath == 'pytest':
					testsuite_classpath = ''
				test_cases = Utils.parse_num(its.xpath('count(./testcase)'))
				if test_cases < 1: continue
				for itc in its.iter('testcase'):
					test_classname = itc.get('classname') or ''
					if (len(test_classname) == 0):
						test_name = itc.get('name')
						if (len(testsuite_classpath) > 0):
							test_classname = '.'.join([testsuite_classpath, test_name])
						else:
							test_classname = test_name
					if test_classname in cache:
						test_filepath = cache[test_classname]
					else:
						if self.verbose:
							print '[junit] searching class file for "%s"' % test_classname
						test_filepath = SonarCoverage.find_class_file(test_classname, self.source_dirs)
						test_filepath = self.strip_root(test_filepath)
						if self.verbose:
							print '[junit] found corresponding file "%s"' % test_filepath
						cache[test_classname] = test_filepath
					if not test_filepath in testfile_nodes:
						testfile_nodes[test_filepath] = []
					testfile_nodes[test_filepath].append(itc)
			
			for test_filepath, test_nodes in testfile_nodes.iteritems():
				if test_nodes is None or len(test_nodes) == 0: continue
				if not test_filepath in tests:
					tests[test_filepath] = {}
				test_name_cache = {}
				for test_node in test_nodes:
					if test_node is None: continue
					test_name = test_node.get('name') or ''
					test_time = abs(Utils.parse_int(round(Utils.parse_num(test_node.get('time') or '0') * 1000)))
					if test_name in test_name_cache:
						test_name_cache[test_name] += 1
						test_name = "%s%d" % (test_name, test_name_cache[test_name])
					else:
						test_name_cache[test_name] = 1
					tests[test_filepath][test_name] = {'duration': test_time}
					for node_name in ['error', 'failure', 'skipped']:
						inode = test_node.find(node_name)
						if inode is not None:
							node_txt = (inode.text or '').strip()
							node_msg = (inode.get('message') or '').strip()
							if len(node_txt) > 0 or len(node_msg) > 0:
								tests[test_filepath][test_name][node_name + '.txt'] = node_txt
							if len(node_msg) > 0:
								tests[test_filepath][test_name][node_name + '.msg'] = node_msg
			return tests
		
		def from_cobertura(self):
			cb_source_dirs = Cobertura.get_valid_sources(self.itree, self.source_dirs)
			Cobertura.reduce_filepaths(self.itree, cb_source_dirs, [self.root_dir] if self.root_dir else self.source_dirs, self.set_full_path)
			
			coverage = {}
			iroot = self.itree.getroot()
			for cc in iroot.iter('class'):
				cn = cc.get('name')
				mx = re.match(r'^[^\$]+\$_(.*)$', cn)
				subcoverage = mx.group(1) if mx else None
				if subcoverage is not None:
					# NOTE: ignore subcoverage (closures)
					continue
				fn = cc.get('filename')
				if fn is not None:
					if not fn in coverage:
						coverage[fn] = {}
					if self.verbose:
						print '[cobertura] parsing "%s"' % fn
					for cl in cc.iterfind('./lines/line'):
						line_nr = Utils.parse_int(cl.get('number') or '0')
						if not line_nr in coverage[fn]:
							coverage[fn][line_nr] = {'lhits':0, 'bcount':0, 'bhits':0}
						else:
							raise Exception('Cobertura covered file "%s" line %d already covered.' % (fn, line_nr))
						lhits = Utils.parse_int(cl.get('hits') or '0')
						has_branch = ((cl.get('branch') or '').lower() == 'true')
						
						bcount = 0
						bhits = 0
						if has_branch:
							bcount = 1
						cond_cov = cl.get('condition-coverage')
						if cond_cov is not None:
							mx = re.match(r'.*\s+\(\s*([0-9]+)\s*/\s*([0-9]+)\s*\)$', cond_cov)
							if mx is not None:
								bhits = Utils.parse_int(mx.group(1))
								bcount = Utils.parse_int(mx.group(2))
						if (bhits > bcount):
							bcount = bhits
						
						coverage[fn][line_nr]['lhits'] = lhits
						coverage[fn][line_nr]['bcount'] = bcount
						coverage[fn][line_nr]['bhits'] = bhits
			return coverage
		
		def from_jacoco(self):
			coverage = {}
			iroot = self.itree.getroot()
			for pkg_node in iroot.iter('package'):
				pkg_path = (pkg_node.get('name') or '').strip()
				if len(pkg_path) == 0: 
					continue
				for sf_node in pkg_node.findall('sourcefile'):
					sf_name = (sf_node.get('name') or '').strip()
					if len(sf_name) == 0:
						continue
					rfp = os.path.join(pkg_path, sf_name)
					if self.verbose:
						print '[jacoco] searching relative file "%s"' % rfp
					found = 0
					found_fn = None
					for source_dir in self.source_dirs:
						ffp = os.path.join(source_dir, rfp)
						if os.path.isfile(ffp):
							found += 1
							found_fn = ffp
							break
					if found != 1:
						raise Exception('JaCoCo covered file "%s" found %d times.' % (rfp, found))
					fn = self.strip_root(found_fn)
					if self.verbose:
						print '[jacoco] found corresponding file "%s"' % fn
					
					if not found_fn in coverage:
						coverage[fn] = {}
					for line in sf_node.findall('line'):
						line_nr = Utils.parse_int(line.get('nr') or '0')
						if line_nr in coverage[fn]:
							raise Exception('JaCoCo covered file "%s" line %d already covered.' % (fn, line_nr))
						line_mi = Utils.parse_int(line.get('mi') or '0')
						line_ci = Utils.parse_int(line.get('ci') or '0')
						line_mb = Utils.parse_int(line.get('mb') or '0')
						line_cb = Utils.parse_int(line.get('cb') or '0')
						coverage[fn][line_nr] = {'lhits':line_ci, 'bcount':line_mb + line_cb, 'bhits':line_cb}
			return coverage

class Utils():
	@staticmethod
	def parse_int(s):
		return int(Utils.parse_num(s))
	
	@staticmethod
	def parse_num(s): 
		try: 
			return int(s)
		except ValueError:
			return float(s)
	
	@staticmethod
	def strip_dir(path):
		return path.strip().rstrip('/')
	
	@staticmethod
	def filter_dirs(dirs):
		return filter(lambda d: len(d.strip()) > 0, map(lambda d: d.rstrip('/'), dirs))
	
	@staticmethod
	def parse_dirs(root, dirs, reduced=True, existing=False):
		"""Parse directory list.
		
		Args:
			root: (list) root directory
			dirs: (list) directories
			reduced: (bool) reduce to root directory
			existing: (bool) check if directories exist
		"""
		if existing == True:
			for cdir in dirs or []:
				if not os.path.isdir(cdir):
					raise Exception('directory "%s" does not exist.' % cdir)
		rdirs = []
		if root is not None and len(root) > 0:
			rdirs = []
			for cdir in dirs or []:
				if not cdir.startswith(root):
					raise Exception('directory "%s" is not relative to %s.' % (cdir, root))
				if reduced == False:
					rdirs.append(cdir)
			if reduced == True:
				rdirs = [root]
		else:
			rdirs = dirs or []
		return Utils.filter_dirs(rdirs)

class Cobertura():
	@staticmethod
	def get_version(itree):
		if itree is None or not isinstance(itree, etree._ElementTree):
			raise TypeError('tree not valid xml tree', itree)
		dtd = itree.docinfo.system_url or ''
		if dtd is not None:
			m = re.match(r'^.*/coverage-([0-9]+)\.dtd$', dtd)
			if m is not None:
				return parse_num(m.group(1))
		return 3
	
	@staticmethod
	def get_valid_sources(itree, source_dirs):
		"""Returns valid source directories"""
		if itree is None or not isinstance(itree, etree._ElementTree):
			raise TypeError('tree not valid xml tree', itree)
		iroot = itree.getroot()
		source_dirs = Utils.filter_dirs(source_dirs)
		cb_source_dirs = []
		had_sources = False
		isources = iroot.find('sources')
		if isources is not None:
			had_sources = True
			unused_source_dirs = source_dirs[:]
			for isource in isources.iter('source'):
				if isource is None:
					continue
				cb_source_dir = os.path.realpath(Utils.strip_dir(isource.text))
				found = False
				for source_dir in source_dirs:
					if (cb_source_dir + '/').startswith(source_dir + '/'):
						if source_dir in unused_source_dirs:
							unused_source_dirs.remove(source_dir)
						found = True
						cb_source_dirs.append(cb_source_dir)
						break
				if not found:
					raise Exception('Cobertura report source directory "%s" is not relative to %s.' % (cb_source_dir, source_dirs)) 
			for source_dir in unused_source_dirs:
				cb_source_dirs.append(source_dir)
		else:
			isources = etree.SubElement(iroot, 'sources')
		isources.clear()
		for source_dir in source_dirs:
			isource = etree.SubElement(isources, 'source')
			isource.text = source_dir
			if not had_sources:
				cb_source_dirs.append(source_dir)
		return cb_source_dirs
	
	@staticmethod
	def reduce_filepaths(itree, cb_source_dirs, reduce_dirs, set_full_path = False):
		"""Reduce class filepaths"""
		if itree is None or not isinstance(itree, etree._ElementTree):
			raise TypeError('tree not valid xml tree', itree)
		
		iroot = itree.getroot()
		cb_source_dirs = Utils.filter_dirs(cb_source_dirs)
		reduce_dirs = Utils.filter_dirs(reduce_dirs)
		for iclass in iroot.iter('class'):
			class_fp = iclass.get('filename')
			if class_fp is not None:
				found = 0
				valid_fp = None
				for cb_source_dir in cb_source_dirs:
					check_fp = os.path.join(cb_source_dir, class_fp)
					if os.path.isfile(check_fp):
						found += 1
						valid_fp = Utils.strip_dir(check_fp)
						break
				if found != 1:
					raise Exception('Cobertura covered file "%s" found %d times in %s.' % (class_fp, found, cb_source_dirs))
				if set_full_path:
					class_fp_new = valid_fp
				else:
					class_fp_new = ''
					for reduce_dir in reduce_dirs:
						if valid_fp.startswith(reduce_dir + '/'):
							fp_tmp = valid_fp[len(reduce_dir) + 1:]
							fp_len = len(class_fp_new)
							if fp_len == 0 or fp_len > len(fp_tmp):
								class_fp_new = fp_tmp
				if len(class_fp_new) == 0:
					raise Exception('Cobertura covered file "%s" not relative to %s' % (valid_fp, reduce_dirs))
				if class_fp != class_fp_new:
					iclass.set('filename', class_fp_new)

class Config(object):
	SRC_FORMATS = ['cobertura', 'jacoco', 'junit']
	DST_FORMATS = ['sonar']
	DST_DEFAULT_FORMAT = 'sonar'
	
	def __init__(self, verbose=False):
		self.verbose = verbose
		self.root_dir = None
		self.source_dirs = []
		self.full_path = False
		self.src_file = None
		self.dst_file = None
		self.src_format = None
		self.dst_format = None

pass_config = click.make_pass_decorator(Config, ensure=True)
class CmdLine():
	_type_dir = click.Path(exists=True, file_okay=False, dir_okay=True, readable=True, resolve_path=True)
	_type_rofile = click.Path(exists=True, file_okay=True, dir_okay=False, readable=True, resolve_path=True)
	_type_rwfile = click.Path(exists=False, file_okay=True, dir_okay=False, writable=True, resolve_path=True)
	
	def run(self):
		self.cli()
	
	@click.group()
	@click.option('--verbose', '-v', default=False, is_flag=True)
	@click.pass_context
	def cli(ctx, verbose):
		cfg = ctx.ensure_object(Config)
		cfg.verbose = verbose
	
	@cli.command('convert', short_help='convert report to other format')
	@click.option('--root-dir', '-r', type=_type_dir)
	@click.option('source_dirs', '--source-dir', '-s', multiple=True, type=_type_dir, required=True)
	@click.option('--full-path', '-f', help='Output full paths', default=False, is_flag=True)
	@click.option('--input-format', '-i', metavar='[%s]' % '|'.join(Config.SRC_FORMATS), help='Input format (guess by default)', type=click.Choice(['guess']  + Config.SRC_FORMATS), default='guess', required=True)
	@click.option('--output-format', '-o', metavar='[%s]' % '|'.join(Config.DST_FORMATS), help='Output format (default: %s)' % Config.DST_DEFAULT_FORMAT, type=click.Choice(Config.DST_FORMATS), default=Config.DST_DEFAULT_FORMAT, required=True)
	@click.argument('src', metavar='<input>', type=_type_rofile)
	@click.argument('dst', metavar='<output>', type=_type_rwfile)
	#@pass_config
	@click.pass_context
	def convert(ctx, root_dir, source_dirs, src, dst, full_path, input_format, output_format):
		"""Convert coverage/unit report to other format"""
		if input_format == 'guess':
			input_format = SonarCoverage.guess_format(src)
		if not input_format or not input_format in Config.SRC_FORMATS:
			raise click.UsageError('Cannot guess input format, please specify.')
		cfg = ctx.ensure_object(Config)
		cfg.root_dir = root_dir
		cfg.source_dirs = set(source_dirs)
		cfg.full_path = full_path
		cfg.src_file = src
		cfg.dst_file = dst
		cfg.src_format = input_format
		cfg.dst_format = output_format
		sc = SonarCoverage()
		sc.verbose = cfg.verbose
		sc.convert(cfg)
	
	@cli.command('fixpath', short_help='fix report file/dir paths')
	@pass_config
	def fixpath(config):
		"""Fix coverage/unit report file/directory path"""
		pass
	
	@cli.command('merge', short_help='merge reports to single file')
	@click.option('mask', '--file-mask', '-m', required=True, help='File mask', metavar='MASK')
	@click.option('--input-format', '-i', metavar='[%s]' % '|'.join(Config.SRC_FORMATS), help='Input format (guess by default)', type=click.Choice(['guess']  + Config.SRC_FORMATS), default='guess', required=True)
	@click.option('--output-format', '-o', metavar='[%s]' % '|'.join(Config.DST_FORMATS), help='Output format (default: %s)' % Config.DST_DEFAULT_FORMAT, type=click.Choice(Config.DST_FORMATS), default=Config.DST_DEFAULT_FORMAT, required=True)
	@click.argument('dst', metavar='<output>', type=_type_rwfile)
	@click.pass_context
	def merge(ctx, mask, dst, input_format, output_format):
		"""Merge multiple coverage/unit reports to single file"""
		guess_format = (input_format == 'guess')
		src_files = []
		for src in glob.glob(mask):
			src_files.append(src)
			if guess_format:
				src_format = SonarCoverage.guess_format(src)
				if src_format is not None:
					if input_format == 'guess':
						input_format = src_format
					elif input_format != src_format:
						raise click.UsageError('Multiple input formats found: %s, %s.' % (input_format, src_format))
		if len(src_files) == 0:
			raise click.UsageError('No files found by mask %s.' % mask)
		valid_format = False
		if input_format:
			if input_format in Config.SRC_FORMATS:
				valid_format = True
			if input_format in ['sgc-unit', 'sgc-cov']:
				valid_format = True
		if not valid_format:
			raise click.UsageError('Cannot guess input format, please specify.')
		cfg = ctx.ensure_object(Config)
		#cfg.root_dir = None
		#cfg.source_dirs = None
		cfg.src_file = src_files
		cfg.dst_file = dst
		cfg.src_format = input_format
		cfg.dst_format = output_format
		sc = SonarCoverage()
		sc.verbose = cfg.verbose
		sc.merge(cfg)

if __name__ == '__main__':
	cmd = CmdLine()
	cmd.run()


