sonar-tools
===========

Useful SonarQube tools for running analysis

flawfinder
----------
Imports [flawfinder](http://www.dwheeler.com/flawfinder/) reported issues into SonarQube.

### Usage

* Create rule repository:
```
./ar.flawfinder.build_rules.py ~/bin/flawfinder > flawfinder.rules.xml
```
Import into SonarQube's [sonar-cxx](https://github.com/wenns/sonar-cxx) plugin web UI configuration, code Analysis subcategory, external rules.  Restart SonarQube.

* Create report:
```
~/bin/flawfinder -DQS /path/to/source | ./ar.flawfinder.build_report.py > /path/to/flawfinder.report.xml
```
* Run analysis with `sonar.cxx.other.reportPath` property set to `/path/to/flawfinder.report.xml`

