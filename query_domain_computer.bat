@echo off
set THISDATE=%DATE:~0,4%%DATE:~5,2%%DATE:~8,2%

cd d:\Ad\daily
d:\python27\python.exe query_domain_computer.py -r office.example.com -n 10.1.1.2 -s 10.1.1.2 -u testuser -p test123 -d data/adcomputers.%THISDATE%.db -l query_computer_py.log -w 10. >> d:\Ad\daily\query_computer_bat.log 2>&1
d:\python27\python.exe query_domain_computer.py -r example.cn -n 10.2.2.3 -d data/adcomputers.%THISDATE%.db -l query_computer_py.log -w 10. >> d:\Ad\daily\query_computer_bat.log 2>&1

d:\python27\python.exe query_domain_config.py -r example.cn -n 10.2.2.3 -d admin >> d:\Ad\daily\query_config_log.txt 2>&1
d:\python27\python.exe query_domain_config.py -r ny.example.com -n 10.8.0.4 -s 10.8.0.4 -u nytest -p nytest123 -d admin  >> d:\Ad\daily\query_config_log.txt 2>&1
