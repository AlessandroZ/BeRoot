#!/usr/bin/env python
# -*- coding: utf-8 -*-
from beroot.analyse.analyse import Analyse
import time

if __name__ == '__main__':
	banner  = '|====================================================================|\n'
	banner += '|                                                                    |\n'
	banner += '|                      Linux Privilege Escalation                    |\n'
	banner += '|                                                                    |\n'
	banner += '|                          ! BANG BANG !                             |\n'
	banner += '|                                                                    |\n'
	banner += '|====================================================================|\n\n'
	print(banner)

	start_time = time.time()

	a = Analyse()
	a.run()
	print()
	
	elapsed_time = time.time() - start_time
	print(('[!] Elapsed time = ' + str(elapsed_time)))