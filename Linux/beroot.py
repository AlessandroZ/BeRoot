#!/usr/bin/env python
# -*- coding: utf-8 -*-
from beroot.analyse.analyse import Analyse
from beroot.checks.checks import Checks
import time

if __name__ == '__main__':
	banner  = '|====================================================================|\n'
	banner += '|                                                                    |\n'
	banner += '|                      Linux Privilege Escalation                    |\n'
	banner += '|                                                                    |\n'
	banner += '|                          ! BANG BANG !                             |\n'
	banner += '|                                                                    |\n'
	banner += '|====================================================================|\n'

	start_time = time.time()

	c = Checks()
	analyse = Analyse(c)
	
	analyse.print_log('', banner)
	analyse.run()

	elapsed_time = time.time() - start_time
	analyse.print_log('info', 'Elapsed time = {elapsed_time}'.format(elapsed_time=elapsed_time))