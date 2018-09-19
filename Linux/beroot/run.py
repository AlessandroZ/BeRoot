#!/usr/bin/env python
# -*- coding: utf-8 -*-
from beroot.analyse.analyse import Analyse
from beroot.checks.checks import Checks


def run():
    """
    Can be useful when called from other tools - as a package
    beroot.py is not needed anymore
    This function returns all restuls found
    """
    c = Checks()
    analyse = Analyse(c)
    results = analyse.run()
    return results
