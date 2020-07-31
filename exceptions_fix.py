"""
Name:           Timing Attack
Date:           7/31/2020
Author:         inbarmada & louisa
Description:    TimingAttack is open source plugin to help pentesters for guessing if a username is valid or not by how long
                the system takes to respond for a success and a fail authenticationto. It means that if attackers can guess
                one valid username, then they can guess much more using the same technique.
Copyright (c) 2020, louisa & inbarmada
All rights reserved.
Please see the attached LICENSE file for additional licensing information.
"""

# Burp Exceptions Fix magic code
import sys, functools, inspect, traceback

def decorate_function(original_function):
    @functools.wraps(original_function)
    def decorated_function(*args, **kwargs):
        try:
            return original_function(*args, **kwargs)
        except:
            sys.stdout.write('\n\n*** PYTHON EXCEPTION\n')
            traceback.print_exc(file=sys.stdout)
            raise
    return decorated_function

def FixBurpExceptionsForClass(cls):
    for name, method in inspect.getmembers(cls, inspect.ismethod):
        setattr(cls, name, decorate_function(method))
    return cls

def FixBurpExceptions():
    for name, cls in inspect.getmembers(sys.modules['__main__'], predicate=inspect.isclass):
        FixBurpExceptionsForClass(cls)


