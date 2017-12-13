from setuptools import setup

setup(
    name='FG Service Search',
    version='0.1',
    install_requires=['datetime', 'simplejson', 'argparse', 'suds-jurko', 'lxml'],
    url='',
    license='',
    author='Nick Petersen',
    author_email='',
    description='Search FortiGate(s) config searching for objects matching one or more supplied protocol/port '
                'combinations. Searches services, servicegroups, vips, vipgroups.  Then see if the identified objects'
                'used in policies, returning list of objects and policy usage'
)

import os
print("installing ftntlib from source")
os.system("cd ./dependencies/ftntlib-0.4.0.dev13; python3 ./setup.py install")