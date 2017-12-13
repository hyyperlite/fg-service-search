FortiGate Service Search fgss.py
=======================

A program to search one or more FortiGates/FortiGate VDOMs for services, service groups,
VIPS and VIP Groups that match one or more supplied protocol/port combination(s).  Any matches
identified are then searched for in the firewall policy to see if they are used.  If used
the policy IDs each are used in are marked.  A JSON list of relevant matches and
associations is returned.

For examples of file formats to use when specifying lists of fortigates/vdoms or protocol/ports
via file, please refer to the example-files directory.

Tested with Python 3.6.3 on Windows
Tested with Python 3.5.2 on Ubuntu 16.04

----
**Required Packages**
- ftntlib   Available from Fortinet Developer Network. (Follow included readme to install)
- simplejson
- argparse
- datetime

**Example Usage:**

*Help*
``python3 fgss.py -h``

*Single Fortigate/VDOM, Single protocol/port search*
``python3 fgss.py --fortigate <hostname|ip> --vdom <vdom> --login <login> --passwd <passwd> --searchproto <tcp|udp|sctp> --searchport <port>``

*Multiple Fortigates/VDOMs, Multiple protcols/ports*
``python3 fgss.py --fglist </path/to/fglist> --servicelist </path/to/servicelist>``

*Override default output file (./ouput.txt)*
``python3 fgss.py --fglist </path/to/fglist> --servicelist </path/to/servicelist> --outputfile <path/to/outputfile>``

*Set output to json pretty print instead of default json*
``python3 fgss.py --fglist </path/to/fglist> --servicelist </path/to/servicelist> --format json_pretty``
