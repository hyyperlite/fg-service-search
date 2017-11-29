from ftntlib import FortiOSREST
import json
import argparse
import ssl
import sys
import base64
import os


# read command line options
# print ("**argv: ", sys.argv[1:])
# opts, args = getopt.getopt(sys.argv[1:], "i:u:p:v:bhds1:2:")
# print ("**options: ", opts)

### Options Handling
parser = argparse.ArgumentParser()
parser.add_argument('--fortigate', help='IP or hostname of fortigate')
parser.add_argument('--fglist', help='alternative to --fortigate, provide path to file containing list of fortigates and\
                                     vdoms')
parser.add_argument('--fgport', default='443', help='port for fortigate if other than 443')
parser.add_argument('--vdom', default='root', help='vdom to execute against if other than "root"')
parser.add_argument('--login', default='admin', help='login username for fortigate')
parser.add_argument('--pass', default='', help='login password for fortigate')
parser.add_argument('--searchproto', choices=['tcp', 'TCP', 'udp', 'UDP', 'sctp', 'SCTP'], help='for --servicecheck,\
                                                                                           provide a protocol to search\
                                                                                           for (also requires \
                                                                                           --servicecheck and \
                                                                                           --searchport' )
parser.add_argument('--searchport', type=int, choices=range(1,65535), help='for --servicecheck, provide a protocol to \
                                                                            search for (also requires --servicecheck \
                                                                            and --searchprotocol')
parser.add_argument('--servicefile', help='for --servicecheck, provide path to file containing list of proto and port')
parser.add_argument('--servicelist', help='path to file containing a list of services by name to check for in \
                                           policies of the fortigate/vdom')
parser.add_argument('--format', choices=['json', 'tsv', 'csv', 'pretty_json'], default=json, help='output format')
parser.add_argument('--outfile', default='./output.txt', help='path to results file')
args = parser.parse_args()

### Check Options for validity and relationships
if not args.fortigate and not args.fglist:
    parser.error("requires one of --fortigate or --fglist")

if not (args.searchproto and args.searchport):
        if not args.servicefile and not args.servicelist:
                 parser.error("require (--searchproto and --searchport) or --servicefile or --servicelist")
if args.servicefile:
    if not os.access(args.servicefile, os.R_OK):
        parser.error("path/file specified with --servicefile "  + args.servicefile + " is not a readable file")

if args.servicefile:
    if not os.access(args.servicelist, os.R_OK):
        parser.error("path/file specified with --servicelist " + args.servicelist + " is not a readable file")

# set default values
hostname =
username = "fortinetapi"
password = "fortinetapi"
vdom = "root"
verbose = False
serviceCheck = True
policyServiceCheck = True
searchport = 80
searchproto = 'tcp'
serviceMatch = []
policyMatch = {}

# parse args
# for opt, arg in opts:
#     # print ("*arg* " + opt + " : " + arg)
#     if opt in ('-h', '--help'):
#         print("***********************************************************************************")
#         print("Usage: python fgt-ops.py -i <device ip[:port]> -u <username> -p <password>")
#         print("")
#         print("  This script performs various operations against a Fortigate")
#         print("  Device IP, username, and password will be prompted for if left blank")
#         print("  everything is case sensitive")
#         print("")
#         print("  -i: for FG port other than 443, use -i ip:port, ie 192.168.1.99:8443")
#         print("")
#         print("  -p: to enter a password without echoing, leave the -p option out")
#         print("      if the password is blank  <8(   leave off the -p option and hit enter when prompted")
#         print("")
#         print("  -v: for vdom  (default = root)")
#         print("")
#         print("  For the policy:")
#         print("     -1: set from port  (default = port1)")
#         print("     -2: set to port  (default = port2)")
#         print("")
#         print("  -b : verbose outout")
#         print("")
#         print("  -s : search for service utilizations")
#         print("")
#         print("  -d : delete/undo all the changes being made")
#         print("")
#         print("***********************************************************************************")
#         print("examples:  ")
#         print("   python fgt-ops.py -i 192.168.1.99 -u api -p apiapi")
#         print("   python fgt-ops.py -i 192.168.1.99 -u admin -g")
#         print("   python fgt-ops.py -i 192.168.1.99 -u apiUser -p apiPasswd -d")
#         print("***********************************************************************************")
#         sys.exit(2)
#     elif opt == '-i':
#         hostname = arg
#     elif opt == '-b':
#         verbose = True
#     elif opt == '-u':
#         username = arg
#     elif opt == '-p':
#         password = arg
#     elif opt == '-v':
#         vdom = arg
#     elif opt == '-d':
#         undo = True
#     elif opt == '-s':
#         serviceCheck = True
#     elif opt == '-1':
#         port1 = arg
#     elif opt == '-2':
#         port2 = arg

if verbose: print("****** arguments *******")
if verbose: print("host: " + hostname)
if verbose: print("username: " + username)

# ask for missing args
if hostname == "":
    hostname = raw_input('Enter a host IP: ')
if username == "":
    username = raw_input('Enter a user ID: ')
if password == "":
    password = getpass.getpass('Enter Password: ')
if searchproto == "":
    searchproto == raw_input('Enter a protocol to search (tcp/udp/sctp): ')
if searchport == "":
    searchport == raw_input('Enter a tcp or udp port to search for: ')


### Function to identify if a given service object will match for a specified protocol/port
def findService(service, prange, searchport):
    lowport = []
    highport = []

    if service[prange] == '':
        return False

    ### portrange fields in FOS may report in various formats. Differs depending on if just lowport was
    ### specified or low/high ports and also based on if source ports specified or multiple low/high,src/dst
    # ':' denotes delimiter between dport/dport-range and sport/sport-range
    if ':' in service[prange]:
        dports, sports = service[prange].split(':')
    else:
        dports = service[prange]
        sports = ''

    # ' ' deliniates multiple dport/dport-ranges
    if ' ' in dports:
        dports = dports.split()
    else:
        dports = [dports]

    # '-' deliniates lowport and highport if a range is given
    for y in range(len(dports)):
        if '-' in dports[y]:
            low, high = dports[y].split('-')
            lowport.append(str(low))
            highport.append(str(high))
        else:
            lowport = dports
            highport = dports

    # Created a list of low ports and high ports for this object, now analyze each to identify if
    # the protocol/port we are searching for falls in any of the ranges provided.  (note, we do not yet
    # consider source ports)
    for idx in range(len(lowport)):
        if (int(lowport[idx]) <= searchport) and (searchport <= int(highport[idx])):
            #print("MATCH: " + service['name'] + "\t" + service[prange] + "\t" + str(service['protocol-number']))
            return service['name']
        else:
            return False

### Function to find match from list of services provided to services contained in policy
def findPolicyService(policies, services):
    for service in services:
        for policysvc in policies['service']:
            if service == policysvc['name']:
                return True
    return False

try:
    ##### begin

    #print("****** login *******")
    fgt = FortiOSREST()
    if verbose: fgt.debug('on')
    result = fgt.login(hostname, username, password)
    if verbose: print(result)

    ### Check if a given service object will match for a specified protocol/port (call findService)
    if serviceCheck:
        # Query the FG
        response = fgt.get('cmdb', 'firewall.service', 'custom')
        json_response = json.loads(response)

        # Set service port-range type to use
        if searchproto == 'tcp' or searchproto == 'TCP':
            portrange = 'tcp-portrange'
        elif searchproto == 'udp' or searchproto == 'UDP':
            portrange = 'udp-portrange'
        elif searchproto == 'sctp' or searchproto == 'SCTP':
            portrange = 'sctp-portrange'

        # For each service object returned from FG, search for protocol/port match
        for x in json_response['results']:
            result = findService(x, portrange, searchport)
            if result:
                serviceMatch.append(result)

        print('Services Containing Protocol/Port:')
        print(serviceMatch)

    ## Given a list of service objects, check to see if any policies use the service objects
    if policyServiceCheck:
        # Query the FG for defined policies
        response = fgt.get('cmdb', 'firewall', 'policy')
        json_response = json.loads(response)
        #print(json.dumps(json_response['results'], indent=2, sort_keys=True))

        # For each policy returned from FG, compare its service list to the provided service list
        for x in json_response['results']:
            result = findPolicyService(x, serviceMatch)
            if result:
                policyMatch.update(x)

        print('Policies containing service/protocol')
        print(policyMatch)




    fgt.logout()

# on exception, try to log out
except:
    print("****** EXCEPTION *******")
    fgt.logout()
