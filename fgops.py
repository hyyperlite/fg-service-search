from ftntlib import FortiOSREST
import json
import argparse
import ssl
import sys
import base64
import os

### Options Handling
parser = argparse.ArgumentParser()
parser.add_argument('--fortigate', help='IP or hostname of fortigate')
parser.add_argument('--fglist', help='alternative to --fortigate, provide path to file containing list of fortigates '
                                     'and vdoms')

parser.add_argument('--fgport', default='443', help='port for fortigate if other than 443')
parser.add_argument('--vdom', default='root', help='vdom to execute against if other than "root"')
parser.add_argument('--login', default='admin', help='login username for fortigate')
parser.add_argument('--passwd', default='admin', help='login password for fortigate')
parser.add_argument('--searchproto', choices=['tcp', 'TCP', 'udp', 'UDP', 'sctp', 'SCTP'], help='for --servicecheck, '
                                    'provide a protocol to search for (also requires --servicecheck and --searchport')

parser.add_argument('--searchport', type=int, choices=range(1,65535), help='for --servicecheck, provide a protocol to '
                                                        'search for (also requires --servicecheck and --searchprotocol')

parser.add_argument('--servicefile', help='for --servicecheck, provide path to file containing list of proto and port')
parser.add_argument('--servicelist', help='path to file containing a list of services by name to check for in '
                                          'policies of the fortigate/vdom')

parser.add_argument('--format', choices=['json', 'tsv', 'csv', 'pretty_json'], default='json', help='output format')
parser.add_argument('--outfile', default='./output.txt', help='path to results file')
args = parser.parse_args()

### Check Options for validity and relationships
if not args.fortigate and not args.fglist:
    parser.error("requires one of --fortigate or --fglist")

if not (args.searchproto and args.searchport):
        if not args.servicefile and not args.servicelist:
                 parser.error('require (--searchproto and --searchport) or --servicefile or --servicelist')

if args.servicefile and args.servicelist:
    parser.error('may only specify one of --servicefile or --servicelist not both')

### Check and Open Files for r/w
if args.fglist:
    if not os.access(args.fglist, os.R_OK):
        parser.error('path/file specified with --fglist " + args.fglist + " is not a readable file')
    else:
        try:
            fglist = open(args.fglist, 'r')
        except IOError:
            print('Could not read file:', args.fglist)
            sys.exit()

if args.servicefile:
    if not os.access(args.servicefile, os.R_OK):
        parser.error('path/file specified with --servicefile " + args.servicefile + " is not a readable file')
    else:
        try:
            servicefile = open(args.servicefile, 'r')
        except IOError:
            print('Could not read file:', args.servicefile)
            sys.exit()

if args.servicelist:
    if not os.access(args.servicelist, os.R_OK):
        parser.error('path/file specified with --servicelist " + args.servicelist + " is not a readable file')
    else:
        try:
            servicelist = open(args.servicelist, 'r')
        except IOError:
            print('Could not read file:', args.servicelist)
            sys.exit()

if args.outfile:
    try:
        outfile = open(args.outfile, 'w+')
    except IOError:
        print('Could not create file for writing:', args.outfile)
        sys.exit()

##################################################
#### Main Processing
#################################################
## Create lists / dicts based on input
fortigates = {}      # Dictionary to contain list of fortigates, logins, passwds
portproto = {}   # Dictionary to contain list of protocol and ports to search for
svcsbyname = []    # List to contain named services to search for

# Create the list of fortigates from file, or if no file, from cli arguments
if args.fglist:
    for line in fglist:
        fg,login,passwd = line.split()
        fortigates[fg] = {'login': login, 'passwd': passwd}
    fglist.close()
elif args.fortigate:
    fortigates[args.fortigate] = {'login': args.login, 'passwd': args.passwd}

# Create list of proto/port to seach for from file, or if no file specified from cli arguments
if args.servicefile:
    x = 0
    for line in servicefile:
        protocol, port = line.split('/')
        portproto[x] = {'protocol': protocol.lower(), 'port': port.lower()}
        x = x + 1
    servicefile.close()
elif args.searchproto and args.searchport:
    portproto[0] = {'protocol': args.searchproto, 'port': args.searchport}

# Create list of services to search for by name if --servicelist
if args.servicelist:
    for line in servicelist:
        svcsbyname.append(line.rstrip())
    servicelist.close()

### Instantiate needed vars, lists and dicts
serviceMatch = {}
policyMatch = {}
serviceCheck = True
policyServiceCheck = True
#verbose = True
allowedprotos = [6, 17, 132]


### Function to identify if a given service object will match for a specified protocol/port
def findService(service, searchproto, searchport):
    prange = searchproto + '-portrange'
    lowport = []
    highport = []

    # Check if object is associated to protocol being searched for
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
        # print(str(searchproto) + "/" + str(searchport) + " Search For: " + service['name'] + "\t" + service[
        #     prange] + "\t" + str(service['protocol-number']))
        if int(service['protocol-number']) not in allowedprotos:
            return False
        if (int(lowport[idx]) <= searchport) and (searchport <= int(highport[idx])):
            print(str(searchproto) + "/" + str(searchport) + " MATCH " + service['name'] + "\t" + service[prange] + "\t" + str(service['protocol-number']))
            return service['name']
        else:
            return False

### Function to find match from list of services provided to services contained in policy
def findPolicyService(policies, service):
    policymatch = []

    for policy in policies:
        for fgservice in policy['service']:
            if service == fgservice['name']:
                policymatch.append(policy['policyid'])

    if len(policymatch) > 0:
        return policymatch
    else:
        return False


try:
    for fg in fortigates:
        serviceMatch = {}
        print('fg: ' + str(fg))
        fgt = FortiOSREST()
        #if verbose: fgt.debug('on')
        result = fgt.login(fg, fortigates[fg]['login'], fortigates[fg]['passwd'])

        if serviceCheck:
            response = fgt.get('cmdb', 'firewall.service', 'custom')
            json_response = json.loads(response)

            # For each service object returned from FG, search for protocol/port match
            for fgsvc in json_response['results']:
                for item in portproto:
                    lproto = portproto[item]['protocol']
                    lport = portproto[item]['port']
                    lprotoport = lproto + "/" + str(lport)
                    result = findService(fgsvc, lproto, lport)
                    if result:
                        if not lprotoport in serviceMatch.keys():
                            serviceMatch[lprotoport] = []

                        serviceMatch[lprotoport].append({result : {'type': 'fgservice', 'policymatch': []}})

        print(serviceMatch)


        # Given a list of service objects, check to see if any policies use the service objects
        # If there is a match, we will add the policyid of the matching rule to the services object data
        if policyServiceCheck:
            # Query the FG for defined policies
            response = fgt.get('cmdb', 'firewall', 'policy')
            json_response = json.loads(response)
            # print(json.dumps(json_response['results'], indent=2, sort_keys=True))

            for protoport in serviceMatch:
                for service_key, service_value in enumerate(serviceMatch[protoport]):
                    for svc_key, svc_value in service_value.items():
                        if svc_value['type'] == 'fgservice':
                            result = findPolicyService(json_response['results'], svc_key)
                            if result:
                                serviceMatch[protoport][service_key][svc_key]['policymatch'].append(result)


            print('*****************************')
            print('*****************************')
            # print(json.dumps(serviceMatch, indent=2, sort_keys=True))
            print(serviceMatch)


        fgt.logout()
# on exception, try to log out
except:
    print("****** EXCEPTION *******")
    fgt.logout()
