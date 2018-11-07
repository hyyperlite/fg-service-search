from ftntlib import FortiOSREST
from datetime import datetime
import json
import argparse
import os
import sys
#
##########################
# Options Handling
##########################
parser = argparse.ArgumentParser()
parser.add_argument('--fortigate', help='IP or hostname of fortigate')
parser.add_argument('--fglist', help='alternative to --fortigate, provide path to file containing list of fortigates '
                        'vdoms, username and passwords')

parser.add_argument('--vdom', default='root', help='vdom to execute against if other than "root"')
parser.add_argument('--login', help='login username for fortigate')
parser.add_argument('--passwd', help='login password for fortigate')
parser.add_argument('--searchproto', choices=['tcp', 'TCP', 'udp', 'UDP', 'sctp', 'SCTP'], help=''
                        'provide a protocol to search for (also requires --searchport')

parser.add_argument('--searchport', type=int, help=''
                        'a protocol to search for (also requires --searchprotocol')

parser.add_argument('--servicelist', help='provide path to file containing list of proto and port')
parser.add_argument('--format', choices=['json', 'json_pretty', 'simple'], default='json', help='output format')
parser.add_argument('--outfile', default='./output.txt', help='path to results file')
parser.add_argument('--outfilemode', default='w', choices=['w', 'a'], help='w=overwrite file, a=append to file')
args = parser.parse_args()

# Instantiate other needed vars, lists and dictionaries
serviceCheck = True
policyCheck = True
vipCheck = True
verbose = False
allowedprotos = [6, 17, 132]
allowedprotosname = ['tcp', 'udp', 'sctp']

# Create lists & dictionaries based on cli input
fortigates = {}      # Dictionary to contain list of fortigates, logins, passwds
portproto = {}   # Dictionary to contain list of protocol and ports to search for
svcsbyname = []    # List to contain named services to search for

# Check Options for validity and relationships
if not args.fortigate and not args.fglist:
    parser.error("requires one of --fortigate or --fglist")
elif args.fortigate:
    if not args.login and args.passwd:
        parser.error("when using --fortigate, must also provide --login and --passwd")

if not (args.searchproto and args.searchport):
        if not args.servicelist:
            parser.error('require (--searchproto and --searchport) or --servicelist')
else:
    if args.searchport not in range(1, 65535):
        parser.error('--searchport must be in range of 1 to 65535')

# Check and Open Files for r/w
# For read-only files check to make sure that they exist before attempting to open them
if args.fglist:
    if not os.access(args.fglist, os.R_OK):
        parser.error('path/file specified with --fglist ' + args.fglist + ' is not a readable file')
    else:
        try:
            fglist = open(args.fglist, 'r')
        except IOError:
            print('Could not read file:', args.fglist)
            sys.exit(1)

if args.servicelist:
    if not os.access(args.servicelist, os.R_OK):
        parser.error('path/file specified with --servicelist ' + args.servicelist + ' is not a readable file')
    else:
        try:
            servicelist = open(args.servicelist, 'r')
        except IOError:
            print('Could not read file:', args.servicelist)
            sys.exit(1)

# Since outfile may not already exist we try to open it and catch exceptions, exiting on exception
if args.outfile:
    try:
        if args.outfilemode == 'a':
            outfile = open(args.outfile, 'a')
        else:
            outfile = open(args.outfile, 'w+')
    except IOError:
        print('Could not create file for writing:', args.outfile)
        sys.exit(1)

# Create the list of fortigates from file, or if no file, from cli arguments
if args.fglist:
    for line in fglist:
        fg, vdom, login, passwd = line.split()
        fortigates[fg + '-' + vdom] = {'host': fg, 'vdom': vdom, 'login': login, 'passwd': passwd}
    fglist.close()
elif args.fortigate:
    fortigates[args.fortigate + '-' + args.vdom] = {'host': args.fortigate,
                                                    'vdom': args.vdom, 'login': args.login, 'passwd': args.passwd}

# Create list of proto/port to search for from file, or if no file specified from cli arguments
if args.servicelist:
    x = 0
    for line in servicelist:
        if not '/' in line:
            continue
        line = line.rstrip()
        protocol, port = line.split('/')
        portproto[x] = {'protocol': protocol.lower(), 'port': port.lower()}
        x += 1
    servicelist.close()
elif args.searchproto and args.searchport:
    portproto[0] = {'protocol': args.searchproto, 'port': args.searchport}


#################################################
# Function definitions
#################################################

# Function to identify if a given service object will match for a specified protocol/port
def find_service(service, searchproto, searchport):
    prange = searchproto + '-portrange'
    lowport = []
    highport = []

    # Match any generic IP (ALL, TCP, UDP, ICMP)
    if service['protocol'] == 'IP':
        if service['protocol-number'] == 0:
            return service['name']
        elif searchproto == 'tcp' and service['protocol-number'] == 6:
            return service['name']
        elif searchproto == 'udp' and service['protocol-number'] == 17:
            return service['name']
        elif searchproto == 'icmp' and service['protocol-number'] == 1:
            return service['name']
        else:
            pass

    # Find IP protocol specified matchesc
    if searchproto == 'ip':
        if service['protocol'] == 'IP' and searchport == service['protocol-number']:
            return service['name']
        else:
            return False

    # Find ICMP specified matches (will match protocol and type, but not icmp code)
    if searchproto == 'icmp':
        if service['protocol'] == 'ICMP' and searchport == str(service['icmptype']):
                return service['name']
        else:
            return False


    # Check if object is associated to protocol being searched for
    if service[prange] == '':
        return False

    # Portrange fields in FOS may report in various formats. Differs depending on if just lowport was
    # specified or low/high ports and also based on if source ports specified or multiple low/high,src/dst
    # ':' denotes delimiter between dport/dport-range and sport/sport-range
    if ':' in service[prange]:
        dports, sports = service[prange].split(':')
    else:
        dports = service[prange]

    # ' ' delineates multiple dport/dport-ranges
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
        if int(service['protocol-number']) not in allowedprotos:
            return False

        if (int(lowport[idx]) <= int(searchport)) and (int(searchport) <= int(highport[idx])):
            return service['name']
        else:
            return False


# Function to identify if a given vip object will match for a specified protocol/port
def find_vip(vip, searchproto, searchport):

    # Check if portforwarding is enabled for this vip
    if vip['portforward'] == 'disable':
        return False

    # Check if vip proto is one of supported by this script
    if vip['protocol'] not in allowedprotosname:
        return False

    # Make sure protocol matches search protocol
    if searchproto != vip['protocol']:
        return False

    # Find port range lower/upper
    dports = vip['mappedport']

    # '-' delineates lowport and highport if a range is given
    if '-' in dports:
        lowport, highport = dports.split('-')
        #lowport = low
        #highport = high
    else:
        lowport = dports
        highport = dports

    # Created a list of low ports and high ports for this object, now analyze each to identify if
    # the protocol/port we are searching for falls in any of the ranges provided.  (note, we do not yet
    # consider source ports)
    if (int(lowport) <= int(searchport)) and (int(searchport) <= int(highport)):
        return vip['name']
    else:
        return False


# Function to find match from list of services provided to services contained in policy
def find_policy_match(policies, searchitem, objtype):
    policymatch = []

    for policy in policies:
        # For services, we search policies for a match in the "service" field
        if objtype == 'fgservice' or objtype == 'fgservicegrp':
            for fgobject in policy['service']:
                if searchitem == fgobject['name']:
                    policymatch.append(policy['policyid'])
        # For VIPs were search policies for a match in the "dstaddr" field
        elif objtype == 'fgvip' or objtype == 'fgvipgrp':
            for fgobject in policy['dstaddr']:
                if searchitem == fgobject['name']:
                    policymatch.append(policy['policyid'])
        else:
            continue

    # If results were found, they were added to the policymatch list, return the list
    if len(policymatch) > 0:
        return policymatch
    else:
        return False

# Simplified output formatting for NOC/SOC employee use
def simpleOutput(serviceMatch, outfile):
    all = {'policymatch': [], 'groups': []}
    fortigate = serviceMatch['fortigate']
    vdom = serviceMatch['vdom']
    outStr = ''

    outfile.write('-'*100)
    outfile.write('\n')
    outfile.write('{}/{}'.format(fortigate,vdom))
    outfile.write('\n')
    outfile.write('-'*100)
    outfile.write('\n\n')


    for protoport in sorted(serviceMatch['objmatch']):
        for fgobj_key, fgobj_val in enumerate(serviceMatch['objmatch'][protoport]):
            for key, val in serviceMatch['objmatch'][protoport][fgobj_key].items():
                groups = []
                type = serviceMatch['objmatch'][protoport][fgobj_key][key]['type']
                policyMatch = serviceMatch['objmatch'][protoport][fgobj_key][key]['policymatch']

                if 'groups' in serviceMatch['objmatch'][protoport][fgobj_key][key]:
                    groups = serviceMatch['objmatch'][protoport][fgobj_key][key]['groups']

                # Special Handling for "ALL" object
                if key == 'ALL':
                    if len(all['policymatch']) > 0:
                        all['policymatch'] += policyMatch
                        all['groups'] += groups
                    else:
                        all['policymatch'] = serviceMatch['objmatch'][protoport][fgobj_key][key]['policymatch']
                        all['groups'] = serviceMatch['objmatch'][protoport][fgobj_key][key]['groups']
                else:
                    if len(policyMatch) > 0:
                        outStr += 'Fortigate/VDOM: {}/{}\n'.format(fortigate, vdom)
                        outStr += 'Protocol/Port Match: {}\n'.format(protoport)
                        outStr += 'Object Name: {}\n'.format(key)
                        outStr += 'Object Type: {}\n'.format(type)
                        if len(groups) > 0:
                            outStr += 'Member of: {}\n'.format(groups)
                        outStr += 'Used in Policies: {}\n'.format(sorted(policyMatch))
                        outStr += '-'*36
                        outStr += '\n\n'

    if len(all['policymatch']) > 0:
        all['policymatch'] = set(all['policymatch'])

        outfile.write('*'*36)
        outfile.write('\n')
        outfile.write('Fortigate/VDOM: {}/{}\n'.format(fortigate, vdom))
        outfile.write('')
        outfile.write('\"ALL\" Object Summary')
        outfile.write('\n')
        outfile.write('Used in Policies: {}'.format(sorted(all['policymatch'])))
        if len(all['groups']) > 0:
            all['groups'] = set(all['groups'])
            outfile.write('\nMember of: {}'.format(all['groups']))
        outfile.write('\n')
        outfile.write('*'*36)
        outfile.write('\n\n')

    outfile.write(outStr)

##################################################
#### Main Processing
#################################################
try:
    # Iterate through each FortiGate/VDOM combination loaded from CLI or from fortigates file list
    for fg in fortigates:
        print("Processing: " + fg)
        serviceMatch = {'objmatch': {}, 'date-time': '', 'fortigate': '', 'vdom': ''} # Dict to store all matching objs
        svc_count = 0
        fgt = FortiOSREST()
        result = fgt.login(fortigates[fg]['host'], fortigates[fg]['login'], fortigates[fg]['passwd'])

        ############################################
        # Service Matching
        ###########################################
        if serviceCheck:
            # Get list of all custom services defined on fortigate
            response = fgt.get('cmdb', 'firewall.service', 'custom', parameters={'vdom': fortigates[fg]['vdom']})
            json_response = json.loads(response.decode())

            # For each service object returned from FG, search for protocol/port match
            for fgsvc in json_response['results']:
                for item in portproto:
                    proto = portproto[item]['protocol']
                    port = portproto[item]['port']
                    protoport = proto + "/" + str(port)

                    # if fgsvc['name'] == 'PING':
                    #     print(fgsvc)
                    #     sys.exit()

                    result = find_service(fgsvc, proto, port)

                    if result:
                        if protoport not in serviceMatch['objmatch'].keys():
                            serviceMatch['objmatch'][protoport] = []

                        serviceMatch['objmatch'][protoport].append({result: {'type': 'fgservice', 'policymatch': [],
                                                                  'groups': []}})

                        svc_count += 1

            #######################################
            # Service Group Matching
            #######################################
            # Also need to check if any of the services that were matched are in an address group
            # If so then we'll store those address groups, and later check to see if those are used
            # in a policy
            svcgrp_count = 0
            response = fgt.get('cmdb', 'firewall.service', 'group', parameters={'vdom': fortigates[fg]['vdom']})
            json_response = json.loads(response.decode())

            for group in json_response['results']:
                for member in group['member']:
                    for protoport in serviceMatch['objmatch']:
                        for service_key, service_val in enumerate(serviceMatch['objmatch'][protoport]):
                            for svc_key, svc_val in service_val.items():
                                if svc_val['type'] == 'fgservice':
                                    if svc_key == member['name']:

                                        # add new fgservice group entry to serviceMatch
                                        serviceMatch['objmatch'][protoport].append({group['name']: {'type':
                                                                                    'fgservicegrp', 'policymatch': []}})

                                        # update existing service object with related servicegroup map
                                        serviceMatch['objmatch'][protoport][service_key][svc_key]['groups']\
                                            .append(group['name'])

                                        svcgrp_count += 1

        ##########################################
        # VIP Matching
        ##########################################
        if vipCheck:
            vip_count = 0
            # Get list of all vips defined on fortigate
            response = fgt.get('cmdb', 'firewall', 'vip', parameters={'vdom': fortigates[fg]['vdom']})
            json_response = json.loads(response.decode())

            # For each vip object returned from FG, search for port match
            for fgvip in json_response['results']:
                for item in portproto:
                    proto = portproto[item]['protocol']
                    port = portproto[item]['port']
                    protoport = proto + "/" + str(port)

                    result = find_vip(fgvip, proto, port)

                    if result:
                        if protoport not in serviceMatch['objmatch'].keys():
                            serviceMatch['objmatch'][protoport] = []

                        serviceMatch['objmatch'][protoport].append({result: {'type': 'fgvip', 'policymatch': [],
                                                                             'groups': []}})

                        vip_count += 1


            # #######################################
            # # VIP Group Matching
            # #######################################
            # Also need to check if any of the vips that were matched are in an vip group
            # If so then we'll store those vip groups, and later check to see if those are used
            # in a policy
            vipgrp_count = 0
            response = fgt.get('cmdb', 'firewall', 'vipgrp', parameters={'vdom': fortigates[fg]['vdom']})
            json_response = json.loads(response.decode())

            for group in json_response['results']:
                for member in group['member']:
                    for protoport in serviceMatch['objmatch']:
                        for service_key, service_val in enumerate(serviceMatch['objmatch'][protoport]):
                            for svc_key, svc_val in service_val.items():
                                if svc_val['type'] == 'fgvip':
                                    if svc_key == member['name']:
                                        # add new fgservice group entry to serviceMatch
                                        serviceMatch['objmatch'][protoport].append({group['name']: {'type': 'fgvipgrp',
                                                                                                'policymatch': []}})

                                        # update existing service object with related servicegroup map
                                        serviceMatch['objmatch'][protoport][service_key][svc_key]\
                                        ['groups'].append(group['name'])

                                        vipgrp_count += 1


        ##########################################
        # Policy Matching
        ##########################################
        # Given a list of service objects, check to see if any policies use the service objects
        # # If there is a match, we will add the policyid of the matching rule to the services object data
        if policyCheck:
            pol_count = 0
            # Query the FG for defined policies
            response = fgt.get('cmdb', 'firewall', 'policy', parameters={'vdom': fortigates[fg]['vdom']})
            json_response = json.loads(response.decode())

            for protoport in serviceMatch['objmatch']:
                for service_key, service_value in enumerate(serviceMatch['objmatch'][protoport]):
                    for svc_key, svc_value in service_value.items():
                        result = find_policy_match(json_response['results'], svc_key, svc_value['type'])
                        if result:
                            # serviceMatch['objmatch'][protoport][service_key][svc_key]['policymatch'].append(result)
                            serviceMatch['objmatch'][protoport][service_key][svc_key]['policymatch'] += result

                            pol_count += 1

        # Add additional detail to the dictionary
        serviceMatch['fortigate'] = fortigates[fg]['host']
        serviceMatch['vdom'] = fortigates[fg]['vdom']
        serviceMatch['date-time'] = str(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

        ########################################
        # Results Output
        ########################################
        if args.format == 'json_pretty':
            # print(json.dumps(serviceMatch, indent=2, sort_keys=True))
            outfile.write(json.dumps(serviceMatch, indent=2, sort_keys=True))
        elif args.format == 'simple':
            simpleOutput(serviceMatch, outfile)
        else:
            # print(json.dumps(serviceMatch))
            outfile.write(json.dumps(serviceMatch))

        # print('\t Services Match: {}, Service Groups Match: {}'.format(svc_count, svcgrp_count))
        # print('\t VIP Match: {}, VIP Groups Match: {}'.format(vip_count, vipgrp_count))
        # print('\t Policy Match: {}'.format(vip_count, vipgrp_count))
        # print()

        outfile.flush()
        fgt.logout()

    print('*'*40)
    print('Completed, results written to: ' + os.path.abspath(args.outfile))
    # print(json.dumps(serviceMatch, indent=2, sort_keys=True))
    outfile.close()

# If exception, attempt close fg connection and print exception msg
except Exception as e:
    print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
    try:
        fgt.logout()
    except:
        pass