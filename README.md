# fg_api

A playground of test snippets for FortiGate REST API

## Notice

It is recommended that this code be tested in a lab/staging environment prior to use on production deployments.

## Testing

Tested against FortiOS 5.6.5 and 6.0.2

## Getting Started

git clone https://github.com/hyyperlite/fg-service-search

### Prerequisites

* python3
* libxml2
* libxml-dev
* libxslt
* libxslt-dev
* ftntlib


### Installing

Install Python3 & pip3

```
sudo apt update
sudo apt upgrade
sudo apt install python3 python3-pip
```

Update pip to latest common version

```
sudo pip3 install --upgrade pip
```

Ensure python setuptools package is installed

```
sudo pip3 install setuptools
```

Execute fg_service_search setup, from cloned directory.

```
sudo python3 setup.py install
```

### Examples

Get Help

```
python3 fgss.py -h
```

Single FortiGate/VDOM, single search proto/port via CLI

```
python3 fgss.py --fortigate <ip|hostname> --vdom <vdom> --login <login> --passwd <password> --searchproto <tcp|udp|sctp> --searchport <1-65535>
```

Execute on multiple fortigates/vdoms for multiple protocols/ports by providing files with lists of each. (For examples of required file formats refer to example-files directory)

```
python3 fgss.py --fglist </path/to/fg-vdom/list> --servicelist <path/to/port-proto/list>
```

Output by default will be to CWD/output.txt.  To change output path:

```
python3 fgss.py --fglist </path/to/fg-vdom/list> --servicelist <path/to/port-porto/list --outfile </path/to/output/file>
```

Output to file will by default be in standard json.  To print in more human readable json_pretty:

```
python3 fgss.py --fglist </path/to/fg-vdom/list> --servicelist <path/to/port-porto/list --format json_pretty
```

Output file by default will be in write mode. All data will be overwritten on each execution.  To change to append mode:

```
python3 fgss.py --fglist </path/to/fg-vdom/list> --servicelist <path/to/port-porto/list --outfilemode a
```


## Authors

* **Nick Petersen** - *Initial work* - [hyyperlite](https://github.com/hyyperlite)

See also the list of [contributors](https://github.com/your/project/contributors) who participated in this project.

