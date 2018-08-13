# gramfuzz is py2 only :(

import gramfuzz
import os
import yaml
import sysstate
import time
import ipaddress
import itertools
import random

def parse_addr(addr_str):
    if ':' in addr_str:
        desired_addr = ipaddress.IPv6Network(unicode(addr_str), strict=False)
    else:
        desired_addr = ipaddress.IPv4Network(unicode(addr_str), strict=False)
    return desired_addr

# manually shadow stupid networkmanager file!
with open('/etc/NetworkManager/conf.d/10-globally-managed-devices.conf', 'w') as f:
    f.write('\n')

fuzzer = gramfuzz.GramFuzzer()
fuzzer.load_grammar("yaml_grammar.py")
yaml_dat = fuzzer.gen(cat="yamlfile", num=1)[0]
parsed = yaml.load(yaml_dat)
described_ifs = parsed['network']['ethernets'].keys()
#print(described_ifs)

# we need to query routing tables so keep track of the ones we use
tables = []

# NM will refuse to apply the configuration if the routes are invalid
# (e.g. unreachable)
# So go through and mangle them to be OK
# we also do it for networkd so as not to have them silently discarded
for iface_name in parsed['network']['ethernets']:
    iface = parsed['network']['ethernets'][iface_name]

    addresses4 = []
    addresses6 = []
    for a in iface['addresses']:
        if ':' in a:
            addresses6 += [ipaddress.IPv6Network(unicode(a), strict=False)]
        else:
            addr = ipaddress.IPv4Network(unicode(a), strict=False)
            # drop multicast
            if addr.subnet_of(ipaddress.IPv4Network(u'224.0.0.0/4')):
                iface['addresses'].remove(a)
            else:
                addresses4 += [addr]

    if addresses4 == [] and addresses6 == []:
        # ergh, no ipv6 and all our ipv4 were multicast!
        iface['addresses'] = ['1.2.3.4/8']
        addresses4 = [ipaddress.IPv4Network(u'1.0.0.0/8')]

    if 'gateway4' in iface:
        gw = ipaddress.IPv4Network(unicode(iface['gateway4']+'/32'))
        is_ok = False
        for a in addresses4:
            if gw.subnet_of(a):
                is_ok = True
                break
        if not is_ok:
            del iface['gateway4']

    if 'gateway6' in iface:
        gw = ipaddress.IPv6Network(unicode(iface['gateway6']+'/128'))
        is_ok = False
        for a in addresses6:
            if gw.subnet_of(a):
                is_ok = True
                break
        if not is_ok:
            del iface['gateway6']

    if 'routes' in iface:
        new_routes = []
        for r in iface['routes']:
            # NM cannot represent on-link or type - bug 3 :(
            if 'on-link' in r and iface['renderer'] == 'NetworkManager':
                del r['on-link']

            # it looks like this will be pretty well constantly broken
            # thanks to bug 5
            if 'type' in r: #and iface['renderer'] == 'NetworkManager':
                del r['type']

            # bug 6 : from doesn't work for networkd - prints From= not Source=
            # (always also drop for nm as result of bug 3)
            if 'from' in r: #and iface['renderer'] == 'NetworkManager':
                del r['from']

            is_ok = False
            if not ':' in r['via']:
                via_addr = ipaddress.IPv4Network(unicode(r['via']+'/32'))
                for a in addresses4:
                    if via_addr.subnet_of(a):
                        is_ok = True
                        break
                if not is_ok and addresses4 and not 'on-link' in r:
                    try:
                        via_addr = random.choice(list(itertools.islice(addresses4[-1].hosts(), 1000)))
                        r['via'] = str(via_addr.compressed)
                        #print("new via for r", r)
                        is_ok = True
                    except IndexError:  # empty .hosts()
                        pass
                elif not is_ok and 'on-link' in r:
                    # hoping my understanding of on-link is correct here and you
                    # cannot have an on-link gw be normally accessible
                    is_ok = True
                elif is_ok and 'on-link' in r:
                    is_ok = False

                # finally, just verify that there exists an address of this type!
                if addresses4 == []:
                    is_ok = False
            else:
                via_addr = ipaddress.IPv6Network(unicode(r['via']+'/128'))
                for a in addresses6:
                    if via_addr.subnet_of(a):
                        is_ok = True
                        break
                if not is_ok and addresses6 and not 'on-link' in r:
                    via_addr = random.choice(list(itertools.islice(addresses6[-1].hosts(), 1000)))
                    r['via'] = str(via_addr.compressed)
                    #print("new via for r", r)
                    is_ok = True
                elif not is_ok and 'on-link' in r:
                    # hoping my understanding of on-link is correct here and you
                    # cannot have an on-link gw be normally accessible
                    is_ok = True
                elif is_ok and 'on-link' in r:
                    is_ok = False

                if addresses6 == []:
                    is_ok = False

            # NM cannot understand 0.0.0.0/0, makes it 0.0.0.0/24 (bug 4)
            # so i guess just drop these routes
            if iface['renderer'] == 'NetworkManager' and r['to'] == '0.0.0.0/0':
                is_ok = False

            # normalise 'to', otherise we get Error: Invalid prefix for given prefix length.
            r['to'] = str(parse_addr(r['to']).compressed)

            # scope link and scope host can't have a gateway; drop it
            if 'scope' in r and (r['scope'] == 'link' or r['scope'] == 'host'):
                if 'via' in r:
                    del r['via']
                # bug 8: this makes them un-renderable.
                is_ok = False

            if not is_ok:
                #print("Dropping a route for ", iface_name, r, addresses4, addresses6)
                pass
            else:
                #print('keeping', r)
                new_routes += [r]
                # keep track of tables we use
                if 'table' in r:
                    tables += [r['table']]

            #print(new_routes)
            iface['routes'] = new_routes

    # drop NSs if there does not exist an address of that family
    if 'nameservers' in iface:
        new_nsaddrs = []
        for nsaddr in iface['nameservers']['addresses']:
            if ':' in nsaddr:
                if not len(addresses6) == 0:
                    new_nsaddrs += [nsaddr]
                    iface['nameservers']['addresses'].remove(nsaddr)
            else:
                if not len(addresses4) == 0:
                    new_nsaddrs += [nsaddr]
        iface['nameservers']['addresses'] = new_nsaddrs

with open('/etc/netplan/fuzz.yaml', 'w') as f:
    f.write(yaml.dump(parsed))
            
if os.system("netplan apply") != 0:
    exit(1)
    
any_down = True
sleep = 0
while any_down:
    state = sysstate.get_status(tables)
    any_down = False
    for intf in described_ifs:
        iface = state[intf]
        if iface['state'] != 'UP':
            print('waiting for UP on', intf)
            any_down = True
            break
        if not 'addresses' in iface:
            print('waiting for addresses on', intf)
            #print(iface)
            any_down = True
            break
        for addr in parsed['network']['ethernets'][intf]['addresses']:
            found_addr = False
            # canonicalise to deal with ipv6 addresses (:09: vs :9:, ::)
            if ':' in addr:
                desired_addr = ipaddress.IPv6Network(unicode(addr), strict=False)
            else:
                desired_addr = ipaddress.IPv4Network(unicode(addr), strict=False)

            for ifaddr in iface['addresses']:
                if ':' in ifaddr['address']:
                    got_addr = ipaddress.IPv6Network(unicode(ifaddr['address']), strict=False)
                else:
                    got_addr = ipaddress.IPv4Network(unicode(ifaddr['address']), strict=False)
                if desired_addr == got_addr:
                    found_addr = True
                    break
            if not found_addr:
                print("Missing addr", addr, "on", intf)
                any_down = True
                break

        # routes
        if 'routes' in parsed['network']['ethernets'][intf] and parsed['network']['ethernets'][intf]['routes']:
            #print(intf, iface, parsed['network']['ethernets'][intf], 'routes' in iface)
            if not 'routes' in iface:
                any_down = True
                print("Waiting for routes on", intf)
                break
            
            for desired_route in parsed['network']['ethernets'][intf]['routes']:
                #print(desired_route)
                found_route = False
                desired_to = parse_addr(desired_route['to'])
                for iface_route in iface['routes']:
                    iface_to = parse_addr(iface_route['to'])
                    if desired_to == iface_to:
                        found_route = True
                        break
                if not found_route:
                    any_down = True
                    print("missing route", desired_route, "on", intf, " - ", iface['routes'])


    if any_down:
        time.sleep(1)
        sleep += 1
        if sleep == 3:
            print("kicking netplan apply")
            os.system("netplan apply")
        if sleep == 12:
            print("giving up")
            exit(1)
print("success")        
    
# clean up
ifs = ["ens" + str(n) for n in range(7, 13)]# + ["wlan0", "wlan1"]
for intf in ifs:
    os.system("ip address flush dev " + intf)
    os.system("ip link set dev %s down" % intf)

# once we fix bug 5 we will need to take more care to flush routes
