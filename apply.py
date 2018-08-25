#!/usr/bin/env python2
# gramfuzz is py2 only :(

import gramfuzz
import os
import yaml
import sysstate
import time
import ipaddress
import itertools
import random


TEST_GENERATE = True


def parse_network(addr_str):
    if ':' in addr_str:
        desired_addr = ipaddress.IPv6Network(unicode(addr_str), strict=False)
    else:
        desired_addr = ipaddress.IPv4Network(unicode(addr_str), strict=False)
    return desired_addr


def parse_address(addr_str):
    addr_str = addr_str.split('/')[0]
    if ':' in addr_str:
        desired_addr = ipaddress.IPv6Address(unicode(addr_str))
    else:
        desired_addr = ipaddress.IPv4Address(unicode(addr_str))
    return desired_addr


def is_reserved_net(addr):
    """Return True if an network is reserved in some 
    way, and False if it's a regular address.
    
    Currently checks for:
     - IPv4 multicast addresses (224.0.0.0/4)
     - IPv4 localhost (127.0.0.0/8)
     - IPv6 localhost (::1/128)
     - IPv6 multicast (ff00::/8)"""

    if isinstance(addr, ipaddress.IPv4Network):
        return (addr.subnet_of(ipaddress.IPv4Network(u'127.0.0.0/8')) or
                addr.subnet_of(ipaddress.IPv4Network(u'224.0.0.0/4')))
    elif isinstance(addr, ipaddress.IPv6Network):
        return (addr == ipaddress.IPv6Network(u'::1/128') or
                addr.subnet_of(ipaddress.IPv6Network(u'ff00::/8')))
    elif isinstance(addr, str) or isinstance(addr, unicode):
        return is_reserved_net(parse_network(addr))


def is_reserved_addr(addr):
    """Return True if an network is reserved in some
    way, and False if it's a regular address.

    Currently checks for:
     - IPv4 multicast addresses (224.0.0.0/4)
     - IPv4 localhost (127.0.0.0/8)
     - IPv6 localhost (::1/128)
     - IPv6 multicast (ff00::/8)"""

    if isinstance(addr, ipaddress.IPv4Address):
        return (addr in (ipaddress.IPv4Network(u'127.0.0.0/8')) or
                addr in (ipaddress.IPv4Network(u'224.0.0.0/4')))
    elif isinstance(addr, ipaddress.IPv6Address):
        return (addr == ipaddress.IPv6Address(u'::1/128') or
                addr in (ipaddress.IPv6Network(u'ff00::/8')))
    elif isinstance(addr, str) or isinstance(addr, unicode):
        return is_reserved_addr(parse_address(addr))


# manually shadow stupid networkmanager file!
with open('/etc/NetworkManager/conf.d/10-globally-managed-devices.conf', 'w') as f:
    f.write('\n')

fuzzer = gramfuzz.GramFuzzer()
fuzzer.load_grammar("yaml_grammar.py")
yaml_dat = fuzzer.gen(cat="yamlfile", num=1)[0]

# in theory, at this point, the YAML should survive 'netplan generate'.
# now we expect netplan generate to make the checks around e.g. the
# things NM can't render (e.g. bug 3, bug 4), so those sorts of things
# should really be sorted out and the grammar level.

if TEST_GENERATE:
    with open('/etc/netplan/fuzz.yaml', 'w') as f:
        f.write(yaml_dat)

    if os.system("netplan generate") != 0:
        exit(1)

parsed = yaml.load(yaml_dat)
described_ifs = parsed['network']['ethernets'].keys()
# print(described_ifs)

# we need to query routing tables so keep track of the ones we use
tables = []


def mangle_route(r, addresses4, addresses6, iface):
    """Make a route semantically meaningful.
    There's quite a lot that can go wrong here.
    Return None or a fixed up route.
    Amend the global list of tables if returning a valid route"""

    global tables

    # generic tweaks across address family

    # don't permit the destination to be part of the multicast group
    to_net = parse_network(r['to'])
    if is_reserved_net(to_net):
        return None
    # now normalise, otherwise we get Error: Invalid prefix for given prefix length.
    r['to'] = str(to_net.compressed)

    # scope link and scope host can't have a gateway; drop it
    if 'scope' in r and (r['scope'] == 'link' or r['scope'] == 'host'):
        if 'via' in r:
            del r['via']
        # bug 8: this makes them un-renderable.
        return None

    # likewise non-unicast routes cannot have a gateway
    if 'type' in r and 'via' in r:
        del r['via']

    if 'from' in r:
        # cannot have this with type or scope
        # and on-link just seems fraught (TODO)
        if 'type' in r or 'scope' in r or 'on-link' in r:
            del r['from']

    # address-family specific
    route_is_ok = False
    if 'via' in r and ':' not in r['via']:
        # IPv4

        # Firstly verify that there exists an address of this type
        if addresses4 == []:
            return None

        via_addr = ipaddress.IPv4Address(unicode(r['via']))
        for a in addresses4:
            if via_addr in a[1]:
                route_is_ok = True
                break
        if not route_is_ok and addresses4 and not 'on-link' in r:
            try:
                via_addr = random.choice(list(itertools.islice(addresses4[-1][1].hosts(), 1000)))
                r['via'] = str(via_addr.compressed)
                # print("new via for r", r)
                route_is_ok = True
            except IndexError:  # empty .hosts()
                return None
        elif not route_is_ok and 'on-link' in r:
            # hoping my understanding of on-link is correct here and you
            # cannot have an on-link gw be normally accessible
            if not is_reserved_addr(via_addr):
                print(via_addr.compressed)
                route_is_ok = True
        elif route_is_ok and 'on-link' in r:
            return None

        if not route_is_ok:
            return None

        # now we have a valid gw. validate from if supplied
        # assume we just throw whatever has been generated right out
        # we currently know that on-link is not set now (but see TODO above)
        if 'from' in r:
            # identify which address corresponds to the gw's subnet and pick that
            for a in addresses4:
                if via_addr in a[1]:
                    r['from'] = str(a[0].compressed)
                    break

    elif 'via' in r:
        if addresses6 == []:
            return None

        # onlink seems very complex in IPv6 so just disable it for now
        # TODO: refer linux: tools/testing/selftests/net/fib-onlink-tests.sh
        if 'on-link' in r:
            del r['on-link']

        via_addr = ipaddress.IPv6Address(unicode(r['via']))
        for a in addresses6:
            if via_addr in a[1]:
                route_is_ok = True
                break
        if not route_is_ok:
            via_addr = random.choice(list(itertools.islice(addresses6[-1][1].hosts(), 1000)))
            r['via'] = str(via_addr.compressed)
            # print("new via for r", r)
            route_is_ok = True

        if not route_is_ok:
            return None

        if 'from' in r:
            # looks like this doesn't work in with current systemd: #5882
            del r['from']

    else:
        route_is_ok = True

    assert route_is_ok

    # keep track of tables we use
    if 'table' in r:
        tables += [r['table']]

    return r


# make the configuration semantically meaningful -
# things like not having things in the multicast or
# loopback address range, having non-on-link gws in the
# right subnets, etc.
for iface_name in parsed['network']['ethernets']:
    iface = parsed['network']['ethernets'][iface_name]

    addresses4 = []
    addresses6 = []
    for a in iface['addresses']:
        addr = parse_network(a)
        if is_reserved_net(addr):
            iface['addresses'].remove(a)
        else:
            if ':' in a:
                addresses6 += [(parse_address(a), addr)]
            else:
                addresses4 += [(parse_address(a), addr)]

    if addresses4 == [] and addresses6 == []:
        # ergh, no non-reserved addresses
        iface['addresses'] = ['1.2.3.4/8']
        addresses4 = [(ipaddress.IPv4Address(u'1.2.3.4'), ipaddress.IPv4Network(u'1.0.0.0/8'))]

    if 'gateway4' in iface:
        gw = ipaddress.IPv4Address(unicode(iface['gateway4']))
        is_ok = False
        for a in addresses4:
            if gw in a[1]:
                is_ok = True
                break
        if not is_ok:
            del iface['gateway4']

    if 'gateway6' in iface:
        gw = ipaddress.IPv6Address(unicode(iface['gateway6']))
        is_ok = False
        for a in addresses6:
            if gw in a[1]:
                is_ok = True
                break
        if not is_ok:
            del iface['gateway6']

    if 'routes' in iface:
        new_routes = []
        for r in iface['routes']:
            new_r = mangle_route(r, addresses4, addresses6, iface)
            if new_r:
                new_routes.append(new_r)

        #print(new_routes)
        iface['routes'] = new_routes

    # drop NSs if there does not exist an address of that family
    if 'nameservers' in iface and 'addresses' in iface['nameservers']:
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
            desired_addr = parse_network(addr)

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
                # this assumes that if to matches, we're good, which is not completely
                # accurate but a good first pass
                # we should also match on all other properties as well.
                desired_to = parse_network(desired_route['to'])
                if 'from' in desired_route:
                    desired_from = parse_address(desired_route['from'])
                for iface_route in iface['routes']:
                    iface_to = parse_network(iface_route['to'])
                    if desired_to != iface_to:
                        continue

                    if 'from' in desired_route:
                        if 'src' not in iface_route:
                            continue
                        iface_from = parse_address(iface_route['src'])
                        if desired_from != iface_from:
                            continue

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

    os.system("ip route flush type blackhole")
    os.system("ip route flush type prohibit")
    os.system("ip route flush type unreachable")
    os.system("ip -6 route flush type blackhole")
    os.system("ip -6 route flush type prohibit")
    os.system("ip -6 route flush type unreachable")
