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
import copy


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


def reset(rules):
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

    if rules:
        sysstate.purge_rules(rules)

    os.system("ip link set dev ens7 address 52:54:00:b4:02:6e")
    os.system("ip link set dev ens8 address 52:54:00:38:19:7f")
    os.system("ip link set dev ens9 address 52:54:00:31:9f:12")
    os.system("ip link set dev ens10 address 52:54:00:9d:a6:ab")
    os.system("ip link set dev ens11 address 52:54:00:da:93:14")
    os.system("ip link set dev ens12 address 52:54:00:aa:3d:c3")


def generate_syntatically_valid_yaml():
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

    return yaml_dat


def mangle_route(r, addresses4, addresses6, iface):
    """Make a route semantically meaningful.
    There's quite a lot that can go wrong here.
    Return None  or (fixed up route, additional tables).
    Amend the global list of tables if returning a valid route"""

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
        return r, [r['table']]
    else:
        return r, []


def make_semantically_meaningful(parsed):
    """make the configuration semantically meaningful -
    things like not having things in the multicast or
    loopback address range, having non-on-link gws in the
    right subnets, etc.

    takes parsed syntactically valid yaml dict (which is mutated!)
    returns (updated dict, used routing tables)"""

    # we need to query routing tables so keep track of the ones we use
    tables = []

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

        if 'routes' in iface:
            new_routes = []
            for r in iface['routes']:
                new_r = mangle_route(r, addresses4, addresses6, iface)
                if new_r:
                    new_routes.append(new_r[0])
                    tables += new_r[1]

            # print(new_routes)
            iface['routes'] = new_routes

    return (parsed, tables)


def validate(parsed, tables):
    """Check if the system state matches a provided configuration

    takes parsed, a dict representing a netplan yaml config
      and tables, a list of the routing tables to query

    returns (boolean representing success, string representing status)
    eg. (True, 'success')
        (False, 'ens7 is not up')
    """
    if 'network' not in parsed:
        return (False, 'invalid')
    if 'ethernets' not in parsed['network']:
        return (False, 'invalid')

    described_ifs = parsed['network']['ethernets'].keys()
    any_down = True
    state = "success"
    sleep = 0
    while any_down:
        full_state = sysstate.get_status(tables)
        iface_state = full_state['interfaces']
        rules = full_state['rules']

        any_down = False
        for intf in described_ifs:
            iface = iface_state[intf]
            if iface['state'] != 'UP':
                state = ('waiting for UP on %s' % intf)
                any_down = True
                break
            if 'addresses' in parsed['network']['ethernets'][intf]:
                if 'addresses' not in iface:
                    state = ('waiting for addresses on %s' % intf)
                    any_down = True
                    break
                for addr in parsed['network']['ethernets'][intf]['addresses']:
                    found_addr = False
                    desired_addr = parse_address(addr)
                    desired_net = parse_network(addr)

                    for ifaddr in iface['addresses']:
                        got_addr = parse_address(ifaddr['address'])
                        got_net = parse_network(ifaddr['address'])
                        # print(desired_addr, desired_net, got_addr, got_net,
                        #      desired_addr == got_addr,
                        #      desired_net == got_net)
                        if desired_addr == got_addr and desired_net == got_net:
                            found_addr = True
                            break
                    if not found_addr:
                        state = ("Missing addr %s on %s" % (addr, intf))
                        any_down = True
                        break

            # mac
            #if 'macaddress' in parsed['network']['ethernets'][intf]:
            #    if parsed['network']['ethernets'][intf]['macaddress'] != \
            #            iface['hwaddress']:
            #        state = ("MAC mismatch on %s: %s desired, %s seen" % (
            #            intf,
            #            parsed['network']['ethernets'][intf]['macaddress'],
            #            iface['hwaddress']
            #        ))
            #        any_down = True
            #        break

            # routes
            if 'routes' in parsed['network']['ethernets'][intf] and parsed['network']['ethernets'][intf]['routes']:
                if 'routes' not in iface:
                    any_down = True
                    state = ("Waiting for routes on %s" % intf)
                    break

                for desired_route in parsed['network']['ethernets'][intf]['routes']:
                    found_route = False
                    # this assumes that if from and to match, we're good,
                    # which is not completely accurate but a good first pass
                    # we should also match on all other properties as well.
                    desired_to = parse_network(desired_route['to'])
                    desired_from = None
                    if 'from' in desired_route:
                        desired_from = parse_address(desired_route['from'])
                    for iface_route in iface['routes']:
                        iface_to = parse_network(iface_route['to'])
                        if desired_to != iface_to:
                            continue

                        if desired_from:
                            if 'src' not in iface_route:
                                continue
                            iface_from = parse_address(iface_route['src'])
                            if desired_from != iface_from:
                                continue

                        found_route = True
                        break
                    if not found_route:
                        any_down = True
                        state = ("missing route %s on %s" % (desired_route, intf))
                        break

            # check routing policy
            if ('routing-policy' in parsed['network']['ethernets'][intf] and
                    parsed['network']['ethernets'][intf]['routing-policy']):
                found_rule = False
                desired_rules = parsed['network']['ethernets'][intf]['routing-policy']
                for desired_rule in desired_rules:
                    found_rule = False
                    desired_from = None
                    if 'from' in desired_rule:
                        desired_from = parse_network(desired_rule['from'])

                    desired_to = None
                    if 'to' in desired_rule:
                        desired_to = parse_network(desired_rule['to'])

                    for system_rule in rules:
                        # from
                        if desired_from:
                            if 'from' not in system_rule:
                                continue

                            system_from = parse_network(system_rule['from'])
                            if system_from != desired_from:
                                continue

                        # to
                        if desired_to:
                            if 'to' not in system_rule:
                                # this is equivalent to a default (0.0.0.0/0, ::/0)
                                if desired_to != ipaddress.IPv4Network(u'0.0.0.0/0') and \
                                        desired_to != ipaddress.IPv6Network(u'::/0'):
                                    continue
                            else:
                                system_to = parse_network(system_rule['to'])
                                if system_to != desired_to:
                                    continue

                        # table
                        if 'table' in desired_rule:
                            if 'table' not in system_rule:
                                continue
                            if desired_rule['table'] != system_rule['table']:
                                continue

                        # priority
                        # fwmark (mark)
                        # type-of-service
                        # hope for the best for now
                        found_rule = True
                        break

                if not found_rule:
                    any_down = True
                    status = ("missing rule %s from %s", (desired_rule, intf))
                    break

        if any_down:
            print(state)
            time.sleep(1)
            sleep += 1
            if sleep == 3:
                print("kicking netplan apply")
                sysstate.purge_rules(rules)
                os.system("netplan apply")
            if sleep == 6:
                print("giving up")
                return (False, state)

    print("success")
    return (True, "success")


def same_failure(new, tables, old_error):
    with open('/etc/netplan/fuzz.yaml', 'w') as f:
        f.write(yaml.dump(new))

    reset(sysstate.get_status(tables)['rules'])
    if os.system("netplan apply") != 0:
        print("invalid yaml")
        return False

    new_result = validate(new, tables)
    print(new_result, old_error)
    return new_result[1] == old_error


def minimise_dict(broken, key, orig_ptr, tables, error):
    print('m_d', key, error)
    b_k = broken[key]
    keys = b_k.keys()
    for k in keys:
        if k in ['addresses', 'version']:
            print('skipping', k)
            continue
        print('trying to delete', k)
        save = copy.deepcopy(b_k)
        #print(yaml.dump(b_k))
        #print(b_k[k])
        del b_k[k]
        #print(k in b_k)
        #print(yaml.dump(b_k))
        if same_failure(orig_ptr, tables, error):
            print('can delete', k)
        else:
            broken[key] = save
            b_k = broken[key]
            print('cannot delete', k)
            if isinstance(b_k[k], dict):
                print('recursing into', k)
                broken[key] = minimise_dict(broken[key], k, orig_ptr, tables, error)
            elif isinstance(b_k[k], list):
                print('iterating through', k)
                broken[key] = minimise_list(broken[key], k, orig_ptr, tables, error)
    print('leaving m_d', key)
    return broken


def minimise_list(broken, key, orig_ptr, tables, error):
    print('m_l', key, error)
    new_l = []
    rest = copy.deepcopy(broken[key])
    while rest:
        print('trying to delete', rest[0])
        old = rest[0]
        del rest[0]
        broken[key] = new_l + rest
        if same_failure(orig_ptr, tables, error):
            print('can delete', old)
        else:
            print('cannot delete', old)
            new_l += [old]
            broken[key] = new_l + rest

    print('leaving m_l', key)
    return broken


def minimise(broken, tables, error):
    """attempt to minimise broken yaml so as to get a minimal example of something
    that fails the same way"""

    broken = minimise_dict(broken, 'network', broken, tables, error)

    return broken


if __name__ == '__main__':
    # manually shadow stupid networkmanager file!
    # https://github.com/CanonicalLtd/netplan/pull/40
    with open('/etc/NetworkManager/conf.d/10-globally-managed-devices.conf', 'w') as f:
        f.write('\n')

    yaml_dat = generate_syntatically_valid_yaml()
    parsed = yaml.load(yaml_dat)
    parsed, tables = make_semantically_meaningful(parsed)

    with open('/etc/netplan/fuzz.yaml', 'w') as f:
        f.write(yaml.dump(parsed))

    reset([])
    if os.system("netplan apply") != 0:
        exit(1)

    time.sleep(1)

    result = validate(parsed, tables)
    if not result[0]:
        print("failed - attempting to minimise!")
        reset(sysstate.get_status(tables)['rules'])
        minimal_1 = minimise(parsed, tables, result[1])
        minimal_1_yaml = yaml.dump(minimal_1)
        print("------")
        print(minimal_1_yaml)
        minimal_2 = minimise(minimal_1, tables, result[1])
        minimal_2_yaml = yaml.dump(minimal_2)
        print("------")
        print(minimal_2_yaml)
        while minimal_1_yaml != minimal_2_yaml:
            minimal_1 = minimal_2
            minimal_1_yaml = minimal_2_yaml
            minimal_2 = minimise(minimal_1, tables, result[1])
            minimal_2_yaml = yaml.dump(minimal_2)
            print("------")
            print(minimal_2_yaml)
        print('=========')
        print(minimal_2_yaml)
        print('=========')
        print("Throws error: %s" % result[1])
        with open('/etc/netplan/fuzz.yaml', 'w') as f:
            f.write(yaml.dump(minimal_2))
        exit(1)

    # clean up
    reset(sysstate.get_status(tables)['rules'])
