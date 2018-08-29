#!/usr/bin/python3
import subprocess


def parse_ip_link_for_iface(iface, ip_link):
    for l in ip_link.splitlines():
        if l.split(" ")[1][:-1] == iface:
            result = {}
            fields = l.split(" ")
            for (i, field) in enumerate(fields):
                if field == 'mtu':
                    result['mtu'] = int(fields[i + 1])
                elif field == 'link/ether':
                    result['hwaddress'] = fields[i + 1]
                elif field == 'state':
                    result['state'] = fields[i + 1]
            return result


def parse_ip_addr_for_iface(iface, ip_addr):
    result = {}
    for l in ip_addr.splitlines():
        if l.split(" ")[1] == iface:
            fields = l.split(" ")
            address = {}
            for (i, field) in enumerate(fields):
                if field == 'inet' or field == 'inet6':
                    address['address'] = fields[i + 1]
                elif field == 'scope':
                    address['scope'] = fields[i + 1]
                elif field == 'dynamic':
                    address['dynamic'] = True

            if not 'addresses' in result:
                result['addresses'] = []
            result['addresses'] += [address]

    return result


def parse_ip_route_for_iface(iface, ip_route_str, six=False, table=None):
    routes = []
    for l in ip_route_str.splitlines():
        # two reasons we would consider a route
        # 1) it mentions us specifically
        # 2) it's a blackhole/prohibit/unreachable, in which case it could come from
        #    any interface. So report it from all.
        fields = l.split(" ")

        is_interesting = False
        if ('dev ' + iface) in l:
            is_interesting = True
            to_posn = 0
        elif fields[0] in ['blackhole', 'prohibit', 'unreachable']:
            is_interesting = True
            to_posn = 1

        if not is_interesting:
            continue

        route = {'to': fields[to_posn]}
        if route['to'] == 'default':
            if six:
                route['to'] = "::/0"
            else:
                route['to'] = "0.0.0.0/0"

        # the ipaddr module interprets this as ::/128, afaict
        # force the netmask
        if route['to'] == '::':
            route['to'] = '::/0'

        for (i, field) in enumerate(fields):
                if field == 'src':
                    route['src'] = fields[i + 1]
                if field == 'via':
                    route['via'] = fields[i + 1]
                elif field == 'metric':
                    route['metric'] = int(fields[i + 1])
                elif field == 'scope':
                    route['scope'] = fields[i + 1]
                elif field == 'src':
                    route['src'] = fields[i + 1]

        if table:
            route['table'] = table

        routes += [route]
    if routes:
        return {'routes': routes}
    return {}
                    

def get_routes(interfaces, table):
    command = ['ip', '--oneline', 'route', 'show']
    if table:
        command += ['table', str(table)]
    ip_route_bstr = subprocess.check_output(command)
    ip_route_str = ip_route_bstr.decode()
    for iface in interfaces.keys():
        routes = parse_ip_route_for_iface(iface, ip_route_str, table=table)
        #print(routes)
        if routes:
            if 'routes' in interfaces[iface]:
                interfaces[iface]['routes'].extend(routes['routes'])
            else:
                interfaces[iface].update(routes)
    command = ['ip', '-6', '--oneline', 'route', 'show']
    if table:
        command += ['table', str(table)]
    ip_route_bstr = subprocess.check_output(command)    
    ip_route_str = ip_route_bstr.decode()
    for iface in interfaces.keys():
        routes6 = parse_ip_route_for_iface(iface, ip_route_str, six=True, table=table)
        #print(iface, routes6)
        if routes6:
            if 'routes' in interfaces[iface]:
                interfaces[iface]['routes'].extend(routes6['routes'])
            else:
                interfaces[iface].update(routes6)


def parse_ip_rule(rules_str, six=False):
    rules = []
    for r in rules_str.splitlines():
        (priority, desc) = r.split("\t")
        priority = int(priority[:-1])
        parts = desc.split()

        rule = {'priority': priority}

        for i, part in enumerate(parts):
            if part == 'from':
                rule['from'] = parts[i + 1]
                if rule['from'] == 'all':
                    if six:
                        rule['from'] = '::/0'
                    else:
                        rule['from'] = '0.0.0.0/0'
            elif part == 'to':
                # I don't think to all really makes sense? I guess we'll find out
                rule['to'] = parts[i + 1]
            elif part == 'lookup':
                rule['table'] = parts[i + 1]
                if rule['table'] == 'local':
                    rule['table'] = 255
                elif rule['table'] == 'main':
                    rule['table'] = 254
                elif rule['table'] == 'default':
                    rule['table'] = 253
                else:
                    rule['table'] = int(rule['table'])
            elif part == 'tos':
                tos = parts[i + 1]
                # from /etc/iproute2/rt_dsfield
                mapping = {
                    'default': 0x0,
                    'AF11': 0x28,
                    'AF12': 0x30,
                    'AF13': 0x38,
                    'AF21': 0x48,
                    'AF22': 0x50,
                    'AF23': 0x58,
                    'AF31': 0x68,
                    'AF32': 0x70,
                    'AF33': 0x78,
                    'AF41': 0x88,
                    'AF42': 0x90,
                    'AF43': 0x98,
                    'CS1': 0x20,
                    'CS2': 0x40,
                    'CS3': 0x60,
                    'CS4': 0x80,
                    'CS5': 0xA0,
                    'CS6': 0xC0,
                    'CS7': 0xE0,
                    'EF': 0xB8
                }
                if tos in mapping:
                    rule['type-of-service'] = mapping[tos]
                else:
                    rule['type-of-service'] = int(tos[2:], 16)
            elif part == 'fwmark':
                rule['mark'] = int(parts[i + 1][2:], 16)
            else:
                pass
                #print('ignoring', i, part)

        rules += [rule]

    return rules


def get_status(tables):
    # get a list of interfaces
    ip_l_bstr = subprocess.check_output(['ip', '--oneline', 'link'])
    ip_l_str = ip_l_bstr.decode()
    interfaces = {}
    for ip_l_line in ip_l_str.splitlines():
        # idx: name: foo
        # so get second field and remove ':'
        iface = ip_l_line.split(" ")[1][:-1]
        if iface == 'lo':
            continue
        interfaces[iface] = {}
        
    # for each interface
    # get usual stuff
    for iface in interfaces.keys():
        interfaces[iface].update(parse_ip_link_for_iface(iface, ip_l_str))

    ip_a_bstr = subprocess.check_output(['ip', '--oneline', 'address'])
    ip_a_str = ip_a_bstr.decode()
    for iface in interfaces.keys():
        interfaces[iface].update(parse_ip_addr_for_iface(iface, ip_a_str))

    # default table is 0
    get_routes(interfaces, None)
    for table in tables:
        if table == 0:
            continue
        get_routes(interfaces, table)

    # routing policy/ip rule
    ip_rule_bstr = subprocess.check_output(['ip', 'rule'])
    ip_rule_str = ip_rule_bstr.decode()
    rules = parse_ip_rule(ip_rule_str, six=False)
    ip_rule_bstr = subprocess.check_output(['ip', '-6', 'rule'])
    ip_rule_str = ip_rule_bstr.decode()
    rules += parse_ip_rule(ip_rule_str, six=True)

    return {'interfaces': interfaces,
            'rules': rules}


def purge_rules(rules):
    for rule in rules:
        command = ['ip']

        if ('to' in rule and ':' in rule['to']) or \
                ('from' in rule and ':' in rule['from']):
            command += ['-6']

        command += ['rule', 'del']

        if 'from' in rule:
            command += ['from', rule['from']]

        if 'to' in rule:
            command += ['to', rule['to']]

        if 'type-of-service' in rule:
            command += ['tos', hex(rule['type-of-service'])]

        if 'mark' in rule:
            command += ['fwmark', str(rule['mark'])]

        if 'table' in rule:
            command += ['table', str(rule['table'])]

        #print(command)
        rc = subprocess.call(command)
        #print(rc)

    subprocess.call(['ip', 'rule', 'add', 'from', 'all', 'priority', '0', 'table', 'local'])
    subprocess.call(['ip', 'rule', 'add', 'from', 'all', 'priority', '32766', 'table', 'main'])
    subprocess.call(['ip', 'rule', 'add', 'from', 'all', 'priority', '32767', 'table', 'default'])
    subprocess.call(['ip', '-6', 'rule', 'add', 'from', 'all', 'priority', '0', 'table', 'local'])
    subprocess.call(['ip', '-6', 'rule', 'add', 'from', 'all', 'priority', '32766', 'table', 'main'])
    subprocess.call(['ip', '-6', 'rule', 'add', 'from', 'all', 'priority', '32767', 'table', 'default'])


if __name__ == '__main__':
    print(get_status([]))
    purge_rules(get_status([])['rules'])
