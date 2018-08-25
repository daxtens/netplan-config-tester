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

# i have no idea what an ipv6 route looks like!
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
        
    return interfaces
    # get type specific properties


if __name__ == '__main__':
    print(get_status())
