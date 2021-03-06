from gramfuzz.fields import *

# Welcome to the netplan grammar, rendered in a way gramfuzz can understand.
# gramfuzz takes this grammar and generates random samples that comply with
# the grammar. apply.py then adjusts it to be semantically meaningful and
# calls netplan apply to apply it to the system. sysstate.py collects system
# info and apply.py checks if everything matches.

# This file is very, very much a work in progress. It's poorly ordered, has
# lots of old stuff or stuff I haven't implemented yet, and the gramfuzz
# style is not amazingly easy to read. (Although frankly I haven't yet read
# a grammar definition that is easy to read.)
#
# But in short, we start with some utilities, then define a netplan yaml
# file, and then progressively fill in what that means. NRef() marks a
# reference to a definition supplied by NDef(). Definitions *can* be
# referenced before they are used, and I do this liberally. The general
# and very loose structure of the file is basically depth-first search:
# start with the top level, drill down, repeat. Ideally I'd like to
# rearrange to breadth-first search so you progressively get more detailed.
# one day.


class NRef(Ref):
    cat = "netplan_def"


class NDef(Def):
    cat = "netplan_def"


class Octet(UInt):
    min = 0
    max = 256
    odds = [
        (0.999, [0, 255]),
        (0.001, 255)
    ]


# /0 is not usually allowed, special cased for routes
# things tend to go wrong with really small netmasks so set middling mins
# likewise, the kernel seems to have trouble adding routes where the gateway
# is the other IP on a /31. Again, this seems not worth the trouble: make
# a /30 the smallest
class IPv4Netmask(UInt):
    min = 8
    max = 31
    odds = []


class IPv6Netmask(UInt):
    min = 32
    max = 97
    odds = []


# todo redo above to be like this:
IPv6Part = String(min=2, max=3, charset="0123456789abcdef")
    

Def("yamlfile",
    """network:
  version: 2
""",
    "  renderer: ", Or("networkd", "NetworkManager"), "\n",
    # briefly had these as Opt, but why bother? go for broke with the underlying
    # devices
    "  ethernets:", "\n",
    NRef("ethernets"),
    # can't test atm
    #"  wifis:\n",
    #NRef("wifis"),
    cat="yamlfile")

NDef("ethernets",
     # need at least 1, make it ens7
     "    ens7:\n",
     # bug 15
     "      match:\n"
     #"        name: ens7\n",
     "        macaddress: 52:54:00:b4:02:6e\n",
     NRef("ethernet"),
     Opt("    ens8:\n",
         "      match:\n"
         #"        name: ens8\n",
         "        macaddress: 52:54:00:38:19:7f\n",
         NRef("ethernet")),
     Opt("    ens9:\n",
         "      match:\n"
         #"        name: ens9\n",
         "        macaddress: 52:54:00:31:9f:12\n",
         NRef("ethernet")),
     Opt("    ens10:\n",
         "      match:\n"
         #"        name: ens10\n",
         "        macaddress: 52:54:00:9d:a6:ab\n",
         NRef("ethernet")),
     Opt("    ens11:\n",
         "      match:\n"
         #"        name: ens11\n",
         "        macaddress: 52:54:00:da:93:14\n",
         NRef("ethernet")),
     Opt("    ens12:\n",
         "      match:\n"
         #"        name: ens12\n",
         "        macaddress: 52:54:00:aa:3d:c3\n",
         NRef("ethernet")),
)

NDef("ethernet",
     Or(NRef("networkd_eth"), NRef("nm_eth")),
     Opt("      wakeonlan: true\n"),
     NRef("common_properties")
)


NDef("networkd_eth",
     "      renderer: networkd\n",
     # don't do match atm, makes testing hard
     #Opt(NRef("match"),
     #    # set-name requires a match, not documented but sensible
     #    Opt("      set-name: ", NRef("set_name"), "\n"),
     #)
     "      routes:\n", NRef("networkd_routes"),
     Opt("      routing-policy:\n", NRef("routing_policy"))
)

NDef("nm_eth",
     "      renderer: NetworkManager\n",
     #Opt(NRef("nm_match"),
     #    # set-name requires a match, not documented but sensible
     #    Opt("      set-name: ", NRef("set_name"), "\n"),
     #)
     "      routes:\n", NRef("nm_routes"),
)


# ideally we want at least 1 and no more than 1 of any.
# but due to the way the parser works, better to have multiple, last will just win
NDef("match",
     "      match:\n",
     NRef("match_part"),
     Opt(NRef("match_part")),
     Opt(NRef("match_part")))

NDef("match_part",
    NRef("name_match_part") |
    NRef("mac_match_part") |
    NRef("driver_match_part"))

NDef("name_match_part", "        name: ", Or(NRef("eth_key"), "ens*"), "\n")
NDef("mac_match_part", "        macaddress: ", NRef("real_mac"), "\n")
NDef("driver_match_part", "        driver: ", NRef("real_driver"), "\n")

# networkmanager cannot match by driver, or use globs
NDef("nm_match",
     "      match:\n",
     NRef("nm_match_part"),
     Opt(NRef("nm_match_part")))

NDef("nm_match_part", Or(
    NRef("nm_name_match_part"),
    NRef("mac_match_part")))

NDef("nm_name_match_part", "        name: ", NRef("eth_key"), "\n")


# keep to devices my VM can have
# exclude ens3 for my own sanity
eth_keys = ["ens" + str(n) for n in range(7, 13)]

NDef("eth_key",
     Or(*eth_keys))

real_macs = ["52:54:00:d2:9b:b5",
             "52:54:00:b4:02:6e",
             "52:54:00:38:19:7f",
             "52:54:00:9d:a6:ab",
             "52:54:00:da:93:14",
             "52:54:00:aa:3d:c3"]
NDef("real_mac", Or(*real_macs))
real_drivers = ["virtio_net", "e1000", "8139cp"]
NDef("real_driver", Or(*real_drivers))

# no point in doing y/n/yes/no/whatever
NDef("bool", Or("true", "false"))

set_names = ["myif" + str(n) for n in range(8)]
NDef("set_name", Or(*set_names))


# only encode non-defaults, keep sample space small
# moved renderer out as it affects match
NDef("common_properties",
     #Opt("      dhcp4: true\n"),
     #Opt("      dhcp6: true\n"),
     #Opt("      critical: true\n"),
     #Opt("      dhcp-identifier: mac\n"),
     Opt("      accept-ra: false\n"),
     And("      addresses: [", NRef("addresses"), "]\n",
         # gateways only make sense with addresses, per docs
         Opt("      gateway4: ", NRef("ipv4_address"), "\n"),
         Opt("      gateway6: ", NRef("ipv6_address"), "\n")),
     Opt("      nameservers:\n", NRef("nameserver_parts")),
     Opt("      macaddress: ", NRef("set_mac"), "\n"),
     #Opt("      optional: true\n"),
)


NDef("nameserver_parts",
     Or(NRef("ns_search"), NRef("ns_addrs")),
     Opt(Or(NRef("ns_search"), NRef("ns_addrs"))))
NDef("ns_search",
     "        search: [lab, home]\n") # thoughts?
NDef("ns_addrs", "        addresses: [",
     Or(NRef("ipv4_address"), NRef("ipv6_address")),
     Opt(", ", NRef("ipv4_address")),
     Opt(", ", NRef("ipv4_address")),
     Opt(", ", NRef("ipv6_address")),
     Opt(", ", NRef("ipv6_address")), "]\n")


NDef("addresses", NRef("address_nm"), Opt(", ", NRef("addresses")))
NDef("address_nm", Or(NRef("ipv4_address_nm"), NRef("ipv6_address_nm")))
NDef("ipv4_address_nm", NRef("ipv4_address"), "/", IPv4Netmask)
NDef("ipv6_address_nm", '"',
     NRef("ipv6_address_inner"),  "/", IPv6Netmask, '"')
# NM seems to really dislike 0.n.n.n addresses and that seems not really
# worth fussing about
NDef("ipv4_address", Octet(min=1), ".", Octet(), ".", Octet(), ".", Octet())
NDef("ipv6_address", '"', NRef("ipv6_address_inner"), '"')
NDef("ipv6_address_inner",
     IPv6Part, ":", IPv6Part, ":", IPv6Part, ":", IPv6Part, ":",
     IPv6Part, ":", IPv6Part, ":", IPv6Part, ":", IPv6Part)


set_macs = ["52:54:00:2d:b9:5b",
            "52:54:00:4b:20:e6",
            "52:54:00:83:91:f7",
            "52:54:00:d9:6a:ba",
            "52:54:00:ad:39:41",
            "52:54:00:aa:d3:3c"]
NDef("set_mac", Or(*set_macs))


NDef("networkd_routes", PLUS(NRef("networkd_route")))
NDef("nm_routes", PLUS(NRef("nm_route")))

NDef("networkd_route", Or(NRef("networkd_ipv4_route"), NRef("networkd_ipv6_route")))
NDef("nm_route", Or(NRef("nm_ipv4_route"), NRef("nm_ipv6_route")))

NDef("networkd_ipv4_route",
     # at least to and via must be specified:
     "        - to: ", Or("0.0.0.0/0", NRef("ipv4_address_nm")), "\n",
     "          via: ", NRef("ipv4_address"), "\n",
     Opt("          from: ", NRef("ipv4_address_nm"), "\n"),
     NRef("route_common"))
NDef("networkd_ipv6_route",
     "        - to: ", Or('"::/0"', NRef("ipv6_address_nm")), "\n",
     "          via: ", NRef("ipv6_address"), "\n",
     Opt("          from: ", NRef("ipv6_address_nm"), "\n"),
     NRef("route_common"))

NDef("route_common",
     Opt("          on-link: true\n"),
     Opt("          metric: ", UInt(min=0, max=65535, odds=[]), "\n"),
     Opt("          type: ", Or("unreachable", "blackhole", "prohibit"), "\n"),
     Opt("          scope: ", Or("global", "link", "host"), "\n"),
     Opt("          table: ", UInt(min=1, max=65536, odds=[]), "\n")
)


# bug 4: no default routes for networkmanager
# bug 3: only to, via, metric for networkmanager
NDef("nm_ipv4_route",
     "        - to: ", NRef("ipv4_address_nm"), "\n",
     "          via: ", NRef("ipv4_address"), "\n",
     Opt("          metric: ", UInt(min=0, max=65535, odds=[]), "\n")
)
NDef("nm_ipv6_route",
     "        - to: ", NRef("ipv6_address_nm"), "\n",
     "          via: ", NRef("ipv6_address"), "\n",
     Opt("          metric: ", UInt(min=0, max=65535, odds=[]), "\n")
)


NDef("routing_policy", PLUS(Or(NRef("ipv4_policy"), NRef("ipv6_policy"))))
NDef("ipv4_policy",
     "        - ", NRef("ipv4_rprule"), "\n",
     Opt("          ", NRef("ipv4_rp_from"), "\n"),
     Opt("          ", NRef("ipv4_rp_to"), "\n"),
     Opt("          ", NRef("ipv4_rp_tos"), "\n"),
     NRef("policy_common"))
NDef("ipv6_policy",
     "        - ", NRef("ipv6_rprule"), "\n",
     Opt("          ", NRef("ipv6_rp_from"), "\n"),
     Opt("          ", NRef("ipv6_rp_to"), "\n"),
     Opt("          ", NRef("ipv6_rp_tos"), "\n"),
     NRef("policy_common"))

NDef("ipv4_rp_from", "from: ", Or(NRef("ipv4_address_nm"), "0.0.0.0/0"))
NDef("ipv4_rp_to", "to: ", Or(NRef("ipv4_address_nm"), "0.0.0.0/0"))
NDef("ipv6_rp_from", "from: ", Or(NRef("ipv6_address_nm"), '"::/0"'))
NDef("ipv6_rp_to", "to: ", Or(NRef("ipv6_address_nm"), '"::/0"'))
NDef("rp_table", "table: ",  UInt(min=1, max=32676, odds=[])) # don't clash with local, main or default
NDef("rp_prio", "priority: ",  UInt(min=0, max=65535, odds=[]))
NDef("rp_mark", "mark: ",  UInt(min=1, max=65536, odds=[]))
# rm ok; for i in `seq 0 255`; do hex=$(printf "0x%x" $i); echo $i $hex; if ip rule add to 0.0.0.0\0
# from 58.70.6.15/21 table 12345 tos $hex; then echo $i $hex >> ok; ip rule del to 0.0.0.0/0 tos $hex
# from 58.70.6.15/21 table 12345; fi; done
NDef("ipv4_rp_tos", "type-of-service: ",
     Or(0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30))
# similar command with ipv6
NDef("ipv6_rp_tos", "type-of-service: ",
     Or(*list(range(0, 256))))


NDef("ipv4_rprule", Or(
    NRef("ipv4_rp_from"),
    NRef("ipv4_rp_to"),
    # bug 14
    #Opt(NRef("rp_mark"), "\n"),
    #Opt(NRef("ipv4_rp_tos"), "\n"),
))
NDef("ipv6_rprule", Or(
    NRef("ipv6_rp_from"),
    NRef("ipv6_rp_to"),
    # bug 14
    #Opt(NRef("rp_mark"), "\n"),
    #Opt(NRef("ipv6_rp_tos"), "\n"),
))

NDef("policy_common",
     "          ", NRef("rp_table"), "\n",
     Opt("          ", NRef("rp_prio"), "\n"),
     Opt("          ", NRef("rp_mark"), "\n"),
     )

NDef("wifis",
     "    wlan0:\n",
    NRef("wifi"),
    "    wlan1:\n",
    NRef("wifi"))

NDef("wifi",    
     Or(NRef("networkd_wifi"), NRef("nm_wifi")),
     NRef("common_properties")
)


# ERROR: wlan0: networkd backend does not support wifi with match:, only by interface name
# so don't match at all
NDef("networkd_wifi",
     "      renderer: networkd\n",
     NRef("networkd_access_points"))

NDef("nm_wifi",
     "      renderer: NetworkManager\n",
     #Opt(NRef("nm_wifi_match"),
     #    Opt("      set-name: ", NRef("set_name"), "\n"),
     #),
     NRef("nm_access_points"),
)

NDef("wifi_mac_match_part", "        macaddress: ",
     Or("02:00:00:00:00:00",
        "02:00:00:00:01:00"), "\n")

NDef("nm_wifi_match",
     "      match:\n",
     NRef("nm_wifi_match_part"),
     Opt(NRef("nm_wifi_match_part")))

NDef("nm_wifi_match_part", Or(
    NRef("nm_wifi_name_match_part"),
    NRef("wifi_mac_match_part")))

NDef("nm_wifi_name_match_part", "        name: ", Or("wlan0", "wlan1"), "\n")

NDef("nm_access_points",
     "      access-points:\n",
     '        "', NRef("ap_name"), '":', NRef("nm_access_point"),
     Opt('        "', NRef("ap2_name"), '":', NRef("nm_access_point")),
     Opt('        "', NRef("ap3_name"), '":', NRef("nm_access_point")),
     Opt('        "', NRef("ap4_name"), '":', NRef("nm_access_point"))
)

NDef("nm_access_point",
     Or(" {}\n",
        And('\n          mode: ', Or("infrastructure", "ap", "adhoc"), "\n",
            Opt('          password: "Password? Why not Zoidberg?"\n')))
)

# networkd does not support ap mode
NDef("networkd_access_points",
     "      access-points:\n",
     '        "', NRef("ap_name"), '":', NRef("networkd_access_point"),
     Opt('        "', NRef("ap2_name"), '":', NRef("networkd_access_point")),
     Opt('        "', NRef("ap3_name"), '":', NRef("networkd_access_point")),
     Opt('        "', NRef("ap4_name"), '":', NRef("networkd_access_point"))
)


NDef("networkd_access_point",
     Or(" {}\n",
        And('\n          mode: ', Or("infrastructure", "adhoc"), "\n",
            Opt('          password: "Password? Why not Zoidberg?"\n')))
)

NDef("ap_name", Or(
    "wifinetwork",
    "Pretty Fly For a Wi-Fi",
    "ASIO Surveillence Van"))

#netplan doesn't like duplicate ap names. sad.
NDef("ap2_name", Or(
    "Tell My WiFiLoveHer",
    "Drop it like it's hotspot",
    "Some Random's iPhone"))

NDef("ap3_name", Or(
    "WHEN I hoped I feared,	",
    "Since I hoped I dared;	",
    "Everywhere alone"	,
    "As a church remain;"))

NDef("ap4_name", Or(
    "Spectre cannot harm,",
    "Serpent cannot charm;	",
    "He deposes doom,",
    "Who hath suffered him."))




