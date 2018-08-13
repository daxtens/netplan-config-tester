netplan config tester
=====================

This project attempts to validate the correct behaviour of netplan by random testing. While it was originally inspired by fuzz testing, at its core it is really a specialised implementation of property based testing - the sort made popular by QuickCheck.

In short, we:

 - Generate a random, syntactically valid netplan configuration
 - Make it semantically meaningful
 - Apply it to a system
 - See if the results match our expectations

Netplan provides a reasonably rich configuration language - while not as rich as the underlying backends, it's still quite large and we currently don't cover it all. Currently, we can:

 - Generate a subset of config for up to 6 ethernet devices. No wifis, bridges, bonds or vlans yet.
 
 - Make sure addresses, nameservers, gateways and routes are semantically valid. This means things like no addresses in the IPv4 multicast block, making sure gateways live in the same subnet, making sure routes are something the kernel will accept, etc.

 - Verify some properties - currently: that the devices come up, that they have the desired addresses, and that explictly-specified routes are configured.

Does it work?
-------------

By "work", you could mean either of the following questions:

**Can I run it?**

Yes, but it's fiddly to set up.  You'll need:

 - a throwaway VM with ens7 through ens12. These interfaces don't need to (and probably should not) be attached to a real network. (If that's a real problem, modify yaml_grammar.py and the cleanup in apply.py to match what you have.)
 
 - Ideally, netplan compiled from the head of my tree (https://github.com/daxtens/netplan). When I find bugs, I put in a workaround so I can keep testing, but then I remove the workaround when I fix the bug. If you run with an unpatched netplan, you're likely to rediscover bugs.

 - A virtualenv with gramfuzz and ipaddress. (Irritatingly gramfuzz only supports python2.) 
 
Then, as root, enter the virtualenv and run "while python apply.py; do true; done". It should be pretty chatty about what it's doing and will stop when something that should be set up has not been set up.

**Does it find bugs?**

Yes. See bugs.txt

TODO
----

Many, many things:
 - implement more of the grammar - wifis, bridges, bonds, vlans
 - verify more properties
 - make the code less embarassing
 - ipv6 onlink stuff looks very complex (see tools/testing/selftests/net/fib-onlink-tests.sh in a modern linux source tree) so I have completely disabled it for now, it should be sorted out.