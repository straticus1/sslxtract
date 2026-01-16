#!/usr/bin/env python3
# What: swissarmydns.py
# What can this do:
			- Connect to infoblox,bluecoast, or efficient IP API's
			- list DNS Zones, list networks, list DHCP Scopes
			- Show/View/Edit scope information
			- Add/Update/Delete scope information
			- Supports: 1. Blue Cat 2. Men and Mice, legacy, 3. Infoblox
			- Supports: Converting to After Dark Systems YAML DNS Format
			- import/export djb,unbound,bind,nsd,ibx,mambc (men and mice blue cat)
# Finally support: "login","api","reset",test" features
# And site-query <site> --single,--round-robin,--all
# --dnssec=yes,no,auto --sigs=dkim,dmarc,sts --specialtxt=dkim,spf,senderid,sts
# Research infoblox,bluecat API's
# Check our new dns standard in ~/development/dnsgo/ and ~/development/dnsscienced

