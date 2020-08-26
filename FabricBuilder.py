import cvp
from string import Template
from cvplibrary import CVPGlobalVariables,GlobalVariableNames
from cvplibrary import Form

#
# Assign constants
#

#host = CVPGlobalVariables.getValue(GlobalVariableNames.CVP_IP)
host = '10.251.0.19'
user = CVPGlobalVariables.getValue(GlobalVariableNames.CVP_USERNAME)
password = CVPGlobalVariables.getValue(GlobalVariableNames.CVP_PASSWORD)
parentName = 'Tenant'

#
# Assign command line options to variables and assign static variables
#

name = Form.getFieldById('dcname').getValue()
no_spine = int(Form.getFieldById('spines').getValue())
no_leaf = int(Form.getFieldById('leafs').getValue())
defaultgw = Form.getFieldById('defaultgw').getValue()
mgmtnetwork = Form.getFieldById('mgmtnet').getValue()
mgmtvrf = Form.getFieldById('mgmtvrf').getValue()
mgmtnetmask = int(Form.getFieldById('mgmtnetmask').getValue())
vxlanloopback = Form.getFieldById('vxlanloopback').getValue()
loopback = Form.getFieldById('loopback').getValue()
linknetwork = Form.getFieldById('linknetwork').getValue()
deploymenttype = Form.getFieldById('deploymenttype').getValue()
cvxserver = Form.getFieldById('cvx_server').getValue()

mlag = Form.getFieldById('mlag').getValue()
if mlag == "yes":
  mlagnetwork = Form.getFieldById('mlagnetwork').getValue()
  mlagtrunkinterfaces = Form.getFieldById('mlagtrunkinterfaces').getValue()

virtual = Form.getFieldById('virtual').getValue()
uplinks = Form.getFieldById('uplinks').getValue()
snmp_public = Form.getFieldById('snmp_public').getValue()
snmp_private = Form.getFieldById('snmp_private').getValue()
syslogserver = Form.getFieldById('syslogserver').getValue()
log_facility = Form.getFieldById('log_facility').getValue()
primary_ntp = Form.getFieldById('primary_ntp').getValue()
second_ntp = Form.getFieldById('second_ntp').getValue()
spine_start_asn = Form.getFieldById('spine_start_asn').getValue()
max_routes = Form.getFieldById('max_routes').getValue()
max_evpn_routes = Form.getFieldById('max_evpn_routes').getValue()
max_ecmp = int(uplinks) * int(no_spine)

my_spine_container_name = name + " Spine"
my_leaf_container_name = name + " Leaf"
dc_configlet_name = name + " Base config"
configlet_list = []
cvx_configlet_list = []
leaf_configlet_list = []

#
# Support functions for main code
#

def configletExists( cvpServer , configlet_name ):
	configlet_exist = 0
	myConfiglets = cvpServer.getConfiglets()
	for myConfiglet in myConfiglets:
		if myConfiglet.name == configlet_name:
			configlet_exist = 1
	return configlet_exist

def updateMyConfiglet( cvpServer , configlet_name , configlet_config ):
	myConfiglet = cvpServer.getConfiglet( configlet_name )
	myConfiglet.config = configlet_config
	cvpServer.updateConfiglet( myConfiglet )

def containerExists( cvpServer , container_name ):
	container_exist = 0
	myContainers = cvpServer.getContainers()
	for myContainer in myContainers:
		if myContainer.name == container_name:
			container_exist = 1
	return container_exist

#
#
# The first part of the code builds a dictionary representing first all the spines
# and their relevant data to create their config.
#
# Second part of the code builds a dictionary representing first all the leafs
# and their relevant data to create their config.
#

#
# Build the DC list of spine switches in dictionary form.
#

linksubnetcounter = 0
loopbackcounter = 0
vxlanloopbackcounter = 0
mgmtnetworkcounter = 80

DC = []
Leafs = []

for counter in range(1,no_spine+1):
	spine_name = name + "spine" + str(counter)
	interface_list = []
	element_dict = {}
	element_dict['name'] = spine_name
	element_dict['loopback'] = loopback + str(loopbackcounter)
	loopbackcounter = loopbackcounter + 1
	element_dict['mgmt'] = mgmtnetwork + str(mgmtnetworkcounter)
	mgmtnetworkcounter = mgmtnetworkcounter + 1
	counter3 = 1

	for counter2 in range(1,int(no_leaf)+1):
		for i in range(1,int(uplinks)+1):
			if virtual == "physical":
				spine_interface_name = "Ethernet"+str(counter3)+"/1"
			else:
				spine_interface_name = "Ethernet"+str(counter3)

			leaf_name = name + "leaf" + str(counter2)
			neighbor_dict = {}
			neighbor_dict['neighbor'] = leaf_name
			link = linknetwork + str(linksubnetcounter)
			neighborlink = linknetwork + str(linksubnetcounter+1)
			neighborint = str(linksubnetcounter+1)
			linksubnetcounter = linksubnetcounter + 2
			neighbor_dict['linknet'] = link
			neighbor_dict['neighbor_ip'] = neighborlink
			if virtual == "physical":
				neighbor_dict['neighbor_interface'] = "Ethernet" + str(i + 48 + ((counter - 1) * int(uplinks))) + "/1"
			else:
				neighbor_dict['neighbor_interface'] = "Ethernet" + str(i + ((counter - 1) * int(uplinks)))
			
			neighbor_dict['local_interface'] = spine_interface_name
			neighbor_dict['neighbor_int'] = neighborint
			
			neighbor_asn = int(spine_start_asn) + counter2
			if neighbor_asn % 2 == 1:
				neighbor_dict['asn'] = neighbor_asn
			else:
				neighbor_dict['asn'] = neighbor_asn - 1 
			
			interface_list.append(neighbor_dict)
			counter3 = counter3 + 1
		
		element_dict['interfaces'] = interface_list
	
	DC.append(element_dict)

#
# Build the Leaf list of leaf switches in dictionary form.
#

#
# If leafs are organised as MLAG pairs, build accordingly.
#

if mlag == "yes":
	for counter in range (1,no_leaf+1):
		leaf_dict = {}
		leaf_dict['name'] = name + "leaf" + str(counter)
		leaf_dict['loopback'] = loopback + str(loopbackcounter)
		loopbackcounter = loopbackcounter +1
		if vxlanloopbackcounter % 2 == 1:
			mlaginterface = mlagnetwork + "0"
			mlagpeer = mlagnetwork + "1"
			leaf_dict['mlaginterface'] = mlaginterface
			leaf_dict['mlagpeer'] = mlagpeer
			leaf_dict['vxlan'] = vxlanloopback + str(vxlanloopbackcounter - 1)
		else:
			mlaginterface = mlagnetwork + "1"
			mlagpeer = mlagnetwork + "0"
			leaf_dict['mlaginterface'] = mlaginterface
			leaf_dict['mlagpeer'] = mlagpeer
			leaf_dict['vxlan'] = vxlanloopback + str(vxlanloopbackcounter)
		vxlanloopbackcounter = vxlanloopbackcounter +1
		leaf_dict['mgmt'] = mgmtnetwork + str(mgmtnetworkcounter)
		mgmtnetworkcounter = mgmtnetworkcounter + 1
		asn = int(spine_start_asn) + counter
		if asn % 2 == 1:
			leaf_dict['asn'] = asn
		else:
			leaf_dict['asn'] = asn - 1 

		Leafs.append(leaf_dict)

#
# If leafs are organised standalone, build accordingly.
#

if mlag == "no":
	for counter in range (1,no_leaf+1):
		leaf_dict= {}
		leaf_dict['name'] = name + "leaf" + str(counter)
		leaf_dict['loopback'] = loopback + str(loopbackcounter)
		loopbackcounter = loopbackcounter +1
		leaf_dict['vxlan'] = vxlanloopback + str(vxlanloopbackcounter)
		vxlanloopbackcounter = vxlanloopbackcounter +1
		leaf_dict['mgmt'] = mgmtnetwork + str(mgmtnetworkcounter)
		mgmtnetworkcounter = mgmtnetworkcounter + 1
		asn = int(spine_start_asn) + counter
		leaf_dict['asn'] = asn

		Leafs.append(leaf_dict)

#
# Build a VTEP list for the HER use case.
#

if deploymenttype == "her":
	vteplist = ""
	for leaf in Leafs:
		if leaf['vxlan'] not in vteplist:
			vteplist = vteplist + " " + leaf['vxlan']

#
# Connect and authenticate with CVP server
#

server = cvp.Cvp( host )
server.authenticate( user , password )

#
# Create needed configlets for the new DC
#

Replacements = {
                "defaultgw": defaultgw,
                "syslog": syslogserver,
                "private": snmp_private,
                "public": snmp_public,
                "facility": log_facility,
                "primary_ntp": primary_ntp,
                "second_ntp": second_ntp,
                "mgmtvrf": mgmtvrf 
                }

dc_base_config = Template("""
!
transceiver qsfp default-mode 4x10G
!
logging buffered 128000
logging console informational
logging format timestamp high-resolution
logging facility $facility
logging host $syslog
logging source-interface Management1
!
snmp-server community $private rw
snmp-server community $public ro
!
ntp server $primary_ntp prefer version 4
ntp server $second_ntp version 4
!
spanning-tree mode mstp
!
no aaa root
!
ip virtual-router mac-address 00:11:22:33:44:55
!
vrf instance $mgmtvrf
!
ip route vrf $mgmtvrf 0.0.0.0/0 $defaultgw
ip routing
!
management api http-commands
   protocol http
   cors allowed-origin all
   no shutdown
   vrf $mgmtvrf
   no shutdown
""").safe_substitute(Replacements)

if deploymenttype == "evpn":
	Replacements = {
    				"dummy":"dummy"
                }

	arbgp_config = Template("""
!
service routing protocols model multi-agent 
!
""").safe_substitute(Replacements)
	dc_base_config = dc_base_config + arbgp_config

#
# If debug is activated, only print config that should have gone into configlets,
# do not actually create configlets. If debug is not activated, create configlets
# and add them to CVP.
#

dc_configlet = cvp.Configlet( dc_configlet_name , dc_base_config  )
if configletExists( server , dc_configlet_name ):
	updateMyConfiglet( server , dc_configlet_name , dc_base_config )
	rebuild = 1
else:
	server.addConfiglet( dc_configlet )
	configlet_list.append( dc_configlet )
	rebuild = 0
  
#
# Build base config configlets for spines and add them to CVP.
# Start with config that is the same in all deployment types.
#

for spine_switch in DC:
	Replacements = {
					"hostname": spine_switch['name'],
					"loopaddress": spine_switch['loopback'],
					"mgmtaddress": spine_switch['mgmt'],
					"mgmtnetmask": mgmtnetmask,
					"mgmtvrf": mgmtvrf
					}

	spine_base_config = Template("""
!
hostname $hostname
!
interface Loopback0
   ip address $loopaddress/32
!
interface Management1
   vrf $mgmtvrf
   ip address $mgmtaddress/$mgmtnetmask
""").safe_substitute(Replacements)
	
	for interface in spine_switch['interfaces']:
		Replacements = {
						"local_interface": interface['local_interface'] ,
						"description": interface['neighbor'],
						"linknet": interface['linknet']
						}
		add_to_spine_config = Template("""
!
interface $local_interface
   description $description
   no switchport
   ip address $linknet/31
!""").safe_substitute(Replacements)

		spine_base_config = spine_base_config + add_to_spine_config

	spine_configlet_name = spine_switch['name'] + " configuration"
	if rebuild == 1:
	  		updateMyConfiglet( server , spine_configlet_name , spine_base_config )
	else:
		spine_configlet = cvp.Configlet( spine_configlet_name , spine_base_config )
		server.addConfiglet( spine_configlet )
		
#
# Create configlets unique for spine in cvx and her deployment types
# and add them to CVP.
#

	if deploymenttype == "her" or deploymenttype == "cvx":
		Replacements = {
						"routerid": spine_switch['loopback'],
						"linknet": linknetwork + "0/24",
						"uplinks": uplinks,
						"asn": spine_start_asn,
						"max_routes": max_routes,
						"max_ecmp": max_ecmp
						}

		spine_bgp_config = Template("""
router bgp $asn
   router-id $routerid
   maximum-paths $max_ecmp ecmp $max_ecmp
   neighbor leafs peer group
   neighbor leafs maximum-routes $max_routes 
   redistribute connected""").safe_substitute(Replacements)

		for interface in spine_switch['interfaces']:
			Replacements = {
							"neighbor": interface['neighbor_ip'],
							"asn": interface['asn']
							}
			add_to_sping_bgp_config = Template("""
   neighbor $neighbor peer group leafs
   neighbor $neighbor remote-as $asn""").safe_substitute(Replacements)
			spine_bgp_config = spine_bgp_config + add_to_sping_bgp_config
#
# Create config unique for spine in evpn deployment type
#

	if deploymenttype == "evpn":
		Replacements = {
						"routerid": spine_switch['loopback'],
						"linknet": linknetwork,
						"uplinks": uplinks,
						"asn": spine_start_asn,
						"max_routes": max_routes,
						"max_ecmp": max_ecmp,
						"max_evpn_routes": max_evpn_routes
						}

		spine_bgp_config = Template("""
router bgp $asn
   router-id $routerid
   maximum-paths $max_ecmp ecmp $max_ecmp
   neighbor leafs peer group
   neighbor leafs maximum-routes $max_routes 
   neighbor EVPN peer group
   neighbor EVPN bfd
   neighbor EVPN maximum-routes $max_evpn_routes
   neighbor EVPN next-hop-unchanged
   neighbor EVPN update-source Loopback0
   neighbor EVPN ebgp-multihop 4
   neighbor EVPN send-community
   redistribute connected""").safe_substitute(Replacements)

		for interface in spine_switch['interfaces']:
			Replacements = {
							"neighbor": interface['neighbor_ip'],
							"asn": interface['asn']
							}
			add_to_sping_bgp_config = Template("""
   neighbor $neighbor peer group leafs
   neighbor $neighbor remote-as $asn""").safe_substitute(Replacements)
			spine_bgp_config = spine_bgp_config + add_to_sping_bgp_config

		for leaf in Leafs:
			Replacements = {
							"neighbor": leaf['loopback'],
							"asn": leaf['asn']
							}
			add_to_sping_bgp_config = Template("""
   neighbor $neighbor peer group EVPN
   neighbor $neighbor remote-as $asn""").safe_substitute(Replacements)
			spine_bgp_config = spine_bgp_config + add_to_sping_bgp_config

		add_to_sping_bgp_config = ("""
   address-family evpn""")
		spine_bgp_config = spine_bgp_config + add_to_sping_bgp_config

		for leaf in Leafs:
			Replacements = {
							"neighbor": leaf['loopback'],
							"asn": leaf['asn']
							}
			add_to_sping_bgp_config = Template("""
      neighbor $neighbor activate""").safe_substitute(Replacements)
			spine_bgp_config = spine_bgp_config + add_to_sping_bgp_config

		add_to_sping_bgp_config = ("""
   address-family ipv4""")
		spine_bgp_config = spine_bgp_config + add_to_sping_bgp_config

		for leaf in Leafs:
			Replacements = {
							"neighbor": leaf['loopback'],
							"asn": leaf['asn']
							}
			add_to_sping_bgp_config = Template("""
      no neighbor $neighbor activate""").safe_substitute(Replacements)
			spine_bgp_config = spine_bgp_config + add_to_sping_bgp_config

	spine_bgp_configlet_name = spine_switch['name'] + " BGP configuration"
	if rebuild == 1:
		updateMyConfiglet( server , spine_bgp_configlet_name , spine_bgp_config )
	else:
		spine_bgp_configlet = cvp.Configlet( spine_bgp_configlet_name , spine_bgp_config )
		server.addConfiglet( spine_bgp_configlet )
#
# Build standalone shared configlets for CVX use case
#

if deploymenttype == "cvx":
  Replacements = {
	  "cvxserver": cvxserver
		  }

  cvx_config = Template("""
!
management cvx
   no shutdown
   server host $cvxserver
!
""").safe_substitute(Replacements)

  cvx_configlet_name = name + " CVX client configuration"
  cvx_configlet = cvp.Configlet( cvx_configlet_name, cvx_config )
  if configletExists( server , cvx_configlet_name ):
    updateMyConfiglet( server , cvx_configlet_name , cvx_config )
  else:
    server.addConfiglet( cvx_configlet )
    cvx_configlet_list.append( cvx_configlet )

#
# Create Vxlan1 configlets based on CVX deployment type.
#

if deploymenttype == "cvx":
	Replacements = { "dummy": "dummy"
					}
	vxlan_leaf_config = Template("""
interface Vxlan1
   vxlan source-interface Loopback1
   vxlan udp-port 4789
   vxlan controller-client
!
""").safe_substitute(Replacements)

#
# Create Vxlan1 config based on HER deployment type.
#

if deploymenttype == "her":
	Replacements = { "dummy": "dummy",
					 "vteplist": vteplist
					}
	vxlan_leaf_config = Template("""
interface Vxlan1
   vxlan source-interface Loopback1
   vxlan udp-port 4789
   vxlan flood vtep$vteplist
!
""").safe_substitute(Replacements)

#
# Create Vxlan1 config based on EVPN deployment type.
#

if deploymenttype == "evpn":
	Replacements = { "dummy": "dummy"
					}
	vxlan_leaf_config = Template("""
interface Vxlan1
   vxlan source-interface Loopback1
   vxlan udp-port 4789
!
""").safe_substitute(Replacements)

#
# Create and add the VXLAN configlet, or update if it exists
#

vxlan_configlet_name = name + " Interface VXLAN1 base configuration"
if rebuild == 1:
	updateMyConfiglet ( server , vxlan_configlet_name , vxlan_leaf_config )
else:
	vxlan_configlet = cvp.Configlet( vxlan_configlet_name, vxlan_leaf_config )
	server.addConfiglet( vxlan_configlet )
	
# Build base config configlets for leafs and add them to CVP.
# Start with config that is the same in all deployment types.
#

for leaf in Leafs:
	if deploymenttype == "her":
		Replacements = {
						"hostname": leaf['name'],
						"loopback": leaf['loopback'],
						"vxlan": leaf['vxlan'],
						"mgmtip": leaf['mgmt'],
						"mgmtnetmask": mgmtnetmask,
						"mgmtvrf": mgmtvrf
						}
		leaf_config = Template("""
!
hostname $hostname
!
interface Loopback0
   ip address $loopback/32
!
interface Loopback1
   ip address $vxlan/32
!
interface Management1
   vrf $mgmtvrf
   ip address $mgmtip/$mgmtnetmask
!
""").safe_substitute(Replacements)

	if deploymenttype == "cvx":
		Replacements = {
						"hostname": leaf['name'],
						"loopback": leaf['loopback'],
						"vxlan": leaf['vxlan'],
						"mgmtip": leaf['mgmt'],
						"mgmtnetmask": mgmtnetmask,
						"mgmtvrf": mgmtvrf
						}
		leaf_config = Template("""
!
hostname $hostname
!
interface Loopback0
   ip address $loopback/32
!
interface Loopback1
   ip address $vxlan/32
!
interface Management1
   vrf $mgmtvrf
   ip address $mgmtip/$mgmtnetmask
!
""").safe_substitute(Replacements)


	if deploymenttype == "evpn":
		Replacements = {
						"hostname": leaf['name'],
						"loopback": leaf['loopback'],
						"mgmtip": leaf['mgmt'],
						"mgmtnetmask": mgmtnetmask,
						"mgmtvrf": mgmtvrf,
						"vxlan": leaf['vxlan']
						}
		leaf_config = Template("""
!
hostname $hostname
!
interface Loopback0
   ip address $loopback/32
!
interface Loopback1
   ip address $vxlan/32
!
interface Management1
   vrf $mgmtvrf
   ip address $mgmtip/$mgmtnetmask
!
""").safe_substitute(Replacements)		

#
# Create MLAG config when leafs are organised as MLAG pairs.
#

	if mlag == "yes":
		mlagtrunkinterfacelist = mlagtrunkinterfaces.split(',')
		mlagtrunkinterface1 = mlagtrunkinterfacelist[0]
		mlagtrunkinterface2 = mlagtrunkinterfacelist[1]
		Replacements = { "mlaginterface": leaf['mlaginterface'],
						 "mlagpeer": leaf['mlagpeer'],
						 "mlagtrunkinterface1": mlagtrunkinterface1,
						 "mlagtrunkinterface2": mlagtrunkinterface2
						}
		mlag_add_to_leaf_config = Template("""
!
vlan 4094
   name MLAGPEER
   trunk group mlagpeer
!
no spanning-tree vlan-id 4094
!
interface port-channel 2000
   switchport trunk group mlagpeer
   switchport mode trunk
!
interface $mlagtrunkinterface1
   channel-group 2000 mode active
!
interface $mlagtrunkinterface2
   channel-group 2000 mode active
!
interface Vlan4094
   ip address $mlaginterface/31
!
mlag
   local-interface vlan 4094
   peer-address $mlagpeer
   peer-link port-channel 2000
   domain-id MLAG
!
""").safe_substitute(Replacements)
		leaf_config = leaf_config + mlag_add_to_leaf_config

#
# Create BGP configlets for CVX and HER deployment types.
# I.e. underlay BGP configlets.
#

	if (deploymenttype == "her" or deploymenttype == "cvx") and mlag == "no":
		Replacements = {
						"routerid": leaf['loopback'],
						"uplinks": uplinks,
						"asn": leaf['asn'],
						"spine_asn": spine_start_asn,
						"max_ecmp": max_ecmp,
						"max_routes": max_routes
						}
		leaf_bgp_config = Template("""
router bgp $asn
   router-id $routerid
   maximum-paths $max_ecmp ecmp $max_ecmp
   neighbor spines peer group
   neighbor spines remote-as $spine_asn
   neighbor spines maximum-routes $max_routes
   redistribute connected""").safe_substitute(Replacements)

	if (deploymenttype == "her" or deploymenttype == "cvx") and mlag == "yes":
		Replacements = {
						"routerid": leaf['loopback'],
						"mlagpeer": leaf['mlagpeer'],
						"uplinks": uplinks,
						"asn": leaf['asn'],
						"spine_asn": spine_start_asn,
						"max_ecmp": max_ecmp,
						"max_routes": max_routes
						}
		leaf_bgp_config = Template("""
router bgp $asn
   router-id $routerid
   maximum-paths $max_ecmp ecmp $max_ecmp
   neighbor spines peer group
   neighbor spines remote-as $spine_asn
   neighbor spines maximum-routes $max_routes
   neighbor mlag-neighbor peer group
   neighbor mlag-neighbor remote-as $asn
   neighbor mlag-neighbor update-source vlan4094
   neighbor $mlagpeer peer group mlag-neighbor
   redistribute connected""").safe_substitute(Replacements)

#
# Create BGP configlets for EVPN deployment types.
# I.e. underlay and EVPN overlay BGP configlets.
#

	if deploymenttype ==  "evpn" and mlag == "no":
		Replacements = {
						"asn": leaf['asn'] ,
						"routerid": leaf['loopback'],
						"uplinks": uplinks,
						"spine_asn": spine_start_asn,
						"max_ecmp": max_ecmp,
						"max_routes": max_routes,
						"max_evpn_routes": max_evpn_routes
						}
		leaf_bgp_config = Template("""
router bgp $asn
   router-id $routerid
   maximum-paths $max_ecmp ecmp $max_ecmp
   neighbor EVPN peer group
   neighbor EVPN update-source Loopback0
   neighbor EVPN ebgp-multihop 4
   neighbor EVPN send-community
   neighbor EVPN bfd
   neighbor EVPN maximum-routes $max_evpn_routes
   neighbor spines peer group
   neighbor spines remote-as $spine_asn
   neighbor spines maximum-routes $max_routes""").safe_substitute(Replacements)

	if deploymenttype ==  "evpn" and mlag == "yes":
		Replacements = {
						"asn": leaf['asn'] ,
						"routerid": leaf['loopback'],
						"mlagpeer": leaf['mlagpeer'],
						"uplinks": uplinks,
						"spine_asn": spine_start_asn,
						"max_ecmp": max_ecmp,
						"max_routes": max_routes,
						"max_evpn_routes": max_evpn_routes
						}
		leaf_bgp_config = Template("""
router bgp $asn
   router-id $routerid
   maximum-paths $max_ecmp ecmp $max_ecmp
   neighbor EVPN peer group
   neighbor EVPN update-source Loopback0
   neighbor EVPN ebgp-multihop 4
   neighbor EVPN send-community
   neighbor EVPN bfd
   neighbor EVPN maximum-routes $max_evpn_routes
   neighbor mlag-neighbor peer group
   neighbor mlag-neighbor remote-as $asn
   neighbor mlag-neighbor update-source vlan4094
   neighbor $mlagpeer peer group mlag-neighbor
   neighbor spines peer group
   neighbor spines remote-as $spine_asn
   neighbor spines maximum-routes $max_routes""").safe_substitute(Replacements)

#
# Build interface configlets for each leaf. Add BGP neighbor configuration to
# BGP configlets.
#

	for spine_switch in DC:
		for interface in spine_switch['interfaces']:
			if interface['neighbor'] == leaf['name']:
				Replacements = {
								"interface": interface['neighbor_interface'],
								"description": spine_switch['name'],
								"neighbor_ip": interface['neighbor_ip']
								}
				add_to_leaf_config = Template("""
!
interface $interface
   description $description
   no switchport
   ip address $neighbor_ip/31
!
""").safe_substitute(Replacements)
				leaf_config = leaf_config + add_to_leaf_config

				if deploymenttype == "her" or deploymenttype == "cvx":
					Replacements = {
									"neighborip": linknetwork + str(int(interface['neighbor_int']) -1)
									}
					add_to_leaf_bgp_config = Template("""
   neighbor $neighborip peer group spines""").safe_substitute(Replacements)
					leaf_bgp_config = leaf_bgp_config + add_to_leaf_bgp_config

				if deploymenttype == "evpn":
					Replacements = {
									"neighborip": linknetwork + str(int(interface['neighbor_int']) -1)
					}
					add_to_leaf_bgp_config = Template("""
   neighbor $neighborip peer group spines""").safe_substitute(Replacements)
					leaf_bgp_config = leaf_bgp_config + add_to_leaf_bgp_config
					
	if deploymenttype == "evpn":
		for evpnleaf in DC:
			Replacements = {
							"loopback": evpnleaf['loopback'],
							"asn": spine_start_asn
							}
			add_to_leaf_bgp_config = Template("""
   neighbor $loopback peer group EVPN
   neighbor $loopback remote-as $asn""").safe_substitute(Replacements)
			leaf_bgp_config = leaf_bgp_config + add_to_leaf_bgp_config

	if deploymenttype == "evpn":
	
		add_to_leaf_bgp_config = """
   address-family evpn"""
		leaf_bgp_config = leaf_bgp_config + add_to_leaf_bgp_config

	if deploymenttype == "evpn":
		for evpnleaf in DC:
			Replacements = {
							"loopback": evpnleaf['loopback'],
							"asn": spine_start_asn
							}
			add_to_leaf_bgp_config = Template("""
      neighbor $loopback activate""").safe_substitute(Replacements)
			leaf_bgp_config = leaf_bgp_config + add_to_leaf_bgp_config

	if deploymenttype == "evpn":
		add_to_leaf_bgp_config = """
   address-family ipv4"""
		leaf_bgp_config = leaf_bgp_config + add_to_leaf_bgp_config
		for evpnleaf in DC:
			Replacements = {
							"loopback": evpnleaf['loopback'],
							"asn": spine_start_asn
							}
			add_to_leaf_bgp_config = Template("""
      no neighbor $loopback activate""").safe_substitute(Replacements)
			leaf_bgp_config = leaf_bgp_config + add_to_leaf_bgp_config

	if deploymenttype == "evpn":
		add_to_leaf_bgp_config = """
      redistribute connected"""
		leaf_bgp_config = leaf_bgp_config + add_to_leaf_bgp_config

#
# If debug is activated, only print config that should have gone into configlets,
# do not actually create configlets. If debug is not activated, create configlets
# and add them to CVP.
#

	leaf_configlet_name = leaf['name'] + " configuration"
	if rebuild == 1:
		updateMyConfiglet ( server , leaf_configlet_name , leaf_config )
	else:
		leaf_configlet = cvp.Configlet( leaf_configlet_name , leaf_config )
		server.addConfiglet( leaf_configlet )
		
	leaf_bgp_configlet_name = leaf['name'] + " bgp configuration"
	if rebuild == 1:
		updateMyConfiglet ( server , leaf_bgp_configlet_name , leaf_bgp_config )
	else:
		leaf_bgp_configlet = cvp.Configlet( leaf_bgp_configlet_name , leaf_bgp_config )
		server.addConfiglet( leaf_bgp_configlet )
		





#
# If debug is not activated, create Container structure for new DC
#

if rebuild == 0:
	my_dc_container = cvp.Container( name, parentName )
	server.addContainer( my_dc_container )
	server.mapConfigletToContainer( my_dc_container , configlet_list )
	if deploymenttype == "cvx":
	  server.mapConfigletToContainer( my_dc_container , cvx_configlet_list )

	my_leaf_container = cvp.Container( my_leaf_container_name , name )
	server.addContainer( my_leaf_container )
	leaf_configlet_list.append( vxlan_configlet )
	server.mapConfigletToContainer( my_leaf_container , leaf_configlet_list )

	my_spine_container = cvp.Container( my_spine_container_name , name )
	server.addContainer( my_spine_container )
