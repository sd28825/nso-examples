"""
L3VPN Service module - Python implementation of the Java L3VPN service.
"""

import ncs
from network import getIpAddress, getIpPrefix, getNetMask, getNextIPV4Address
from network import prefixToWildcardMask



class ServiceCallbacks(ncs.application.Service):
    """
    Service callback implementation for the L3VPN service.
    """
    
    @ncs.application.Service.create
    def cb_create(self, tctx, root, service, proplist):
        """
        Create callback method.
        This method is called when a service instance is created or updated.
        
        This is the Python equivalent of the Java create method in l3vpnRFS.java.
        """
        self.log.debug("Service ", service)
        
        for device in root.devices.device:
            if not device.capability:
                raise Exception(f"Device {device.name} has no known capabilities, has sync-from been performed?")
        
        topology = root.topology
        
        endpoints = service.endpoint
        
        self.log.debug("Topology ", topology, " endpoints ", endpoints)
        
        pe_template = ncs.template.Template(service)
        ce_template = ncs.template.Template(service)
        qos_template = ncs.template.Template(service)
        qos_pe_template = ncs.template.Template(service)
        qos_prio_template = ncs.template.Template(service)
        qos_pe_prio_template = ncs.template.Template(service)
        acl_template = ncs.template.Template(service)
        class_template = ncs.template.Template(service)
        pe_class_template = ncs.template.Template(service)
        
        for endpoint in endpoints:
            conn = None
            for connection in topology.connection:
                e1_dev = connection.endpoint_1.device
                e2_dev = connection.endpoint_2.device
                ce_name = endpoint.ce_device
                if (e1_dev == ce_name) or (e2_dev == ce_name):
                    conn = connection
                    break
            
            if not conn:
                continue
            
            pe_endpoint = get_connected_endpoint(conn, endpoint.ce_device)
            ce_endpoint = get_my_endpoint(conn, endpoint.ce_device)
            
            tv = ncs.template.Variables()
            tv.add('PE', pe_endpoint.device)
            tv.add('CE', endpoint.ce_device)
            tv.add('CE_AS_NUM', endpoint.as_number)
            tv.add('VLAN_ID', conn.link_vlan)
            tv.add('LINK_PE_ADR', getIpAddress(pe_endpoint.ip_address))
            tv.add('LINK_CE_ADR', getIpAddress(ce_endpoint.ip_address))
            tv.add('LINK_MASK', getNetMask(ce_endpoint.ip_address))
            tv.add('LINK_PREFIX', getIpPrefix(ce_endpoint.ip_address))
            tv.add('PE_INT_NAME', pe_endpoint.interface)
            tv.add('CE_INT_NAME', ce_endpoint.interface)
            tv.add('CE_LOCAL_INT_NAME', endpoint.ce_interface)
            tv.add('LOCAL_CE_ADR', getIpAddress(getNextIPV4Address(endpoint.ip_network)))
            tv.add('LOCAL_CE_NET', getIpAddress(endpoint.ip_network))
            tv.add('CE_MASK', getNetMask(endpoint.ip_network))
            tv.add('BW', endpoint.bandwidth)
            
            pe_template.apply('l3vpn-pe', tv)
            ce_template.apply('l3vpn-ce', tv)
            
            if service.qos.qos_policy:
                qos_class_map = {}
                
                qos_var = ncs.template.Variables()
                qos_var.add('POLICY_NAME', service.qos.qos_policy)
                qos_var.add('CE_INT_NAME', ce_endpoint.interface)
                qos_var.add('PE_INT_NAME', pe_endpoint.interface)
                qos_var.add('VLAN_ID', conn.link_vlan)
                qos_var.add('PE', pe_endpoint.device)
                qos_var.add('CE', endpoint.ce_device)
                
                for qos_policy in root.qos.qos_policy:
                    if qos_policy.name == service.qos.qos_policy:
                        class_counter = 0
                        for policy_class in qos_policy.l3vpn__class:
                            for qos_class in root.qos.qos_class:
                                if qos_class.name == policy_class.qos_class:
                                    if policy_class.qos_class not in qos_class_map:
                                        qos_class_map[policy_class.qos_class] = []
                                    
                                    class_var = ncs.template.Variables(qos_var)
                                    class_var.add('CLASS_NAME', policy_class.qos_class)
                                    class_var.add('CLASS_BW', policy_class.bandwidth_percentage)
                                    class_var.add('CLASS_COUNTER', str(class_counter))
                                    
                                    try:
                                        class_dscp = str(qos_class.dscp_value)
                                        class_var.add('CLASS_DSCP', class_dscp)
                                        
                                        if class_dscp == 'ef' or class_dscp == 'af31':
                                            class_var.add('CLASS_PRIORITY', 'high')
                                        else:
                                            class_var.add('CLASS_PRIORITY', 'low')
                                    except Exception:
                                        class_var.add('CLASS_DSCP', '')
                                        class_var.add('CLASS_PRIORITY', 'low')
                                    
                                    try:
                                        if policy_class.priority:
                                            qos_prio_template.apply('l3vpn-qos-prio', class_var)
                                            qos_pe_prio_template.apply('l3vpn-qos-pe-prio', class_var)
                                        else:
                                            qos_template.apply('l3vpn-qos', class_var)
                                            qos_pe_template.apply('l3vpn-qos-pe', class_var)
                                    except Exception:
                                        qos_template.apply('l3vpn-qos', class_var)
                                        qos_pe_template.apply('l3vpn-qos-pe', class_var)
                                    
                                    pe_class_template.apply('l3vpn-qos-pe-class', class_var)
                                    
                                    for match in qos_class.match_traffic:
                                        qos_class_map[policy_class.qos_class].append(f"GLOBAL-{match.name}")
                                        
                                        acl_var = set_acl_vars(match, "GLOBAL")
                                        acl_var.add('CE', endpoint.ce_device)
                                        acl_template.apply('l3vpn-acl', acl_var)
                                    
                                    class_counter += 1
                
                for match in service.qos.custom_qos_match:
                    name_prefix = service.name
                    
                    if match.qos_class in qos_class_map:
                        qos_class_map[match.qos_class].append(f"{name_prefix}-{match.name}")
                    
                    acl_var = set_acl_vars(match, name_prefix)
                    acl_var.add('CE', endpoint.ce_device)
                    acl_template.apply('l3vpn-acl', acl_var)
                
                for class_name, match_entries in qos_class_map.items():
                    for match_entry in match_entries:
                        class_var = ncs.template.Variables()
                        class_var.add('CLASS_NAME', class_name)
                        class_var.add('MATCH_ENTRY', match_entry)
                        class_var.add('CE', endpoint.ce_device)
                        class_template.apply('l3vpn-qos-class', class_var)


def set_acl_vars(match, name_prefix):
    """
    Set ACL variables for a match rule.
    
    This is the Python equivalent of the Java setAclVars method in l3vpnRFS.java.
    """
    acl_var = ncs.template.Variables()
    
    acl_var.add('ACL_NAME', f"{name_prefix}-{match.name}")
    acl_var.add('PROTOCOL', match.protocol)
    acl_var.add('SOURCE_IP', match.source_ip)
    
    if match.source_ip == 'any':
        acl_var.add('SOURCE_IP_ADR', 'any')
        acl_var.add('SOURCE_WMASK', ' ')  # Note the space here
    else:
        acl_var.add('SOURCE_IP_ADR', getIpAddress(match.source_ip))
        acl_var.add('SOURCE_WMASK', prefixToWildcardMask(getIpPrefix(match.source_ip)))
    
    if match.destination_ip == 'any':
        acl_var.add('DEST_IP_ADR', 'any')
        acl_var.add('DEST_WMASK', ' ')  # Note the space here
    else:
        acl_var.add('DEST_IP_ADR', getIpAddress(match.destination_ip))
        acl_var.add('DEST_WMASK', prefixToWildcardMask(getIpPrefix(match.destination_ip)))
    
    acl_var.add('PORT_START', match.port_start)
    acl_var.add('PORT_END', match.port_end)
    
    return acl_var


def get_connected_endpoint(conn, device_name):
    """
    Get the endpoint connected to the specified device.
    
    This is the Python equivalent of the Java getConnectedEndpoint method in l3vpnRFS.java.
    """
    if device_name == conn.endpoint_1.device:
        return conn.endpoint_2
    else:
        return conn.endpoint_1


def get_my_endpoint(conn, device_name):
    """
    Get the endpoint for the specified device.
    
    This is the Python equivalent of the Java getMyEndpoint method in l3vpnRFS.java.
    """
    if device_name == conn.endpoint_1.device:
        return conn.endpoint_1
    else:
        return conn.endpoint_2



class Service(ncs.application.Application):
    """
    Main application class for the L3VPN service.
    """
    
    def setup(self):
        """
        Set up the service application.
        """
        self.log.info('L3VPN Service RUNNING')
        
        self.register_service('l3vpn-servicepoint', ServiceCallbacks)
    
    def teardown(self):
        """
        Clean up when the application is shut down.
        """
        self.log.info('L3VPN Service FINISHED')
