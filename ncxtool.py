#!/usr/bin/env python

__version__ = '0.1.2'

import argparse
import logging
import requests
import json
import time
import sys
import uuid
from functools import partial

class CustomFormatter(logging.Formatter):
    """Logging colored formatter, adapted from https://stackoverflow.com/a/56944256/3638629"""

    grey = '\x1b[38;21m'
    blue = '\x1b[38;5;39m'
    yellow = '\x1b[38;5;226m'
    red = '\x1b[38;5;196m'
    bold_red = '\x1b[31;1m'
    reset = '\x1b[0m'

    def __init__(self, fmt):
        super().__init__()
        self.fmt = fmt
        self.FORMATS = {
            logging.DEBUG: self.grey + self.fmt + self.reset,
            logging.INFO: self.blue + self.fmt + self.reset,
            logging.WARNING: self.yellow + self.fmt + self.reset,
            logging.ERROR: self.red + self.fmt + self.reset,
            logging.CRITICAL: self.bold_red + self.fmt + self.reset
        }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

LOGGER = logging.getLogger()
# Define format for logs
fmt = '%(asctime)s | %(levelname)8s | %(message)s'

# Create stdout handler for logging to the console (logs all five levels)
stdout_handler = logging.StreamHandler()
stdout_handler.setFormatter(CustomFormatter(fmt))

LOGGER.addHandler(stdout_handler)

class Ncm:
    JWT_EXPIRATION = 60 * 15 # 15 minutes
    JWT_FILE = './.ncm_jwt'

    def __init__(self, username, password, stack=""):
        self.username = username
        self.password = password
        self.stack = stack
        
        is_mystack = self._is_mystack(self.stack) if self.stack else False
        if is_mystack:
            self.ncm_auth_url = f'https://accounts-{stack}.ncm.public.aws.cradlepointecm.com'
            self.ncm_api_url = f'https://{stack}.ncm.public.aws.cradlepointecm.com/api/v1'
            self.ncm_api_license_addon_url = f"https://view-layer-solution-{stack}.ncm.public.aws.cradlepointecm.com/api/v1"
            self.ncm_api_networks_url = "https://connectivity-{stack}.ncm.public.aws.cradlepointecm.com/api/internal/v1"
            self.ncm_api_policy_config_url = "https://policy-config-{stack}.ncm.public.aws.cradlepointecm.com/api/internal/v1"
            self.ncm_api_ncx_auth_url = "https://ncx-auth-{stack}.ncm.public.aws.cradlepointecm.com/api/internal/v1"
            self.jwt_key = 'jwt'
            self.jwt_auth = ''
        else:
            self.ncm_auth_url = f"https://accounts{'-' + stack if stack else ''}.cradlepointecm.com"
            self.ncm_api_url = f"https://{stack if stack else 'www'}.cradlepointecm.com/api/v1"
            self.ncm_api_license_addon_url = f"https://view-layer-solution{'-' + stack if stack else ''}.cradlepointecm.com/api/v1"
            self.ncm_api_networks_url = f"https://connectivity{'-' + stack if stack else ''}.cradlepointecm.com/api/internal/v1"
            self.ncm_api_policy_config_url = f"https://policy-config{'-' + stack if stack else ''}.cradlepointecm.com/api/internal/v1"
            self.ncm_api_ncx_auth_url = f"https://ncx-auth{'-' + stack if stack else ''}.cradlepointecm.com/api/internal/v1"
            self.jwt_key = 'cpAccountsJwt'
            self.jwt_auth = 'cpAuthJwt'

        self.session = requests.Session()
        self.session.headers.update({'Content-Type': 'application/vnd.api+json'})
        jwt = self._get_jwt()
        self.ncm_api_account = self._get_accountId()
        self.ncm_tenant_id = self._get_tenantId()
        # self.ncm_api_account = 113114
        # self.ncm_tenant_id = "0016u00000FVFEp"
    
    def get_jwt(self):
        return self._get_jwt()

    def license(self, nce_macs):
        params = {'parentAccount': self.ncm_api_account, 'accountId': self.ncm_api_account}

        add_on_lst = ["NCX-SCM", "NCX-SDWAN"]
        #Netcloud Exchange Secure Connect - Medium site add-on license and NetCloud Exchange SD-WAN
        for nce_mac in nce_macs:
            for add_on in add_on_lst:
                payload = {
                    "data": {
                        "attributes" : {
                            "tenantId" : self.ncm_tenant_id,
                            "productName" : "3200v",
                            "ncmAccountList" : [],
                            "groupList" : [],
                            "includedMacList" : [nce_mac],
                            "regradeOperation" : "UPGRADE",
                            "status" : None,
                            "message" : None,
                            "createdDate" : None,
                            "eligibilityCheck" : False,
                            "totalDeviceCount" : None,
                            "subRelationshipConfigId" : add_on
                        },
                        "type" : "bulkRegradeTasks"
                    }
                }

                r = self.session.post(self.ncm_api_license_addon_url + '/tasks/bulkRegrade', params=params, json=payload)
                LOGGER.debug(f"License add request response json for mac {nce_mac}......{r.json()}")
                if not r.ok:
                    LOGGER.info(f"Failed to add ncx license at Post stage for NCE with mac {nce_mac} {r.status_code} {r.text}")
                    return False
                addon_id = r.json().get("data").get("id")
                options_req = self.session.options(self.ncm_api_license_addon_url + '/tasks/bulkRegrade/%s'%addon_id, params=params)
                if not options_req.ok:
                    LOGGER.info(f"Failed to add ncx license at Options stage for NCE with mac {nce_mac} {options_req.status_code} {options_req.text}")
                    return False
        return True

    def get_network(self):
        # networks
        r = self.session.get(self.ncm_api_networks_url + '/networks')
        rval = None
        nid =''
        for net in r.json()["data"]:
            if net["type"] == "networks":
                rval = net
                nid = str(net["id"])
                LOGGER.info(net)

        if nid == '':
            LOGGER.info("No network present")
            return
        
        return rval
    
    def get_network_id(self):
        net = self.get_network()
        if net:
            return str(net['id'])

    def create_network(self, network_name="Default Network Name", primary_id=None, secondary_id=None, primary_ip=None, secondary_ip=None):
        device_ids = []
        hub_ids= [primary_id]
        if secondary_id:
            hub_ids.append(secondary_id)
        device_ids.append(hub_ids)
        
        hosts = []
        hub_ips = [primary_ip]
        if secondary_ip:
            hub_ips.append(secondary_ip)
        hosts.append(hub_ips)

        params = {'parentAccount': self.ncm_api_account, 'tenantId' : self.ncm_tenant_id}
        data = {
            'data': {
                'attributes': {
                    'tenant_id' : None,
                    'account_id' : None,
                    'name' : network_name,
                    'ncx': {
                        'device_ids' : device_ids,
                        'hosts' : hosts,
                        'management_ips': []
                     },
                    'primary_dns': "8.8.8.8",
                    'secondary_dns': "8.8.4.4",
                    'ha_mode': None,
                    "private_virtual_ip": None,
                    "public_virtual_ip": None,
                    'createdAt': None,
                    'updatedAt': None,
                    'state': None
                },
                'type': 'networks'
            }
        }
        LOGGER.info("NETWORK:")
        LOGGER.info(data)
        r = self.session.post(self.ncm_api_networks_url + '/networks', params=params, json=data)
        if not r.ok:
            LOGGER.info("Failed to create a network (%s) %s", r.status_code, r.text)
            return 
        rjson = r.json()
        try:
            nid = str(rjson['data']['id'])
        except KeyError:
            LOGGER.error('Failed to get network id %s', r.text)
            return 
        
        self.deploy_network(nid)

        return nid

    def deploy_network(self, nid=None):
        if not nid:
            LOGGER.info("NID empty")
            nid = self.get_network_id()
            if not nid:
                raise Exception("No network found")

        r = self.session.post(self.ncm_api_networks_url + '/networks/%s/deploy?parentAccount=%s&tenantId=%s'%(nid, self.ncm_api_account, self.ncm_tenant_id))
        errors = []
        if not r.ok:
            LOGGER.error("Failed to post deploy network")
            errors.append(r.status_code)
        try:
            LOGGER.info(r.json())
            state = r.json()['data']['attributes']['state']
            if state != "DEPLOYED":
                LOGGER.error("State is not DEPLOYED")
                errors.append(state)
        except KeyError as Argument:
            LOGGER.error("Failed to deploy network")
            errors.append(str(Argument))
        return errors

    def delete_network(self, nid=None):
        if not nid:
            LOGGER.info("NID empty")
            nid = self.get_network_id()
            if not nid:
                raise Exception("No network found")

        LOGGER.info("Deleting network id %s", nid )
        r = self.session.delete(self.ncm_api_networks_url + '/networks/%s' % nid)
        if not r.ok:
            LOGGER.error(" Error attempting to delete network%s (%s) %s", nid, r.status_code, r.text)
            return False
        else:
            LOGGER.info("Network deleted %s", nid)
        return True

    def add_sites(self, site_name_pfx, rtr_ids, nid=None):
        if not nid:
            LOGGER.info("NID empty")
            nid = self.get_network_id()
            if not nid:
                raise Exception("No network found")

        site_ids = []
        for i, rtr_id in enumerate(rtr_ids):
            if i == 0:
                site_name = site_name_pfx
            else:
                site_name = f"{site_name_pfx}{i}"
            site_ids.append(self.add_single_site(nid=nid, site_name=site_name, rtr_id=rtr_id))

        self.deploy_network(nid)
    
        return site_ids


    def add_single_site(self, nid=None, site_name=None, rtr_id=None):
        if not nid:
            LOGGER.info("NID empty")
            nid = self.get_network_id()
            if not nid:
                raise Exception("No network found")

        device_ids = [rtr_id]
        payload = {
                        "data": {
                                "attributes": {
                                        "tenant_id": None,
                                        "account_id": None,
                                        "name": site_name,
                                        "device_ids": device_ids,
                                        "created_at": None,
                                        "updated_at": None
                                },
                                "relationships": {
                                        "network": {
                                                "data": {
                                                        "type": "networks",
                                                        "id": nid
                                                }
                                        }
                                },
                                "type": "sites"
                        }
                }

        LOGGER.info(payload)

        r = self.session.post(self.ncm_api_networks_url + '/sites?parentAccount=%s&tenantId=%s'%(self.ncm_api_account, self.ncm_tenant_id), json=payload)
        if not r.ok:
            LOGGER.error("Failed to add a site (%s) for %s %s", r.status_code, site_name, r.text)
            raise Exception("Failed to add a site (%s) for %s", r.status_code, site_name)
        try:
            siteid = r.json()['data']['id']
            LOGGER.info("Site Id - %s added", siteid)
        except KeyError:
            LOGGER.error('Failed to get network id %s', r.text)
            raise

        return siteid

    def delete_single_site(self, siteid):
        params = {'parentAccount': self.ncm_api_account, 'tenantId' : self.ncm_tenant_id}
        r = self.session.delete(self.ncm_api_networks_url + '/sites/%s'%siteid, params=params)
        if not r.ok:
            LOGGER.error("Failed to delete site (%s) for %s", r.status_code, siteid)
            raise Exception("Failed to delete site (%s) for %s", r.status_code, siteid)
        
        self.deploy_network()

    def get_sites(self, nid=None):
        if not nid:
            LOGGER.info("NID empty")
            nid = self.get_network_id()
            if not nid:
                raise Exception("No network found")

        params = {'filter[network_id]':nid, 'parentAccount': self.ncm_api_account, 'tenantId' : self.ncm_tenant_id}
        r = self.session.get(self.ncm_api_networks_url + '/sites', params=params)
        return r.json()['data']

    def delete_site_resources(self, site_id, nid=None):
        if not nid:
            LOGGER.info("NID empty")
            nid = self.get_network_id()
            if not nid:
                raise Exception("No network found")

        #Get site details
        params = {'filter[site_id]':site_id, 'parentAccount': self.ncm_api_account, 'tenantId' : self.ncm_tenant_id}
        r = self.session.get(self.ncm_api_policy_config_url+'/resources', params=params)
        if not r.ok:
            LOGGER.error("Failed to get site details (%s).....(%s)", r.status_code, r.json())
            raise Exception("Failed to get site details (%s).....(%s)", r.status_code, r.json())

        for resource in r.json().get("data", []):
            resource_id = resource.get("id")

            self.delete_resource(resource_id, nid=nid)
            LOGGER.info('Resource deleted from site site%s', site_id)
        return True

    def delete_resource(self, resource_id, nid=None):
        if not nid:
            LOGGER.info("NID empty")
            nid = self.get_network_id()
            if not nid:
                raise Exception("No network found")

        #Delete resource
        params = {'filter[network_id]':nid, 'parentAccount':self.ncm_api_account, 'tenantId':self.ncm_tenant_id}

        r = self.session.delete(self.ncm_api_policy_config_url+'/resources/%s'%resource_id, params=params)
        if not r.ok:
            LOGGER.error("Failed to delete resource (%s) for %s", r.status_code, resource_id)
            raise Exception("Failed to delete resource (%s) for %s", r.status_code, resource_id)

    def delete_all_resources(self, nid=None):
        if not nid:
            LOGGER.info("NID empty")
            nid = self.get_network_id()
            if not nid:
                raise Exception("No network found")

        params = {'filter[network_id]':nid, 'parentAccount': self.ncm_api_account, 'tenantId' : self.ncm_tenant_id}
        r = requests.get(self.ncm_api_networks_url + '/sites', params=params)

        for net in r.json()["data"]:
            if net["type"] == "sites" and net["attributes"]["name"] != "External Resources" and net["attributes"]["name"] != "Internal Resources":
                self.delete_site_resources(site_id=net["id"], nid=nid)

    def get_resources(self, sids=None, nid=None):
        if not nid:
            LOGGER.info("NID empty")
            nid = self.get_network_id()
            if not nid:
                raise Exception("No network found")

        params = {'parentAccount': self.ncm_api_account, 'tenantId' : self.ncm_tenant_id, 'filter[network_id]':nid, "resource_template[is_null]":True, "page[size]":500}
        if sids:
            params['filter[site_id]'] = ",".join(sids)
        r = self.session.get(self.ncm_api_policy_config_url+'/resources', params=params)
        if not r.ok:
            LOGGER.error("Failed to get site details (%s).....(%s)", r.status_code, r.json())
            raise Exception("Failed to get site details (%s).....(%s)", r.status_code, r.json())

        return r.json().get("data", [])

    def add_resource(self, site_id, resource_name, resource_type, resource_protocols, resource_port_ranges, resource_ip, resource_domain, nid=None):
        if not nid:
            LOGGER.info("NID empty")
            nid = self.get_network_id()
            if not nid:
                raise Exception("No network found")
        
        def port_ranges(pr):
            if not pr: return None
            rval = []
            for p in pr.split(','):
                if '-' in p:
                    rval.append({"lower_limit": int(p.split('-')[0]), "upper_limit": int(p.split('-')[1])})
                else:
                    rval.append({"lower_limit": int(p), "upper_limit": int(p)})
            return rval

        params = {'filter[site_id]':site_id, 'parentAccount':self.ncm_api_account, 'tenantId':self.ncm_tenant_id}
        data = {"data":
                {"attributes":
                 {"protocols":resource_protocols.split(',') if resource_protocols else None,
                  "port_ranges":port_ranges(resource_port_ranges),
                  "domain":resource_domain,
                  "ip":resource_ip,
                  "name":resource_name,
                  "tags":[],
                  "site_id":site_id,
                  "network_id":nid},
                "type":resource_type}}
        LOGGER.info("Adding resource: %s", data)
        r = self.session.post(self.ncm_api_policy_config_url+'/resources', params=params, json=data)
        if not r.ok:
            LOGGER.error("Failed to add resource (%s) (%s)", r.status_code, r.json())
            raise Exception("Failed to add resource (%s) (%s)", r.status_code, r.json())
    
        return r.json().get("data", [])
    
    def get_policies(self, nid=None):
        if not nid:
            LOGGER.info("NID empty")
            nid = self.get_network_id()
            if not nid:
                raise Exception("No network found")

        params = {"filter[network_id]":nid, 
                  "filter[type]": "access_control_policies",
                  "include": "rules,rules.criteria",
                  "page[size]": 500,
                  "parentAccount": self.ncm_api_account, 
                  "tenantId" : self.ncm_tenant_id,
                  }
        r = self.session.get(self.ncm_api_policy_config_url+'/policies', params=params)
        if not r.ok:
            LOGGER.error("Failed to get policies (%s).....(%s)", r.status_code, r.json())
            raise Exception("Failed to get policies (%s).....(%s)", r.status_code, r.json())

        return r.json()

    def add_policy(self, name="default", allow=False, from_site_ids=None, site_ips=None, user_attribute_id=None, user_attributes=None, to_site_ids=None, to_named_resources=None, order='after', nid=None):
        if not nid:
            LOGGER.info("NID empty")
            nid = self.get_network_id()
            if not nid:
                raise Exception("No network found")
            
        # get the current policies, if one exists, we will do a put to update it, if none exists we need to do a post
        policies = self.get_policies(nid=nid)
        new_policy_rule = partial(self.new_policy_rule, name=name, allow=allow, from_site_ids=from_site_ids, site_ips=site_ips, user_attribute_id=user_attribute_id, user_attributes=user_attributes, to_site_ids=to_site_ids, to_named_resources=to_named_resources, order=order, nid=nid)
        if not policies.get("data") or []:
            policy = new_policy_rule(policy=None)
            LOGGER.info("Creating policy: %s", json.dumps(policy))
            r = self.create_new_policy(policy=policy)
        else:
            policy = {"data": policies['data'][0], "included":policies.get('included') or []}
            policy = new_policy_rule(policy=policy)
            LOGGER.info("Updating policy: %s", json.dumps(policy))
            r = self.update_existing_policy(policy=policy)

        return r

    def delete_policies(self, policy_ids=None, nid=None):
        if not nid:
            LOGGER.info("NID empty")
            nid = self.get_network_id()
            if not nid:
                raise Exception("No network found")

        if not policy_ids:
            policies = self.get_policies(nid=nid)
            policy_ids = [p['id'] for p in policies['data']]
        
        for policy_id in policy_ids:
            LOGGER.info("Deleting policy: %s", policy_id)
            self.session.delete(self.ncm_api_policy_config_url+'/policies/'+policy_id)

    def update_existing_policy(self, policy):
        """Update an existing policy using PUT given the correct payload"""
        acp_uuid = policy['data']['id']
        r = self.session.put(self.ncm_api_policy_config_url+'/policies/'+acp_uuid, json=policy)
        return r.json()

    def create_new_policy(self, policy):
        """Create a new policy using POST given the correct payload"""
        r = self.session.post(self.ncm_api_policy_config_url+'/policies', json=policy)
        return r.json()

    def new_policy_rule(self, policy=None, name="default", allow=False, from_site_ids=None, site_ips=None, user_attribute_id=None, user_attributes=None, to_site_ids=None, to_named_resources=None, order='after', nid=None):
        if not policy:
            acp_uuid = f"GEN-ID-{uuid.uuid4()}"
            policy = {
                "data": {
                    "id": acp_uuid,
                    "attributes": {
                        "name": "organization-policy",
                        "scope_target": "ORGANIZATION",
                        "scope_target_id": None,
                        "network_id": f"{nid}"
                    },
                    "relationships": {
                        "rules": {
                            "data": []
                        }
                    },
                    "type": "access_control_policies"
                },
                "included": []
            }
            order = 1
        else:
            acp_uuid = policy['data']['id']
            if order == "after":
                order = 0
                for r in (_ for _ in policy['included'] if _['type'] == "access_control_rules"):
                    if r['attributes']['order'] > order:
                        order = r['attributes']['order']
                order += 1
            elif order == "before":
                order = 1
                for r in (_ for _ in policy['included'] if _['type'] == "access_control_rules"):
                    r['attributes']['order'] += 1
            else:
                order = int(order)

        acr_uuid = uuid.uuid4()

        policy['data']['relationships']['rules']['data'].append({"type": "access_control_rules", "id": f"GEN-ID-{acr_uuid}"})
        policy_included = {
                    "id": f"GEN-ID-{acr_uuid}",
                    "attributes": {
                        "allow": allow,
                        "log": False,
                        "ips_ids_inspection": False,
                        "name": name,
                        "order": order
                    },
                    "relationships": {
                        "policy": {
                        "data": {
                            "type": "access_control_policies",
                            "id": acp_uuid
                        }
                        }
                    },
                    "type": "access_control_rules"
                    }
        policy['included'].append(policy_included)
        
        if from_site_ids and not site_ips:
            fsi_uuid = uuid.uuid4()
            criteria = policy_included["relationships"].get("criteria", {"data": []})
            criteria["data"].append({"type": "site_criteria", "id": f"GEN-ID-{fsi_uuid}"})
            policy_included["relationships"]["criteria"] = criteria
            policy["included"].append({
                "id": f"GEN-ID-{fsi_uuid}",
                "attributes": {
                    "site_ids": from_site_ids,
                    "rule_section": "FROM",
                    "operator": "IN"
                },
                "relationships": {
                    "rule": {
                    "data": {
                        "type": "access_control_rules",
                        "id": f"GEN-ID-{acr_uuid}"
                    }
                    }
                },
                "type": "site_criteria"
            })
        
        if from_site_ids and site_ips:
            si_uuid = uuid.uuid4()
            criteria = policy_included["relationships"].get("criteria", {"data": []})
            criteria["data"].append({"type": "siteip_criteria", "id": f"GEN-ID-{si_uuid}"})
            policy_included["relationships"]["criteria"] = criteria
            policy["included"].append({
                "id": f"GEN-ID-{si_uuid}",
                "attributes": {
                    "ips": site_ips,
                    "site_id": from_site_ids[0],
                    "rule_section": "FROM",
                    "operator": "IN"
                },
                "relationships": {
                    "rule": {
                    "data": {
                        "type": "access_control_rules",
                        "id": f"GEN-ID-{acr_uuid}"
                    }
                    }
                },
                "type": "siteip_criteria"
            })

        if user_attribute_id and user_attributes:
            uai_uuid = uuid.uuid4()
            criteria = policy_included["relationships"].get("criteria", {"data": []})
            criteria["data"].append({"type": "user_attribute_criteria", "id": f"GEN-ID-{uai_uuid}"})
            policy_included["relationships"]["criteria"] = criteria
            policy["included"].append({
                "id": f"GEN-ID-{uai_uuid}",
                "attributes": {
                    "user_attribute_id": user_attribute_id,
                    "values": user_attributes,
                    "rule_section": "FROM",
                    "operator": "IN"
                },
                "relationships": {
                    "rule": {
                    "data": {
                        "type": "access_control_rules",
                        "id": f"GEN-ID-{acr_uuid}"
                    }
                    }
                },
                "type": "user_attribute_criteria"
                })

        if to_site_ids:
            tsi_uuid = uuid.uuid4()
            criteria = policy_included["relationships"].get("criteria", {"data": []})
            criteria["data"].append({"type": "site_criteria", "id": f"GEN-ID-{tsi_uuid}"})
            policy_included["relationships"]["criteria"] = criteria
            policy["included"].append({
                "id": f"GEN-ID-{tsi_uuid}",
                "attributes": {
                    "site_ids": to_site_ids,
                    "rule_section": "TO",
                    "operator": "IN"
                },
                "relationships": {
                    "rule": {
                    "data": {
                        "type": "access_control_rules",
                        "id": f"GEN-ID-{acr_uuid}"
                    }
                    }
                },
                "type": "site_criteria"
            })
        
        if to_named_resources:
            tnr_uuid = uuid.uuid4()
            criteria = policy_included["relationships"].get("criteria", {"data": []})
            criteria["data"].append({"type": "named_resource_criteria", "id": f"GEN-ID-{tnr_uuid}"})
            policy_included["relationships"]["criteria"] = criteria
            policy["included"].append(    {
                "id": f"GEN-ID-{tnr_uuid}",
                "attributes": {
                    "resource_ids": to_named_resources,
                    "rule_section": "TO",
                    "operator": "IN"
                },
                "relationships": {
                    "rule": {
                    "data": {
                        "type": "access_control_rules",
                        "id": f"GEN-ID-{acr_uuid}"
                    }
                    }
                },
                "type": "named_resource_criteria"
            })

        return policy

    def delete_policy_rule(self, policy_rule_id, nid=None):
        if not nid:
            nid = self.get_network_id()
            if not nid:
                raise Exception("No network found")
        
        policies = self.get_policies(nid=nid)
        if policies.get("data", []):
            policy = {"data": policies['data'][0], "included": policies['included']}
            new_relationships = [_ for _ in policy['data']['relationships']['rules']['data'] if _['id'] != policy_rule_id]
            policy['data']['relationships']['rules']['data'] = new_relationships
            policy_id = policy['data']['id']
        
            rule = next((_ for _ in policy['included'] if _['id'] == policy_rule_id))
            if rule:
                order = rule['attributes']['order']
                excludes = [_['id'] for _ in rule['relationships']['criteria']['data']] + [policy_rule_id]
                new_includes = []
                for e in (_ for _ in policy['included'] if _['id'] not in excludes):
                    if e['type'] == "access_control_rules" and e['attributes']['order'] > order:
                        e['attributes']['order'] -= 1
                    new_includes.append(e)
                policy['included'] = new_includes
                r = self.session.put(self.ncm_api_policy_config_url+'/policies/'+policy_id, json=policy)
                return r.json()

    def get_user_attributes(self, nid=None):
        if not nid:
            LOGGER.info("NID empty")
            nid = self.get_network_id()
            if not nid:
                raise Exception("No network found")
        params = {'filter[network_id]':nid, 'parentAccount': self.ncm_api_account, 'tenantId' : self.ncm_tenant_id}
        r = self.session.get(self.ncm_api_ncx_auth_url+'/user_attributes', params=params)
        return r.json().get('data', [])

    def _is_mystack(self, stack):
        ncm_auth_url = 'https://accounts-' + stack +'.ncm.public.aws.cradlepointecm.com'
        try:
            r = requests.get(ncm_auth_url + '/api/v1/version')
        except requests.exceptions.ConnectionError:
            return False
        if not r.ok:
            return False
        return True

    def _get_jwt(self):
        jwt_from_file = self._load_jwt_from_file()
        if jwt_from_file:
            self.session.cookies.set(self.jwt_key, jwt_from_file)
            return jwt_from_file
        #API1 - Login
        data = {
            "data": {
                "type": "login",
                "attributes": {
                    "email": self.username,
                    "password": self.password
                }
            }                
        }

        r1 = self.session.post(self.ncm_auth_url + '/api/internal/v1/users/login', json=data)
        LOGGER.info(f"r1: {r1.json()}")
        if not r1.ok: 
            LOGGER.info("Failed to login %s %s", r1.status_code, r1.text)
            return
        try:
            mfa_prompt = r1.json()['data']['attributes']['result'] == "MFA_PROMPT"
        except KeyError:
            mfa_prompt = False
        if mfa_prompt:
            LOGGER.info("Prompt for MFA code")
            print("Input MFA code:", file=sys.stderr)
            mfa = input()
            sid = r1.json()['data']['id']
            token = r1.json()['data']['attributes']['token']
            auth_header = {"Authorization": f"Bearer {token}"}
            mfa1 = self.session.post(self.ncm_auth_url + '/api/internal/v1/users/validateMfa', json={"data": {"id": f"{sid}", "type": "login", "attributes": {"mfaToken": f"{mfa}"}}}, headers=auth_header)
            LOGGER.info(f"MFA: {mfa1.json()}")
            r1 = mfa1
        try:
            state = r1.json()['data']['attributes']['state']
            token = r1.json()['data']['attributes']['token']
        except KeyError:
            LOGGER.error("Failed to get the state and token")
            return

        #API2 - Authorize
        params = {'state': state, 'redirect_url': self.ncm_auth_url}
        r2 = self.session.get(self.ncm_auth_url + '/api/internal/v1/users/oidc_authorize', params=params, allow_redirects=False)
       
        loc = ''
        hdr = r2.headers
        loc = hdr.get('location')
        if not r2.ok:
            LOGGER.error('Failed to get Jwt Authorization: (%s) %s', r2.status_code, r2.text)
            return
        LOGGER.info("Got Jwt Authorization")

        #API3 - Callback
        url3 = loc
        r3 = self.session.get(url3, data=data, allow_redirects=False)
        if not r3.ok:
            LOGGER.error('Failed to get Jwt key: (%s) %s', r3.status_code, r3.text)
            return
        LOGGER.info("Got Jwt key")

        try:
            curr_jwt = r3.cookies[self.jwt_key]
        except KeyError:
            LOGGER.error('Jwt key not in cookies %s', r3.cookies)
            return
        self._save_jwt_to_file(curr_jwt)
        return curr_jwt

    def _load_jwt_from_file(self):
        try:
            with open(self.JWT_FILE) as f:
                jwt = f.read()
        except FileNotFoundError:
            return
        if jwt:
            jwt = json.loads(jwt)
            if time.time() > (jwt.get('ts') + self.JWT_EXPIRATION):
                LOGGER.info('JWT from file reached expiration')
                return
            return jwt.get('jwt')
    
    def _save_jwt_to_file(self, jwt):
        with open(self.JWT_FILE, 'w') as f:
            f.write(json.dumps({'jwt': jwt, 'ts': time.time()}))

    def _get_accountId(self):
        payload = {'login': self.username, 'password': self.password}
        r = self.session.get(self.ncm_api_url +'/accounts', data=payload)
        if not r.ok:
            LOGGER.error('Failed trying to query accountId (%s) %s', r.status_code, r.text)
            return
        try:
            aid = r.json()['data'][0]['id']
        except KeyError:
            LOGGER.error('Failed to get accountId for %s' % self.username)
            return
        return aid

    def _get_tenantId(self):
        payload = {'login': self.username, 'password': self.password}
        r = self.session.get(self.ncm_api_url + '/customers/?parentAccount=%s' % (self.ncm_api_account), data=payload)
        if not r.ok:
            LOGGER.error('Failed trying to query tenantId (%s) %s', r.status_code, r.text)
            return
        try:
            tid = r.json()['data'][0]['customer_id']
        except (IndexError, KeyError):
            LOGGER.error('Failed to get tenantId for %s' % self.username)
            return
        return tid



if __name__=="__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', action='count', default=0, help="verbosity, -v is warn -vv is info -vvv is debug")
    parser.add_argument('-l', help="NCM login info. Must be in format username:password")
    parser.add_argument('-s', help="mystack namespace or qa4, or pass in '' for prod (default).", default="")
    subparsers = parser.add_subparsers(dest='cmd')

    # parser for jwt command
    parser_jwt = subparsers.add_parser('jwt', help='get a jwt')

    # parser for license command
    parser_lic = subparsers.add_parser('license', help='license mac adders')
    parser_lic.add_argument(dest='macs', nargs='+', help="mac addrs to register")

    # parser for get_network command
    parser_gnet = subparsers.add_parser('get_network', help='get a network')

    # parser for deploy_network command
    parser_dnet = subparsers.add_parser('deploy_network', help='(re)deploy a network')
    parser_dnet.add_argument(dest="network_id", nargs="?")

    # parser for network command
    parser_net = subparsers.add_parser('create_network', help='create a network')
    parser_net.add_argument("--name", dest="name")
    parser_net.add_argument("--primary_id", dest="primary_id", type=int)
    parser_net.add_argument("--secondary_id", dest="secondary_id", nargs="?", type=int)
    parser_net.add_argument("--primary_ip", dest="primary_ip")
    parser_net.add_argument("--secondary_ip", dest="secondary_ip", nargs="?")

    # parser for delete_network command
    parser_delnet = subparsers.add_parser('delete_network', help='delete a network')
    parser_delnet.add_argument(dest="network_id", nargs="?")

    # parser for add site command
    parser_asite = subparsers.add_parser('add_site', help="add a site")
    parser_asite.add_argument("--name", dest="name", help="site name prefix, multiples will append a number to the end")
    parser_asite.add_argument("--router_id", dest="router_id", type=int, nargs="+")
    parser_asite.add_argument("--network_id", dest="network_id", nargs="?")

    # parser for delete_site command
    parser_dsite = subparsers.add_parser('delete_site', help="delete a site")
    parser_dsite.add_argument("--site_id", dest="site_id")

    # parser for get_sites command
    parser_gsite = subparsers.add_parser('get_sites', help="get sites")
    parser_gsite.add_argument(dest='network_id', nargs="?")

    # parser for delete all resources across all sites
    parser_dares = subparsers.add_parser('delete_all_resources', help="delete all resource")
    parser_dares.add_argument(dest="network_id", nargs="?")

    # parser for get resources
    parser_gres = subparsers.add_parser('get_resources', help="get resources")
    parser_gres.add_argument(dest="site_id", nargs="*")
    parser_gres.add_argument(dest="network_id", nargs="?")

    # parser for add resource
    parser_ares = subparsers.add_parser('add_resource', help="add resource")
    parser_ares.add_argument('--site_id', dest="site_id")
    parser_ares.add_argument('--name', dest="name")
    parser_ares.add_argument('--type', dest="type", nargs="?", default="fqdn_resource")
    parser_ares.add_argument('--protocols', dest="protocols", nargs="?", default=None)
    parser_ares.add_argument('--port_ranges', dest="port_ranges", nargs="?", default=None)
    parser_ares.add_argument('--ip', dest="ip", nargs="?", default=None)
    parser_ares.add_argument('--domain',dest="domain", nargs="?", default="example.com")
    # type can be: fqdn_resources, ipsubnet_resource, wildcard_fqdn_resources

    # parser for delete resource
    parser_dres = subparsers.add_parser('delete_resource', help="delete resource")
    parser_dres.add_argument('--resource_id', dest="resource_id")

    # parser for get policies
    parser_gpol = subparsers.add_parser('get_policies', help="get policies")
    parser_gpol.add_argument(dest="network_id", nargs="?")

    # parser for add policy
    parser_apol = subparsers.add_parser('add_policy', help="add policy")
    parser_apol.add_argument('--name', dest="name")
    parser_apol.add_argument('--allow', dest="allow", action="store_true")
    parser_apol.add_argument('--from_site_ids', dest="from_site_ids", nargs="+")
    parser_apol.add_argument('--site_ips', dest="site_ips", nargs="+")
    parser_apol.add_argument('--user_attribute_id', dest="user_attribute_id", nargs="?")
    parser_apol.add_argument('--user_attributes', dest="user_attributes", nargs="+")
    parser_apol.add_argument('--to_site_ids', dest="to_site_ids", nargs="+")
    parser_apol.add_argument('--to_named_resources', dest="to_named_resources", nargs="+")
    parser_apol.add_argument('--order',dest="order", default="after")

    # parser for delete policy
    parser_dpol = subparsers.add_parser('delete_policies', help="delete policies")
    parser_dpol.add_argument(dest="policy_ids", nargs="*")

    # parser for delete policy
    parser_dpolr = subparsers.add_parser('delete_policy_rule', help="delete policy rule")
    parser_dpolr.add_argument(dest="policy_rule_id")

    # parser for get user attributes
    parser_gua = subparsers.add_parser('get_user_attributes', help="get user attributes")
    parser_gua.add_argument(dest="network_id", nargs="?")

    args = parser.parse_args()

    lvl = logging.ERROR
    if args.v == 1: lvl = logging.WARN
    if args.v == 2: lvl = logging.INFO
    if args.v >= 3: lvl = logging.DEBUG
    LOGGER.setLevel(level=lvl)

    username, password = args.l.split(":")
    LOGGER.info(f"Username:{username} Password:{password}")
    ncm = Ncm(username, password, stack=args.s)

    if args.cmd == "jwt":
        print(ncm.get_jwt())
    
    if args.cmd == "license":
        ncm.license(args.macs)
    
    if args.cmd == "get_network":
        print(json.dumps(ncm.get_network()))
    
    if args.cmd == "deploy_network":
        ncm.deploy_network(args.network_id)
    
    if args.cmd == "delete_network":
        ncm.delete_network(args.network_id)

    if args.cmd == "create_network":

        LOGGER.info(f"network_name={args.network_name},primary_id={args.network_primary_id},secondary_id={args.network_secondary_id},primary_ip={args.network_primary_ip},secondary_ip={args.network_secondary_ip}")

        print(ncm.create_network(network_name=args.network_name,
            primary_id=args.network_primary_id,
            secondary_id=args.network_secondary_id,
            primary_ip=args.network_primary_ip,
            secondary_ip=args.network_secondary_ip))
    
    if args.cmd == "add_site":
        LOGGER.info('router ids: %s', args.router_id)
        print(ncm.add_sites(args.site_name, args.router_id, args.network_id))

    if args.cmd == "delete_site":
        ncm.delete_single_site(args.site_id)

    if args.cmd == "get_sites":
        print(json.dumps(ncm.get_sites(nid=args.network_id)))

    if args.cmd == "delete_all_resources":
        ncm.delete_all_resources(nid=args.network_id)

    if args.cmd == "get_resources":
        print(json.dumps(ncm.get_resources(args.site_id, nid=args.network_id)))
    
    if args.cmd == "add_resource":
        print(ncm.add_resource(
            site_id=args.site_id, 
            resource_name=args.name, 
            resource_type=args.type, 
            resource_protocols=args.protocols, 
            resource_port_ranges=args.port_ranges, 
            resource_ip=args.ip,
            resource_domain=args.domain))

    if args.cmd == "delete_resource":
        ncm.delete_resource(args.resource_id)

    if args.cmd == "get_policies":
        print(json.dumps(ncm.get_policies(nid=args.network_id)))
    
    if args.cmd == "add_policy":
        print(json.dumps(ncm.add_policy(
            name=args.name, 
            allow=args.allow, 
            from_site_ids=args.from_site_ids, 
            site_ips=args.site_ips,
            user_attribute_id=args.user_attribute_id,
            user_attributes=args.user_attributes,
            to_site_ids=args.to_site_ids, 
            to_named_resources=args.to_named_resources,
            order=args.order)))
    
    if args.cmd == "delete_policies":
        print(json.dumps(ncm.delete_policies(policy_ids=args.policy_ids)))
    
    if args.cmd == "delete_policy_rule":
        print(json.dumps(ncm.delete_policy_rule(args.policy_rule_id)))
    
    if args.cmd == "get_user_attributes":
        print(json.dumps(ncm.get_user_attributes(nid=args.network_id)))