# ncxtool

## Overview
'ncxtool' is a custom python library that leverages Cradlepoint's NetCloud Manager (NCM) APIs to perform a variety of tasks related to network management. Using this library, user can handle various operations such as creating, deleting networks, managing nodes in the network etc.

Some of the functionalities provided by 'ncxtool' are:
- Create a network
- Deploy a network
- Delete network
- Add, delete & fetch Sites
- Add, delete & fetch Resources
- Add, delete & fetch Policies
- Get user attributes

Below are examples showing how to use the 'ncxtool' library.

## Library Initialization
To start using the library, an instance of the Ncm class should be created. This will trigger an authentication process validating the provided credentials.

```python
from ncxtool import Ncm

ncm = Ncm('username', 'password')
```

## Creating a Network
Use the `create_network` method to create a new network. The method requires a network name and also optionally accepts a primary and a secondary id as well as IP address. The method returns the id of the created network.

```python
network_id = ncm.create_network(network_name="My Test Network", primary_id='1234567890', secondary_id='0987654321')
```

## Deleting a Network
The `delete_network` method can be used to delete a network. It does not require any parameters and will delete the currently initialized network. The method returns a boolean indicating whether the deletion was successful or not.

```python
ncm.delete_network()
```

## Fetching a Network
You can fetch a network using `get_network` method.

```python
ncm.get_network()
```

## Adding a Site
Use the `add_single_site` method to add a new site to a network.

```python
ncm.add_single_site(site_name="My Site", rtr_id='1234567890')
```

## Deleting a Site
The `delete_single_site` method can be used to delete a site from the current network.

```python
ncm.delete_single_site(site_id)
```

## Fetching All Sites
You can fetch all sites of current network using `get_sites` method.

```python
ncm.get_sites()
```

## Adding a Resource
Use the `add_resource` method to add a new resource to a network site.

```python
ncm.add_resource(site_id='site_id', resource_name="My Resource", resource_type='type', resource_protocols='protocols', resource_port_ranges='port_ranges', resource_ip='1.1.1.1', resource_domain='domain')
```

## Deleting a Resource
The `delete_resource` method can be used to delete a resource from the current network site.

```python
ncm.delete_resource(resource_id)
```

## Fetching All Resources
You can fetch all resources of current network using `get_resources` method.

```python
ncm.get_resources()
```

## Fetching a User Attributes
You can fetch a user attributes using `get_user_attributes` method.

```python
ncm.get_user_attributes()
```

## Adding a Policy
You can add a new policy to a network using `add_policy` method.

```python
ncm.add_policy(name="policy1", allow=True, from_site_ids=["site1"], site_ips=["1.1.1.1"], user_attribute_id="attribute_id", user_attributes=["attribute1"], to_site_ids=["site2"], to_named_resources=["resource1"])
```

## Deleting a Policy
You can delete a policy from a network using `delete_policy_rule` method.

```python
ncm.delete_policy_rule(policy_rule_id)
```

## Fetching All Policies
You can fetch all policies of current network using `get_policies` method.

```python
ncm.get_policies()
```

## Note
This library assumes that requests module is available in your Python environment. To install requests, simply use pip:

```sh
pip install requests
```