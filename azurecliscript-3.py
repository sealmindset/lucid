#!/usr/bin/env python

# Instructions:
#     1. Install Python 3 https://realpython.com/installing-python
#     2. Install the Azure CLI https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest
#     3. Download requirements.txt
#     4. Run 'pip3 install -r requirements.txt'
#     5. If you are retrieving Azure Government Cloud run
#        'az cloud set --name AzureUSGovernment'
#        Otherwise  run
#        'az cloud set --name AzureCloud'
#     6. Run 'az login'
#       - The token that is stored from this gives access to the Active Directory.
#         If you would like to import a different directory please switch the Active Directory in the
#         Azure Portal and re-run 'az login'
#     7. Run this python script 'python3 azurecliscript.py' which will produce an azure.json file
#     8. Upload the azure.json output file into the product

from azure.identity import AzureCliCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.rdbms.postgresql import PostgreSQLManagementClient
from azure.mgmt.rdbms.mysql import MySQLManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.frontdoor import FrontDoorManagementClient
from azure.mgmt.web import WebSiteManagementClient
from azure.mgmt.trafficmanager import TrafficManagerManagementClient
from azure.mgmt.cosmosdb import CosmosDBManagementClient
from azure.mgmt.dns import DnsManagementClient
from azure.mgmt.privatedns import PrivateDnsManagementClient
from azure.mgmt.apimanagement import ApiManagementClient
from azure.mgmt.servicebus import ServiceBusManagementClient
from azure.mgmt.databricks import DatabricksClient
from azure.mgmt.msi import ManagedServiceIdentityClient
from azure.mgmt.iothub import IotHubClient
from azure.mgmt.cdn import CdnManagementClient
from azure.mgmt.redis import RedisManagementClient
from azure.mgmt.hdinsight import HDInsightManagementClient
from azure.mgmt.datafactory import DataFactoryManagementClient
from azure.mgmt.loganalytics import LogAnalyticsManagementClient
from azure.mgmt.logic import LogicManagementClient
from azure.mgmt.eventhub import EventHubManagementClient
from azure.mgmt.eventgrid import EventGridManagementClient
from azure.mgmt.containerservice import ContainerServiceClient

import json
import re
import hashlib
import os
import platform
from argparse import ArgumentParser
from datetime import date, datetime, tzinfo, timedelta

ERROR_COLOR = "\033[91m"
WARNING_COLOR = "\033[93m"
END_COLOR = "\033[0m"


def print_err(msg, warning=False):
    start_color = WARNING_COLOR if warning else ERROR_COLOR
    print(start_color + msg + END_COLOR)


def make_request(request_func, arg_list=[], return_on_error=[]):
    try:
        response = request_func(*arg_list)
        result = []
        for item in response:
            result.append(item.as_dict())
        return result

    except Exception as e:
        error_message = "\t\t\t{error}".format(error=str(e))
        print_err(error_message)
        return return_on_error


class AzureImportUtil:
    def __init__(self, args):
        self.args = args

        credentials = AzureCliCredential()
        self.subscription_client = SubscriptionClient(credentials)

    def set_clients_to_subscription(self, subscription_id=None):
        credentials = AzureCliCredential()

        if subscription_id is not None:
            self.subscription_client = SubscriptionClient(credentials, subscription_id=subscription_id)
            self.resource_client = ResourceManagementClient(credentials, subscription_id=subscription_id)
            self.network_client = NetworkManagementClient(credentials, subscription_id=subscription_id)
            self.compute_client = ComputeManagementClient(credentials, subscription_id=subscription_id)
            self.storage_client = StorageManagementClient(credentials, subscription_id=subscription_id)
            self.postgresql_client = PostgreSQLManagementClient(credentials, subscription_id=subscription_id)
            self.mysql_client = MySQLManagementClient(credentials, subscription_id=subscription_id)
            self.sql_client = SqlManagementClient(credentials, subscription_id=subscription_id)
            self.key_vault_client = KeyVaultManagementClient(credentials, subscription_id=subscription_id)
            self.front_door_client = FrontDoorManagementClient(credentials, subscription_id=subscription_id)
            self.app_service_client = WebSiteManagementClient(credentials, subscription_id=subscription_id)
            self.traffic_manager_client = TrafficManagerManagementClient(credentials, subscription_id=subscription_id)
            self.cosmos_db_client = CosmosDBManagementClient(credentials, subscription_id=subscription_id)
            self.dns_client = DnsManagementClient(credentials, subscription_id=subscription_id)
            self.private_dns_client = PrivateDnsManagementClient(credentials, subscription_id=subscription_id)
            self.api_management_client = ApiManagementClient(credentials, subscription_id=subscription_id)
            self.service_bus_client = ServiceBusManagementClient(credentials, subscription_id=subscription_id)
            self.databricks_client = DatabricksClient(credentials, subscription_id=subscription_id)
            self.msi_client = ManagedServiceIdentityClient(credentials, subscription_id=subscription_id)
            self.iot_hub_client = IotHubClient(credentials, subscription_id=subscription_id)
            self.cdn_client = CdnManagementClient(credentials, subscription_id=subscription_id)
            self.redis_client = RedisManagementClient(credentials, subscription_id=subscription_id)
            self.hdinsight_client = HDInsightManagementClient(credentials, subscription_id=subscription_id)
            self.datafactory_client = DataFactoryManagementClient(credentials, subscription_id=subscription_id)
            self.log_analytics_client = LogAnalyticsManagementClient(credentials, subscription_id=subscription_id)
            self.logic_client = LogicManagementClient(credentials, subscription_id=subscription_id)
            self.event_hub_client = EventHubManagementClient(credentials, subscription_id=subscription_id)
            self.event_grid_client = EventGridManagementClient(credentials, subscription_id=subscription_id)
            self.container_service_client = ContainerServiceClient(credentials, subscription_id=subscription_id)

    def flatten_entry_dict(self, resource_dict, entry):
        if entry in resource_dict:
            to_flatten = resource_dict[entry]
            new_dict = dict(resource_dict)
            for key in to_flatten:
                new_dict[key] = to_flatten[key]
            del new_dict[entry]
            return new_dict
        else:
            return resource_dict

    def hash_string(self, raw_string):
        return hashlib.sha256(raw_string.encode()).hexdigest()

    def get_network_resources(self, resource_group):
        resource_group["resources"]["network"] = {}
        resource_group["resources"]["network"]["applicationGateways"] = []
        resource_group["resources"]["network"]["loadBalancers"] = []
        resource_group["resources"]["network"]["virtualNetworks"] = []
        resource_group["resources"]["network"]["virtualNetworkGateways"] = []
        resource_group["resources"]["network"]["virtualNetworkGatewayConnections"] = []
        resource_group["resources"]["network"]["localNetworkGateways"] = []
        resource_group["resources"]["network"]["subnets"] = []
        resource_group["resources"]["network"]["publicIpAddresses"] = []
        resource_group["resources"]["network"]["applicationSecurityGroups"] = []
        resource_group["resources"]["network"]["networkSecurityGroups"] = []
        resource_group["resources"]["network"]["networkInterfaces"] = []
        resource_group["resources"]["network"]["firewalls"] = []
        resource_group["resources"]["network"]["routeTables"] = []
        resource_group["resources"]["network"]["privateEndpoints"] = []
        resource_group["resources"]["network"]["virtualWans"] = []
        resource_group["resources"]["network"]["expressRouteCircuits"] = []
        resource_group_name = resource_group["resourceGroupName"]

        resource_group["resources"]["network"]["applicationGateways"] = make_request(
            self.network_client.application_gateways.list, [resource_group_name]
        )
        resource_group["resources"]["network"]["loadBalancers"] = make_request(
            self.network_client.load_balancers.list, [resource_group_name]
        )

        for virtual_network in make_request(self.network_client.virtual_networks.list, [resource_group_name]):
            resource_group["resources"]["network"]["virtualNetworks"].append(virtual_network)
            for subnet in make_request(
                self.network_client.subnets.list, [resource_group_name, virtual_network["name"]]
            ):
                resource_group["resources"]["network"]["subnets"].append(subnet)

        resource_group["resources"]["network"]["publicIpAddresses"] = make_request(
            self.network_client.public_ip_addresses.list, [resource_group_name]
        )
        resource_group["resources"]["network"]["virtualNetworkGateways"] = make_request(
            self.network_client.virtual_network_gateways.list, [resource_group_name]
        )
        resource_group["resources"]["network"]["virtualNetworkGatewayConnections"] = make_request(
            self.network_client.virtual_network_gateway_connections.list, [resource_group_name]
        )
        resource_group["resources"]["network"]["localNetworkGateways"] = make_request(
            self.network_client.local_network_gateways.list, [resource_group_name]
        )
        resource_group["resources"]["network"]["applicationSecurityGroups"] = make_request(
            self.network_client.application_security_groups.list, [resource_group_name]
        )
        resource_group["resources"]["network"]["networkSecurityGroups"] = make_request(
            self.network_client.network_security_groups.list, [resource_group_name]
        )
        resource_group["resources"]["network"]["networkInterfaces"] = make_request(
            self.network_client.network_interfaces.list, [resource_group_name]
        )
        resource_group["resources"]["network"]["firewalls"] = make_request(
            self.network_client.azure_firewalls.list, [resource_group_name]
        )
        resource_group["resources"]["network"]["routeTables"] = make_request(
            self.network_client.route_tables.list, [resource_group_name]
        )
        resource_group["resources"]["network"]["privateEndpoints"] = make_request(
            self.network_client.private_endpoints.list, [resource_group_name]
        )
        resource_group["resources"]["network"]["virtualWans"] = make_request(
            self.network_client.virtual_wans.list_by_resource_group, [resource_group_name]
        )
        resource_group["resources"]["network"]["expressRouteCircuits"] = make_request(
            self.network_client.express_route_circuits.list, [resource_group_name]
        )

        network = resource_group["resources"]["network"]
        return (
            len(network["applicationGateways"])
            + len(network["loadBalancers"])
            + len(network["virtualNetworks"])
            + len(network["virtualNetworkGateways"])
            + len(network["virtualNetworkGatewayConnections"])
            + len(network["localNetworkGateways"])
            + len(network["subnets"])
            + len(network["publicIpAddresses"])
            + len(network["applicationSecurityGroups"])
            + len(network["networkSecurityGroups"])
            + len(network["networkInterfaces"])
            + len(network["firewalls"])
            + len(network["routeTables"])
            + len(network["privateEndpoints"])
            + len(network["virtualWans"])
            + len(network["expressRouteCircuits"])
        )

    def get_compute_resources(self, resource_group):
        resource_group["resources"]["compute"] = {}
        resource_group["resources"]["compute"]["disks"] = []
        resource_group["resources"]["compute"]["virtualMachines"] = []
        resource_group["resources"]["compute"]["virtualMachineScaleSets"] = []
        resource_group_name = resource_group["resourceGroupName"]

        resource_group["resources"]["compute"]["disks"] = make_request(
            self.compute_client.disks.list_by_resource_group, [resource_group_name]
        )
        resource_group["resources"]["compute"]["virtualMachines"] = make_request(
            self.compute_client.virtual_machines.list, [resource_group_name]
        )
        resource_group["resources"]["compute"]["virtualMachineScaleSets"] = make_request(
            self.compute_client.virtual_machine_scale_sets.list, [resource_group_name]
        )

        compute = resource_group["resources"]["compute"]
        return len(compute["disks"]) + len(compute["virtualMachines"]) + len(compute["virtualMachineScaleSets"])

    def get_cosmos_db_resources(self, resource_group):
        resource_group["resources"]["cosmosdb"] = {}
        resource_group["resources"]["cosmosdb"]["databaseAccounts"] = []
        resource_group_name = resource_group["resourceGroupName"]

        resource_group["resources"]["cosmosdb"]["databaseAccounts"] = make_request(
            self.cosmos_db_client.database_accounts.list_by_resource_group, [resource_group_name]
        )

        return len(resource_group["resources"]["cosmosdb"]["databaseAccounts"])

    def get_databricks_resources(self, resource_group):
        resource_group["resources"]["databricks"] = {}
        resource_group["resources"]["databricks"]["workspaces"] = []
        resource_group_name = resource_group["resourceGroupName"]

        resource_group["resources"]["databricks"]["workspaces"] = make_request(
            self.databricks_client.workspaces.list_by_resource_group, [resource_group_name]
        )

        return len(resource_group["resources"]["databricks"]["workspaces"])

    def get_storage_resources(self, resource_group):
        resource_group["resources"]["storage"] = {}
        resource_group["resources"]["storage"]["storageAccounts"] = []
        resource_group["resources"]["storage"]["fileShares"] = []
        resource_group["resources"]["storage"]["storageQueues"] = []
        resource_group_name = resource_group["resourceGroupName"]

        resource_group["resources"]["storage"]["storageAccounts"] = make_request(
            self.storage_client.storage_accounts.list_by_resource_group, [resource_group_name]
        )
        for storageAccount in resource_group["resources"]["storage"]["storageAccounts"]:
            if storageAccount["kind"] != "BlobStorage" and storageAccount["kind"] != "BlockBlobStorage":
                if "file" in storageAccount["primary_endpoints"]:
                    resource_group["resources"]["storage"]["fileShares"] += make_request(
                        self.storage_client.file_shares.list, [resource_group_name, storageAccount["name"]]
                    )
                if "queue" in storageAccount["primary_endpoints"]:
                    resource_group["resources"]["storage"]["storageQueues"] += make_request(
                        self.storage_client.queue.list, [resource_group_name, storageAccount["name"]]
                    )

        storage = resource_group["resources"]["storage"]
        return len(storage["storageAccounts"]) + len(storage["fileShares"]) + len(storage["storageQueues"])

    def get_sql_resources(self, resource_group):
        resource_group["resources"]["sql"] = {}
        resource_group["resources"]["sql"]["servers"] = []
        resource_group["resources"]["sql"]["databases"] = []
        resource_group["resources"]["sql"]["managedInstances"] = []
        resource_group_name = resource_group["resourceGroupName"]

        for sql_server in make_request(self.sql_client.servers.list_by_resource_group, [resource_group_name]):
            resource_group["resources"]["sql"]["servers"].append(sql_server)
            for sql_database in make_request(
                self.sql_client.databases.list_by_server, [resource_group_name, sql_server["name"]]
            ):
                resource_group["resources"]["sql"]["databases"].append(sql_database)

        resource_group["resources"]["sql"]["managedInstances"] = make_request(
            self.sql_client.managed_instances.list_by_resource_group, [resource_group_name]
        )

        sql = resource_group["resources"]["sql"]
        return len(sql["servers"]) + len(sql["databases"]) + len(sql["managedInstances"])

    def get_mysql_resources(self, resource_group):
        resource_group["resources"]["mysql"] = {}
        resource_group["resources"]["mysql"]["servers"] = []
        resource_group["resources"]["mysql"]["databases"] = []
        resource_group_name = resource_group["resourceGroupName"]

        for mysql_server in make_request(self.mysql_client.servers.list_by_resource_group, [resource_group_name]):
            resource_group["resources"]["mysql"]["servers"].append(mysql_server)
            for mysql_database in make_request(
                self.mysql_client.databases.list_by_server, [resource_group_name, mysql_server["name"]]
            ):
                resource_group["resources"]["mysql"]["databases"].append(mysql_database)

        mysql = resource_group["resources"]["mysql"]
        return len(mysql["servers"]) + len(mysql["databases"])

    def get_postgresql_resources(self, resource_group):
        resource_group["resources"]["postgresql"] = {}
        resource_group["resources"]["postgresql"]["servers"] = []
        resource_group["resources"]["postgresql"]["databases"] = []
        resource_group_name = resource_group["resourceGroupName"]

        for postgresql_server in make_request(
            self.postgresql_client.servers.list_by_resource_group, [resource_group_name]
        ):
            resource_group["resources"]["postgresql"]["servers"].append(postgresql_server)
            for postgresql_database in make_request(
                self.postgresql_client.databases.list_by_server, [resource_group_name, postgresql_server["name"]]
            ):
                resource_group["resources"]["postgresql"]["databases"].append(postgresql_database)

        postgresql = resource_group["resources"]["postgresql"]
        return len(postgresql["servers"]) + len(postgresql["databases"])

    def get_traffic_manager_resources(self, resource_group):
        resource_group["resources"]["trafficmanager"] = {}
        resource_group["resources"]["trafficmanager"]["profiles"] = []
        resource_group_name = resource_group["resourceGroupName"]

        resource_group["resources"]["trafficmanager"]["profiles"] = make_request(
            self.traffic_manager_client.profiles.list_by_resource_group, [resource_group_name]
        )

        return len(resource_group["resources"]["trafficmanager"]["profiles"])

    def get_key_vault_resources(self, resource_group):
        resource_group["resources"]["keyvault"] = {}
        resource_group["resources"]["keyvault"]["vaults"] = []
        resource_group_name = resource_group["resourceGroupName"]

        for key_vault in make_request(self.key_vault_client.vaults.list_by_resource_group, [resource_group_name]):
            vault_dict = self.flatten_entry_dict(key_vault, "properties")
            resource_group["resources"]["keyvault"]["vaults"].append(vault_dict)

        return len(resource_group["resources"]["keyvault"])

    def get_front_door_resources(self, resource_group):
        resource_group["resources"]["frontdoorandcdn"] = {}
        resource_group["resources"]["frontdoorandcdn"]["frontDoorsAndCdnProfiles"] = []  # Front Door Standard/Premium
        resource_group["resources"]["network"]["frontDoorClassics"] = []  # Front Door (Classic)
        resource_group_name = resource_group["resourceGroupName"]

        for profile in make_request(self.cdn_client.profiles.list_by_resource_group, [resource_group_name]):
            if profile["kind"] != "frontdoor":
                resource_group["resources"]["frontdoorandcdn"]["frontDoorsAndCdnProfiles"].append(profile)
                continue

            profile["endpoints"] = []
            profile["originGroups"] = []

            for endpoint in make_request(
                self.cdn_client.afd_endpoints.list_by_profile, [resource_group_name, profile["name"]]
            ):
                profile["endpoints"].append(endpoint)

            for originGroup in make_request(
                self.cdn_client.afd_origin_groups.list_by_profile, [resource_group_name, profile["name"]]
            ):
                originGroup["origins"] = []
                for origin in make_request(
                    self.cdn_client.afd_origins.list_by_origin_group,
                    [resource_group_name, profile["name"], originGroup["name"]],
                ):
                    originGroup["origins"].append(origin)
                profile["originGroups"].append(originGroup)

            resource_group["resources"]["frontdoorandcdn"]["frontDoorsAndCdnProfiles"].append(profile)

        resource_group["resources"]["network"]["frontDoorClassics"] = make_request(
            self.front_door_client.front_doors.list_by_resource_group, [resource_group_name]
        )

        frontdoor = resource_group["resources"]["frontdoorandcdn"]
        return len(frontdoor["frontDoorsAndCdnProfiles"]) + len(
            resource_group["resources"]["network"]["frontDoorClassics"]
        )

    def get_app_service_resources(self, resource_group):
        resource_group["resources"]["appservice"] = {}
        resource_group["resources"]["appservice"]["appServicePlans"] = []
        resource_group["resources"]["appservice"]["webApps"] = []
        resource_group_name = resource_group["resourceGroupName"]

        for app_service_plan in self.app_service_client.app_service_plans.list_by_resource_group(resource_group_name):
            resource_group["resources"]["appservice"]["appServicePlans"].append(app_service_plan.as_dict())

        for web_app in make_request(self.app_service_client.web_apps.list_by_resource_group, [resource_group_name]):
            web_app["functions"] = []
            for function in make_request(
                self.app_service_client.web_apps.list_functions, [resource_group_name, web_app["name"]]
            ):
                web_app["functions"].append(function)
            resource_group["resources"]["appservice"]["webApps"].append(web_app)

        return len(
            resource_group["resources"]["appservice"]["appServicePlans"]
            + resource_group["resources"]["appservice"]["webApps"]
        )

    def get_dns_resources(self, resource_group):
        resource_group["resources"]["dns"] = {}
        resource_group["resources"]["dns"]["zones"] = []
        resource_group["resources"]["dns"]["privateZones"] = []
        resource_group_name = resource_group["resourceGroupName"]

        for zone in make_request(self.dns_client.zones.list_by_resource_group, [resource_group_name]):
            zone["recordSets"] = []
            for record_set in make_request(
                self.dns_client.record_sets.list_all_by_dns_zone, [resource_group_name, zone["name"]]
            ):
                zone["recordSets"].append(record_set)
            resource_group["resources"]["dns"]["zones"].append(zone)

        for private_zone in make_request(
            self.private_dns_client.private_zones.list_by_resource_group, [resource_group_name]
        ):
            private_zone["recordSets"] = []
            private_zone["virtualNetworkLinks"] = []

            for record_set in make_request(
                self.private_dns_client.record_sets.list, [resource_group_name, private_zone["name"]]
            ):
                private_zone["recordSets"].append(record_set)

            for virtual_network_link in make_request(
                self.private_dns_client.virtual_network_links.list, [resource_group_name, private_zone["name"]]
            ):
                private_zone["virtualNetworkLinks"].append(virtual_network_link)

            resource_group["resources"]["dns"]["privateZones"].append(private_zone)

        return len(resource_group["resources"]["dns"]["zones"]) + len(
            resource_group["resources"]["dns"]["privateZones"]
        )

    def get_api_management_resources(self, resource_group):
        resource_group["resources"]["apimanagement"] = {}
        resource_group["resources"]["apimanagement"]["apiManagementServices"] = []
        resource_group_name = resource_group["resourceGroupName"]

        resource_group["resources"]["apimanagement"]["apiManagementServices"] = make_request(
            self.api_management_client.api_management_service.list_by_resource_group, [resource_group_name]
        )

        return len(resource_group["resources"]["apimanagement"]["apiManagementServices"])

    def get_service_bus_resources(self, resource_group):
        resource_group["resources"]["servicebus"] = {}
        resource_group["resources"]["servicebus"]["serviceBusNamespaces"] = []
        resource_group_name = resource_group["resourceGroupName"]

        for namespace in make_request(self.service_bus_client.namespaces.list_by_resource_group, [resource_group_name]):
            namespace["queues"] = []

            for queue in make_request(
                self.service_bus_client.queues.list_by_namespace, [resource_group_name, namespace["name"]]
            ):
                namespace["queues"].append(queue)

            resource_group["resources"]["servicebus"]["serviceBusNamespaces"].append(namespace)

        return len(resource_group["resources"]["servicebus"]["serviceBusNamespaces"])

    def get_managed_identity_resources(self, resource_group):
        resource_group["resources"]["managedidentity"] = {}
        resource_group["resources"]["managedidentity"]["userAssignedIdentities"] = []
        resource_group_name = resource_group["resourceGroupName"]

        resource_group["resources"]["managedidentity"]["userAssignedIdentities"] = make_request(
            self.msi_client.user_assigned_identities.list_by_resource_group, [resource_group_name]
        )

        return len(resource_group["resources"]["managedidentity"]["userAssignedIdentities"])

    def get_hdinsight_resources(self, resource_group):
        resource_group["resources"]["hdinsight"] = {}
        resource_group["resources"]["hdinsight"]["clusters"] = []
        resource_group_name = resource_group["resourceGroupName"]

        for hdinsight in make_request(self.hdinsight_client.clusters.list_by_resource_group, [resource_group_name]):
            hdinsight_props = self.flatten_entry_dict(hdinsight, "properties")
            resource_group["resources"]["hdinsight"]["clusters"].append(hdinsight_props)

        return len(resource_group["resources"]["hdinsight"]["clusters"])

    def get_iot_hub_resources(self, resource_group):
        resource_group["resources"]["iothub"] = {}
        resource_group["resources"]["iothub"]["iotHubs"] = []
        resource_group_name = resource_group["resourceGroupName"]

        for iot_hub in make_request(self.iot_hub_client.iot_hub_resource.list_by_resource_group, [resource_group_name]):
            iot_hub_props = self.flatten_entry_dict(iot_hub, "properties")
            resource_group["resources"]["iothub"]["iotHubs"].append(iot_hub_props)

        return len(resource_group["resources"]["iothub"]["iotHubs"])

    def get_cache_for_redis_resources(self, resource_group):
        resource_group["resources"]["cacheforredis"] = {}
        resource_group["resources"]["cacheforredis"]["cachesForRedis"] = []
        resource_group_name = resource_group["resourceGroupName"]

        resource_group["resources"]["cacheforredis"]["cachesForRedis"] = make_request(
            self.redis_client.redis.list_by_resource_group, [resource_group_name]
        )

        return len(resource_group["resources"]["cacheforredis"]["cachesForRedis"])

    def get_data_factory_resources(self, resource_group):
        resource_group["resources"]["datafactory"] = {}
        resource_group["resources"]["datafactory"]["dataFactories"] = []
        resource_group_name = resource_group["resourceGroupName"]
        resource_group["resources"]["datafactory"]["dataFactories"] = make_request(
            self.datafactory_client.factories.list_by_resource_group, [resource_group_name]
        )
        return len(resource_group["resources"]["datafactory"]["dataFactories"])

    def get_log_analytics_resources(self, resource_group):
        resource_group["resources"]["loganalytics"] = {}
        resource_group["resources"]["loganalytics"]["workspaces"] = []
        resource_group_name = resource_group["resourceGroupName"]
        resource_group["resources"]["loganalytics"]["workspaces"] = make_request(
            self.log_analytics_client.workspaces.list_by_resource_group, [resource_group_name]
        )
        return len(resource_group["resources"]["loganalytics"]["workspaces"])

    def get_event_hub_resources(self, resource_group):
        resource_group["resources"]["eventhubs"] = {}
        resource_group["resources"]["eventhubs"]["eventHubs"] = []
        resource_group["resources"]["eventhubs"]["eventHubsNamespaces"] = []
        resource_group_name = resource_group["resourceGroupName"]

        for namespace in make_request(self.event_hub_client.namespaces.list_by_resource_group, [resource_group_name]):
            resource_group["resources"]["eventhubs"]["eventHubsNamespaces"].append(namespace)
            for eventHub in make_request(
                self.event_hub_client.event_hubs.list_by_namespace, [resource_group_name, namespace["name"]]
            ):
                resource_group["resources"]["eventhubs"]["eventHubs"].append(eventHub)

        return len(resource_group["resources"]["eventhubs"]["eventHubs"]) + len(
            resource_group["resources"]["eventhubs"]["eventHubsNamespaces"]
        )

    def get_logic_apps_resources(self, resource_group):
        resource_group["resources"]["logicapps"] = {}
        resource_group["resources"]["logicapps"]["workflows"] = []
        resource_group_name = resource_group["resourceGroupName"]
        resource_group["resources"]["logicapps"]["workflows"] = make_request(
            self.logic_client.workflows.list_by_resource_group, [resource_group_name]
        )
        return len(resource_group["resources"]["logicapps"]["workflows"])

    def get_event_grid_resources(self, resource_group):
        resource_group["resources"]["eventgrid"] = {}
        resource_group["resources"]["eventgrid"]["domains"] = []
        resource_group["resources"]["eventgrid"]["topics"] = []
        resource_group_name = resource_group["resourceGroupName"]
        resource_group["resources"]["eventgrid"]["domains"] = make_request(
            self.event_grid_client.domains.list_by_resource_group, [resource_group_name]
        )
        resource_group["resources"]["eventgrid"]["topics"] = make_request(
            self.event_grid_client.topics.list_by_resource_group, [resource_group_name]
        )
        return len(resource_group["resources"]["eventgrid"]["domains"]) + len(
            resource_group["resources"]["eventgrid"]["topics"]
        )

    def get_container_service_resources(self, resource_group):
        resource_group["resources"]["containerservice"] = {}
        resource_group["resources"]["containerservice"]["managedClusters"] = []
        resource_group_name = resource_group["resourceGroupName"]
        resource_group["resources"]["containerservice"]["managedClusters"] = make_request(
            self.container_service_client.managed_clusters.list_by_resource_group, [resource_group_name]
        )
        return len(resource_group["resources"]["containerservice"]["managedClusters"])

    def import_data(self):
        if not self.args.subscriptions:
            print_err(
                "Usage: azurecliscript.py --subscriptions [subscription_id [subscription_ids...]] [-o <output file>]",
                warning=True,
            )
            print_err("Please specify which subscriptions you would like us to pull in", warning=True)
            print("Possible subscriptions:")
            for subscription in self.subscription_client.subscriptions.list():
                print(f"\t{subscription.display_name}: {subscription.subscription_id}")
            return

        num_total_resources = 0
        num_total_compute_resources = 0
        counts = {"subscriptions": {}}
        subscriptions = []
        for subscription_id in set(self.args.subscriptions):
            self.set_clients_to_subscription(subscription_id)
            subscription = self.subscription_client.subscriptions.get(subscription_id)
            num_current_resources = 0
            num_current_compute_resources = 0
            print(f"Adding resources for Subscription {subscription.display_name}")
            subscription_dict = {
                "subscriptionId": subscription.subscription_id,
                "displayName": subscription.display_name,
                "resourceGroups": [],
            }

            for resource_group in self.resource_client.resource_groups.list():
                resource_group_name = resource_group.name
                resource_group_tags = resource_group.tags if resource_group.tags is not None else {}
                print(f"\tAdding resources for Resource Group {resource_group_name}")
                resource_group_dict = {
                    "resourceGroupId": resource_group.id,
                    "resourceGroupName": resource_group_name,
                    "tags": resource_group_tags,
                    "resources": {},
                }
                print("\t\tAdding the Network resources in this resource group")
                num_current_resources += self.get_network_resources(resource_group_dict)

                print("\t\tAdding the Front Door resources in this resource group")
                num_current_resources += self.get_front_door_resources(resource_group_dict)

                print("\t\tAdding the Compute resources in this resource group")
                num_current_resources += self.get_compute_resources(resource_group_dict)
                num_current_compute_resources += len(resource_group_dict["resources"]["compute"]["virtualMachines"])

                print("\t\tAdding the Cosmos DB resources in this resource group")
                num_current_resources += self.get_cosmos_db_resources(resource_group_dict)

                print("\t\tAdding the Databricks resources in this resource group")
                num_current_resources += self.get_databricks_resources(resource_group_dict)

                print("\t\tAdding the Storage resources in this resource group")
                num_current_resources += self.get_storage_resources(resource_group_dict)

                print("\t\tAdding the Database resources in this resource group")
                num_current_resources += self.get_sql_resources(resource_group_dict)
                num_current_resources += self.get_mysql_resources(resource_group_dict)
                num_current_resources += self.get_postgresql_resources(resource_group_dict)

                print("\t\tAdding the Traffic Manager resources in this resource group")
                num_current_resources += self.get_traffic_manager_resources(resource_group_dict)

                print("\t\tAdding the Key Vault resources in this resource group")
                num_current_resources += self.get_key_vault_resources(resource_group_dict)

                print("\t\tAdding the App Service resources in this resource group")
                num_current_resources += self.get_app_service_resources(resource_group_dict)

                print("\t\tAdding the DNS resources in this resource group")
                num_current_resources += self.get_dns_resources(resource_group_dict)

                print("\t\tAdding the API Management resources in this resource group")
                num_current_resources += self.get_api_management_resources(resource_group_dict)

                print("\t\tAdding the Service Bus resources in this resource group")
                num_current_resources += self.get_service_bus_resources(resource_group_dict)

                print("\t\tAdding the Managed Identity resources in this resource group")
                num_current_resources += self.get_managed_identity_resources(resource_group_dict)

                print("\t\tAdding the Iot Hub resources in this resource group")
                num_current_resources += self.get_iot_hub_resources(resource_group_dict)

                print("\t\tAdding the Cache for Redis resources in this resource group")
                num_current_resources += self.get_cache_for_redis_resources(resource_group_dict)

                print("\t\tAdding the HDInsight resources in this resource group")
                num_current_resources += self.get_hdinsight_resources(resource_group_dict)

                print("\t\tAdding the Data Factory resources in this resource group")
                num_current_resources += self.get_data_factory_resources(resource_group_dict)

                print("\t\tAdding the Log Analytics resources in this resource group")
                num_current_resources += self.get_log_analytics_resources(resource_group_dict)

                print("\t\tAdding the Event Hub resources in this resource group")
                num_current_resources += self.get_event_hub_resources(resource_group_dict)

                print("\t\tAdding the Logic Apps resources in this resource group")
                num_current_resources += self.get_logic_apps_resources(resource_group_dict)

                print("\t\tAdding the Event Grid resources in this resource group")
                num_current_resources += self.get_event_grid_resources(resource_group_dict)

                print("\t\tAdding the Container Service resources in this resource group")
                num_current_resources += self.get_container_service_resources(resource_group_dict)

                subscription_dict["resourceGroups"].append(resource_group_dict)

            hash_subscription_id = self.hash_string(subscription.subscription_id)
            counts["subscriptions"][hash_subscription_id] = {
                "resourceCount": num_current_resources,
                "computeResourceCount": num_current_compute_resources,
            }
            num_total_resources += num_current_resources
            num_total_compute_resources += num_current_compute_resources
            subscriptions.append(subscription_dict)

        out_file = self.args.output if self.args.output else "azure.json"
        if not out_file.endswith(".json"):
            out_file += ".json"
        with open(out_file, "w") as f:
            a = {"subscriptions": subscriptions}
            json.dump(a, f)
            print("Output to " + out_file)

        if self.args.count:
            with open("count.json", "w") as f:
                counts["totalResourceCount"] = num_total_resources
                counts["totalComputeResourceCount"] = num_total_compute_resources
                json.dump(counts, f, indent=4)
                print("Resource count output to count.json")


def process_args():
    parser = ArgumentParser()
    parser.add_argument("-c", "--count", help="count number of Azure resources", action="store_true")
    parser.add_argument("-s", "--subscriptions", type=str, nargs="+")
    parser.add_argument("-o", "--output", help="specify output file name", nargs="?", type=str, action="store")
    return parser.parse_args()


if __name__ == "__main__":
    # this enables colorization in windows cmd terminal
    if "Windows" in platform.system():
        os.system("color")
    args = process_args()
    util = AzureImportUtil(args)
    util.import_data()
