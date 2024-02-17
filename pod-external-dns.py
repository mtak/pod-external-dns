import sys
import getopt
import requests
import time
import os
import datetime

from kubernetes import client, config
import re

settings = {
    'managed_domain': None,
    'kubeconfig': None,
    'cf_api_token': None,
    'cf_api_email': None,
    'cf_zone_id': None,
    'reconciliation_interval': None
}


def main_loop():
    pods_with_annotation = find_pods_with_annotation()
    desired_record_state = create_desired_record_state(pods_with_annotation)
    log_message("Pods with the 'external-dns-kafka.alpha.tak.io/enabled' annotation set to true and matching domain:")
    log_message(desired_record_state)

    dns_state = get_managed_dns_records()

    records_removed = remove_records(desired_record_state=desired_record_state, dns_state=dns_state)
    records_added = add_records(desired_record_state=desired_record_state, dns_state=dns_state)
    # State is going to be out of date for the update after an add or delete, skip until next cycle
    if records_removed or records_added:
        log_message("Skipping updating records due to records being added or deleted")
        return
    update_records(desired_record_state=desired_record_state, dns_state=dns_state)


def remove_records(desired_record_state, dns_state):
    r = False
    for dns_record in dns_state:
        log_message(dns_record)
        # Check if record exists in desired state
        if dns_record not in desired_record_state:
            log_message(f"{dns_record} not in desired record state, deleting... (id: {dns_state[dns_record]['id']})")
            remove_record(record_id=dns_state[dns_record]['id'])
            r = True
    return r


def add_records(desired_record_state, dns_state):
    r = False
    for desired_record in desired_record_state:
        if desired_record not in dns_state:
            add_record(name=desired_record, ip=desired_record_state[desired_record])
            r = True
    return r


def update_records(desired_record_state, dns_state):
    r = False
    for desired_record in desired_record_state:
        if desired_record_state[desired_record] != dns_state[desired_record]['content']:
            log_message(f"Updating record {desired_record}")
            log_message(f"current ip: {dns_state[desired_record]['content']}")
            log_message(f"wanted ip: {desired_record_state[desired_record]}")
            remove_record(dns_state[desired_record]['id'])
            add_record(name=desired_record, ip=desired_record_state[desired_record])
            r = True
    return r


def add_record(name, ip):
    zone_id = settings['cf_zone_id']
    headers = {
        'X-Auth-Email': settings['cf_api_email'],
        'X-Auth-Key': settings['cf_api_token'],
        'Content-Type': 'application/json'
    }
    data = {
        'type': 'A',
        'name': name,
        'content': ip,
        'ttl': 60,
        'proxied': False
    }
    url = f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records'

    response = requests.post(url, headers=headers, json=data)

    if response.status_code == 200:
        log_message(f"DNS record {name} added successfully.")
        return True
    else:
        log_message(f"Failed to add DNS record {name}. Status code: {response.status_code}")
        return False


def remove_record(record_id):
    zone_id = settings['cf_zone_id']
    headers = {
        'X-Auth-Email': settings['cf_api_email'],
        'X-Auth-Key': settings['cf_api_token'],
        'Content-Type': 'application/json'
    }
    url = f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}'

    response = requests.delete(url, headers=headers)

    if response.status_code == 200:
        log_message("DNS record deleted successfully.")
        return True
    else:
        log_message(f"Failed to delete DNS record. Status code: {response.status_code}")
        return False


def main():
    global settings

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hm:k:t:r:z:e:",
                                   ["help", "managed-domain=", "kubeconfig=", "cf-api-token=",
                                    "reconciliation-interval=", "cf-zone-id=", "cf-api-email="])
    except getopt.GetoptError as err:
        log_message(str(err))
        usage()
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt in ("-m", "--managed-domain"):
            settings['managed_domain'] = arg
        elif opt in ("-k", "--kubeconfig"):
            settings['kubeconfig'] = arg
        elif opt in ("-t", "--cf-api-token"):
            settings['cf_api_token'] = arg
        elif opt in ("-r", "--reconciliation-interval"):
            settings['reconciliation_interval'] = arg
        elif opt in ("-z", "--cf-zone-id"):
            settings['cf_zone_id'] = arg
        elif opt in ("-e", "--cf-api-email"):
            settings['cf_api_email'] = arg

    # Check for mandatory options
    mandatory_options = ['managed_domain', 'reconciliation_interval', 'cf_zone_id']
    if not all(settings[opt] for opt in mandatory_options):
        log_message("Error: All mandatory options must be provided.")
        usage()
        sys.exit(2)

    if 'cf_api_token' not in settings or not settings['cf_api_token']:
        cf_api_token_env = os.getenv('CF_API_TOKEN')
        if cf_api_token_env:
            settings['cf_api_token'] = cf_api_token_env
        else:
            log_message("Error: CF_API_TOKEN must be provided either as an option or via environment variable.")
            usage()
            sys.exit(2)

    log_message("Configuration:")
    for key, value in settings.items():
        if key != 'cf_api_token':
            log_message(f"{key}: {value}")
    log_message(f"cf_api_token: {'Set' if settings['cf_api_token'] else 'Not set'}")

    while True:
        main_loop()
        time.sleep(int(settings['reconciliation_interval']))


def get_all_dns_records():
    zone_id = settings['cf_zone_id']
    headers = {
        'X-Auth-Email': settings['cf_api_email'],
        'X-Auth-Key': settings['cf_api_token'],
        'Content-Type': 'application/json'
    }
    url = f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records'

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        records = data.get('result', [])
        return records
    else:
        log_message(f"Failed to retrieve DNS records. Status code: {response.status_code}")
        return None


def get_managed_dns_records():
    dns_records = get_all_dns_records()

    filtered_records = {}

    if dns_records:
        log_message("Filtered Cloudflare DNS Records:")
        for record in dns_records:
            if record['name'].endswith(settings['managed_domain']):
                filtered_records[record['name']] = record

    return filtered_records


def find_pods_with_annotation(namespace='default', annotation_key='external-dns-kafka.alpha.tak.io/enabled',
                              annotation_value='true'):
    if settings['kubeconfig']:
        config.load_kube_config(settings['kubeconfig'])
    else:
        config.load_incluster_config()

    v1 = client.CoreV1Api()
    v1_node = client.CoreV1Api()

    pods_with_annotation = {}

    try:
        pod_list = v1.list_namespaced_pod(namespace)
        for pod in pod_list.items:
            annotations = pod.metadata.annotations
            if annotations and annotation_key in annotations and annotations[annotation_key] == annotation_value:
                pod_name = pod.metadata.name
                node_name = pod.spec.node_name

                # Get nodeIP
                node_info = v1_node.read_node(node_name)
                node_ip = node_info.status.addresses[0].address if node_info.status.addresses else None

                domain = annotations.get('external-dns-kafka.alpha.tak.io/domain', '')
                prefix = annotations.get('external-dns-kafka.alpha.tak.io/prefix', '')

                # Extract last digits of pod name as suffix
                suffix_match = re.search(r'\d+$', pod_name)
                suffix = suffix_match.group() if suffix_match else None

                if domain == settings['managed_domain']:
                    pods_with_annotation[pod_name] = {
                        'node_name': node_name,
                        'node_ip': node_ip,
                        'domain': domain,
                        'prefix': prefix,
                        'suffix': suffix
                    }
    except Exception as e:
        log_message("Exception when calling CoreV1Api->list_namespaced_pod:", e)

    return pods_with_annotation


def create_desired_record_state(pods):
    r = {}

    for pod in pods:
        r[pods[pod]['prefix'] + pods[pod]['suffix'] + '.' + pods[pod]['domain']] = pods[pod]['node_ip']

    return r


def usage():
    print("Usage: python script.py -m MANAGED_DOMAIN [-k KUBECONFIG] [-t CF_API_TOKEN] -r RECONCILIATION_INTERVAL -z CF_ZONE_ID")
    print("Options:")
    print("  -h, --help                        Show this help message and exit")
    print("  -m MANAGED_DOMAIN, --managed-domain=MANAGED_DOMAIN")
    print("                                    Specify managed domain")
    print("  -k KUBECONFIG, --kubeconfig=KUBECONFIG")
    print("                                    Specify kubeconfig file path or load via incluster config")
    print("  -z CF_ZONE_ID, --cf-zone-id=CF_ZONE_ID")
    print("                                    Specify Cloudflare zone ID")
    print("  -t CF_API_TOKEN, --cf-api-token=CF_API_TOKEN")
    print("                                    Specify Cloudflare API token. Required, either as a parameter or via the CF_API_TOKEN environment variable.")
    print("  -r RECONCILIATION_INTERVAL, --reconciliation-interval=RECONCILIATION_INTERVAL")
    print("                                    Specify reconciliation interval")


def log_message(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{timestamp}] {message}"
    print(log_line, flush=True)


if __name__ == "__main__":
    main()

