import json
import boto3
import os

# Initialize the WAF client
waf_client = boto3.client('wafv2')

def lambda_handler(event, context):
    print("Received event: ", json.dumps(event))

    # --- 1. Get Configuration from Environment Variables ---
    try:
        ip_set_name = os.environ['IP_SET_NAME']
        scope = os.environ['WAF_SCOPE']
    except KeyError as e:
        print(f"ERROR: Missing environment variable: {e}")
        # Raising an exception will cause Lambda to retry or send to DLQ
        raise Exception("Configuration error: Missing required environment variables.")

    print(f"Targeting IP Set '{ip_set_name}' in scope '{scope}'")

    # --- 2. Extract Attacker IP from GuardDuty Finding ---
    try:
        attacker_ip = event.get('detail', {})\
                             .get('service', {})\
                             .get('action', {})\
                             .get('networkConnectionAction', {})\
                             .get('remoteIpDetails', {})\
                             .get('ipAddressV4')

        if not attacker_ip:
            print("Could not extract attacker IP from the GuardDuty finding.")
            return # Exit gracefully if IP is not in the event
            
        print(f"Extracted attacker IP: {attacker_ip}")

    except Exception as e:
        print(f"Error parsing event: {e}")
        raise

    # --- 3. Get WAF IP Set Details ---
    try:
        response_list = waf_client.list_ip_sets(Scope=scope)
        ip_set = next((s for s in response_list.get('IPSets', []) if s['Name'] == ip_set_name), None)
        
        if not ip_set:
            print(f"ERROR: IP Set '{ip_set_name}' not found in scope '{scope}'.")
            raise Exception(f"WAF IP Set '{ip_set_name}' not found.")
            
        ip_set_id = ip_set['Id']
        
        response_get = waf_client.get_ip_set(Name=ip_set_name, Scope=scope, Id=ip_set_id)
        lock_token = response_get['LockToken']
        current_ips = [cidr.split('/')[0] for cidr in response_get.get('IPSet', {}).get('Addresses', [])]

    except Exception as e:
        print(f"Error getting WAF IP Set details: {e}")
        raise

    # --- 4. Update WAF IP Set ---
    if attacker_ip in current_ips:
        print(f"IP {attacker_ip} is already in the IP Set '{ip_set_name}'. No update needed.")
        return {
            'statusCode': 200,
            'body': json.dumps(f"IP {attacker_ip} was already blocked.")
        }

    try:
        new_addresses = response_get['IPSet']['Addresses']
        new_addresses.append(f"{attacker_ip}/32")
        
        waf_client.update_ip_set(
            Name=ip_set_name,
            Scope=scope,
            Id=ip_set_id,
            Addresses=new_addresses,
            LockToken=lock_token
        )
        print(f"Successfully added IP {attacker_ip} to IP Set '{ip_set_name}'.")
        
    except Exception as e:
        print(f"Error updating WAF IP Set: {e}")
        raise
        
    return {
        'statusCode': 200,
        'body': json.dumps(f'Successfully blocked IP: {attacker_ip}')
    }