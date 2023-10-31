import subprocess
import time
import requests
import json

def start_aries_agent():
    title = "University Agent (Issuer)"
    command = "bash -c 'cd /home/brunopc/Documents/SOVERE_Prototype/final_version/aries-cloudagent-python-main && aca-py start --inbound-transport http 0.0.0.0 9000 --outbound-transport http --admin-insecure-mode --admin 0.0.0.0 9001 --seed 000000000000000000000000Steward2 --trace-target log --trace-tag acapy.events --log-level info --replace-public-did --wallet-type indy --genesis-file /home/brunopc/Documents/SOVERE_Prototype/final_version/project2.0/pool1.txn --wallet-name theUniversity_wallet --wallet-key theUniversity_wallet_key --auto-accept-invites --auto-accept-requests --auto-ping-connection --auto-respond-credential-proposal --auto-respond-credential-request --label University.Agent -e http://localhost:9000 --debug-connection --debug-credentials; $SHELL'"
    
    subprocess.Popen(['gnome-terminal', '--window', '--title', title, '--command', command])
    
    print("============================")
    print("== University Agent Started ==")
    print("============================")
    time.sleep(5)

def post_schema_to_ledger():
    schema_name = "Transcript1"
    schema_version = "99.9.9"
    
    transcript_schema = {
        "attributes": ["first_name", "last_name"],
        "schema_name": schema_name,
        "schema_version": schema_version
    }
    
    post_schema_url = "http://localhost:9000/schemas"
    
    response = requests.post(post_schema_url, json=transcript_schema)
    
    if response.status_code == 200:
        schema_id = response.json()["schema_id"]
        print("Schema posted to ledger. Schema ID: " + schema_id)
    else:
        print("Failed to post schema to ledger.")

def get_schema_from_ledger(schema_id):
    get_schema_url = f"http://localhost:9000/schemas/{schema_id}"
    response = requests.get(get_schema_url)
    
    if response.status_code == 200:
        schema = response.json()["schema"]
        if schema:
            print("Schema retrieved from ledger:")
            print(json.dumps(schema, indent=4))
        else:
            print("Schema not found on the ledger.")
    else:
        print("Failed to get schema from ledger.")

# Start the Aries agent
start_aries_agent()

# Wait for the agent to start
time.sleep(10)

# Post the schema to the ledger
post_schema_to_ledger()

# Wait for the schema to be written to the ledger
time.sleep(5)

# Get the schema from the ledger
schema_id = "EbP4aYNeTHL6q385GuVpRV:2:Transcript1:99.9.9"
get_schema_from_ledger(schema_id)