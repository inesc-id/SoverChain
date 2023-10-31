import asyncio
import json
import subprocess
import requests
import time
import socket
from indy.error import ErrorCode, IndyError
from indy import pool, ledger, wallet, did, crypto
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # Add this import statement
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.padding import PKCS7
import base64
import os
from threading import Thread
from flask import Flask, request
import logging
import timeit


debug = False

global t_start
global t_check

#---------------------------------
# FLASK
#---------------------------------
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
app = Flask(__name__)


@app.route('/webhooks', methods=['POST'])
def handle_webhook():
    data = request.get_data().decode()
    print("EVENT RECEIVED:")
    print("Received data: " + str(data))
    print("----------------")
    return 'Webhook received successfully', 200

@app.route('/webhooks/topic/basicmessages/', methods=['POST'])
def basic_messages():
    
    event = request.json
    #print("Received data: " + str(event))

    did_governament = event['content']
    print(">>> Non-public DID received: " + did_governament)


    return 'Webhook received and processed successfully', 200


# Presentation Proof
@app.route('/webhooks/topic/present_proof_v2_0/', methods=['POST'])
def present_proof():
    event = request.json
    
    #print("Received data: " + json.dumps(event)) 

    pres_ex_id = event['pres_ex_id']
    state = event['state']

    global t_check
    print("Event state: " + state)
    t_check = time.time()
    print("time check->" + str(t_check))

    if state == "request-received":
        print("=== Presentation Resquest Received ===")
        check_proof = requests.get('http://10.154.0.3:8003/present-proof-2.0/records/' + pres_ex_id)
        #if check_proof.text is json
        print("********** Presentation Request ***********")
        print(check_proof.text)
        print("************************************")
        print("pres_ex_id -> " + pres_ex_id)
        print("************************************")
        print("Do you want to send the presentation? (y/n)")
    elif state == "done":
        print("=== Presentation Verified successfully ===")          
    else:
        print("=== Presentation State: " + state + " ===")
        


    return 'Webhook received and processed successfully', 200

# Issue Credential 
@app.route('/webhooks/topic/issue_credential_v2_0/', methods=['POST'])
def issue_credential():
    event = request.json
    
    state = event['state']

    global t_check
    print("Event state: " + state)
    t_check = time.time()
    print("time finished->" + str(t_check))    

    return 'Webhook received and processed successfully', 200

@app.route('/webhooks/topic/issue_credential_v2_0_ld_proof/', methods=['POST'])
def issue_credential_ld_proof():

    global t_check
    t_check = time.time()
    print("time finished stored->" + str(t_check))
    return 'Webhook received and processed successfully', 200

@app.route('/webhooks/topic/connections/', methods=['POST'])
def connections():
    event = request.json
    global t_check

    state = event['state']

    print("Event state: " + state)
    t_check = time.time()
    print("time finished->" + str(t_check))
    # gov create invitation
    #0 start
    #1 receive invitation
    #2 request connection
    #3 response invitation
    #4 accept invitation

   
    return 'Webhook received and processed successfully', 200


#****************************************************
# TESTS================================================================================================
#****************************************************

@app.route('/propose_credential/', methods=['POST'])
def test_propose():
    
    con_id_governament = "8c800275-df3e-475f-80f6-f91ae3983939"
    did_user_bbs = "did:key:zUC75K9H1dUAsAYS4WWStFUkxspttgxmvGnmu34xatdpktvbDUuBqQYDJUMXeso7WjFDt7XELcN9TLQ8p9jSrcqVrSBqXungJ4pYKAhVU9eXBrdJvtpKCHFjqftqRWJEPVTxMSg"
    did_governament_bbs = "did:key:zUC7HXaTTZKhMBa6sWnVhZ1tAEWuykJQcv1r2yQ3HMGjGWHSfn7ZoygmSC6q6ivHnRda2PT7ZHpDDG4TQHZ1h5NjtY3sZxAbgbt95yCzfKCUbVgktsozzuj2XCBBkm5G8G18Uv8"
    input_url = "ola"

    data = {
            "connection_id": con_id_governament,
            "comment": "Credential proposal for identity documents: " + input_url,
            "filter": {
                "ld_proof": {
                    "credential": {
                        "@context": [
                            "https://www.w3.org/2018/credentials/v1",
                            "https://w3id.org/citizenship/v1",
                            {
                                "isAbove18": {
                                    "@id": "https://example.com/definitions#isAbove18",
                                    "@type": "http://www.w3.org/2001/XMLSchema#boolean"
                                },
                                "givenName": "schema:givenName",
                                "familyName": "schema:familyName",
                                "gender": "schema:gender",
                                "birthCountry": "schema:birthCountry",
                                "birthDate": "schema:birthDate"
                            }

                        ],
                        "type": [
                            "VerifiableCredential",
                            "PermanentResident"
                        ],
                        "id": "https://credential.example.com/residents/aaaa",
                        "issuer": did_governament_bbs,
                        "issuanceDate": "2020-01-01T12:00:00Z",
                        "credentialSubject": {
                            "id": did_user_bbs,
                            "givenName": "ANASTACIA",
                            "familyName": "ANASTACIA",
                            "gender": "Female",
                            "birthCountry": "Portugal",
                            "birthDate": "2000-07-17",
                            "isAbove18": True
                        }
                    },
                    "options": {
                        "proofType": "BbsBlsSignature2020"
                    }
                }
            },
            "trace": True,
            "verification_method": "string"
        }
    response = requests.post('http://10.154.0.3:8003/issue-credential-2.0/send-proposal', json=data)
    #if returns error, return error
    if response.status_code != 200:
         return 'Error', 500

   
    return 'Webhook received and processed successfully', 200

@app.route('/present_credential/', methods=['POST'])
def test_present():
    pres_ex_id = "1d10f236-bd09-4c79-aafc-34b1e10dc3af"
    record_id = "ef646093ad004ec2af9e51627511b1c8"
    
    data = data = {
                    "dif": {
                            "record_ids": {
                              "citizenship_input_1": [ record_id ]
                            }
                          }
                    }  
    
    send_presentation = requests.post("http://10.154.0.3:8003/present-proof-2.0/records/" + pres_ex_id + "/send-presentation", json=data )
    if debug: print("POST present-proof-2.0/records/" + pres_ex_id + "/send-presentation -> " + send_presentation.text)
    print(">>> Presentation sent ")

#****************************************************
# AUX FUNCTIONS
#****************************************************
def check_input_descriptor_record_id(input_descriptor_schema_uri, record) -> bool:
        result = False
        for uri in input_descriptor_schema_uri:
            for record_type in record["type"]:
                if record_type in uri:
                    result = True
                    break
                result = False

        return result



async def delete_credentials():
     #check_credentials = requests.get('http://10.154.0.3:8003/issue-credential-2.0/records')
    #print("GET issue-credential-2.0/records-> " + check_credentials.text)

    #for loop and print all ccred_ex_id
    #json_data = json.loads(check_credentials.text)['results']
    #for i in json_data:
        #print("----------------")
        #cred_ex_id = str(i['cred_ex_record']['cred_ex_id'])
        #print("cred_ex_id-> " + cred_ex_id)
        #print("----------------")

        #Delete cred def in wallet
        #dleted = requests.delete('http://10.154.0.3:8003/issue-credential-2.0/records/' + cred_ex_id )
        #print("DELETED -> " + dleted.text)#check_credentials = requests.get('http://10.154.0.3:8003/issue-credential-2.0/records')
    #print("GET issue-credential-2.0/records-> " + check_credentials.text)
    pass


async def get_credentials_w3c( did_governament_bbs):
    # Get all my credentials

    data = {
                "@context": [
                                    "https://www.w3.org/2018/credentials/v1",
                                    "https://w3id.org/citizenship/v1"
                                ],
                #"given_id": "https://credential.example.com/residents/333",
                "issuer_id": did_governament_bbs,
                "max_results": 10,
                "proof_types": [
                    "BbsBlsSignature2020"
                ],
                "type": [
                    "VerifiableCredential",
                    "PermanentResident"
                ],
            }

    check_credentials = requests.post('http://10.154.0.3:8003/credentials/w3c', json=data)
    if debug: print("POST credentials/w3c -> " + check_credentials.text)
    json_data = json.loads(check_credentials.text)['results'] 
    print("*** My W3C credentials: ***")
    for i in json_data:
        print("************")
        print("credential-> " + str(i['cred_value']))
        print("************")


async def delete_records_presentation_requests():
    #delete all records of present request
    check_proof = requests.get('http://10.154.0.3:8003/present-proof-2.0/records')
    json_data = json.loads(check_proof.text)['results']
    for i in json_data:
        pres_ex_id = str(i['pres_ex_id'])
        dleted = requests.delete('http://10.154.0.3:8003/present-proof-2.0/records/' + pres_ex_id )
        
    
async def get_records_presentation_requests():
    #get all records
    check_proof = requests.get('http://10.154.0.3:8003/present-proof-2.0/records')
    results = json.loads(check_proof.text)['results']
    for i in results:
        print("----------")
        print("Presentation Request ->" + str(i['pres_request']))
        print("* pres_ex_id ->" + str(i['pres_ex_id']))
        print("----------")

async def get_presentation_request(pres_ex_id):
    print("*** Presentation-request received: ***")
    check_proof = requests.get('http://10.154.0.3:8003/present-proof-2.0/records/' + pres_ex_id)
    print("GET present-proof-2.0/records -> " + check_proof.text)
    message = json.loads(check_proof.text)

    return message

async def get_presentation_proof_credential(pres_ex_id):
    #fetch credential for presentation proof
    fetch_cred = requests.get('http://10.154.0.3:8003/present-proof-2.0/records/' + pres_ex_id + '/credentials')
    print("GET present-proof-2.0/records/" + pres_ex_id + "/credentials -> " + fetch_cred.text)
    creds = json.loads(fetch_cred.text)

    return creds

async def get_cred_def(cred_def_id):
    # get cred definition
    cred_def = requests.get('http://10.154.0.3:8003/credential-definitions/' + cred_def_id)

    return cred_def.text

async def get_schema(schema_id):
    #get transcript schema id
    schema = requests.get('http://10.154.0.3:8003/schemas/' + schema_id)

    return schema.text

async  def create_did_bbs():    
    data = {
            "method": "key",
            "options": {
                "key_type": "bls12381g2" # or ed25519

            },
            }
    create_did_response = requests.post("http://10.154.0.3:8003/wallet/did/create", json=data)
    print("POST wallet/did/create -> " + create_did_response.text)
    return json.loads(create_did_response.text)['result']['did']

async def create_json_record_id(record_id):
    data = {
                    "dif": {
                            "record_ids": {
                              "citizenship_input_1": [ record_id ]
                            }
                          }
                    }

    return data

async def create_json_proposal(input_url, con_id_governament, did_user_bbs, did_governament_bbs):
    data = {
                "connection_id": con_id_governament,
                "comment": "Credential proposal for identity documents: " + input_url,
                "filter": {
                    "ld_proof": {
                        "credential": {
                            "@context": [
                                "https://www.w3.org/2018/credentials/v1",
                                "https://w3id.org/citizenship/v1",
                                {
                                    "isAbove18": {
                                        "@id": "https://example.com/definitions#isAbove18",
                                        "@type": "http://www.w3.org/2001/XMLSchema#boolean"
                                    },
                                    "givenName": "schema:givenName",
                                    "familyName": "schema:familyName",
                                    "gender": "schema:gender",
                                    "birthCountry": "schema:birthCountry",
                                    "birthDate": "schema:birthDate"
                                }

                            ],
                            "type": [
                                "VerifiableCredential",
                                "PermanentResident"
                            ],
                            "id": "https://credential.example.com/residents/aaaa",
                            "issuer": did_governament_bbs,
                            "issuanceDate": "2020-01-01T12:00:00Z",
                            "credentialSubject": {
                                "id": did_user_bbs,
                                "givenName": "MONICAAAAAAAAAAAAAAAAA",
                                "familyName": "MONICAAAAAAAAAAAAAAAAA",
                                "gender": "Female",
                                "birthCountry": "Portugal",
                                "birthDate": "2000-07-17",
                                "isAbove18": True
                            }
                        },
                        "options": {
                            "proofType": "BbsBlsSignature2020"
                        }
                    }
                },
                "trace": True,
                "verification_method": "string"
            }

    return data

async def open_ledger_genesis_file():
    genesis_file_url = 'http://10.128.0.3:9000/genesis'

    # Download the genesis file from the provided URL
    response = requests.get(genesis_file_url)
    genesis_file_path = 'genesis.txn'

    # Save the downloaded genesis file to disk
    with open(genesis_file_path, 'wb') as file:
        file.write(response.content)
        print(f"Genesis file '{response.content}' downloaded successfully.")

    # Open the pool ledger using the downloaded genesis file
    pool_name = 'my_pool'
    pool_config = json.dumps({'genesis_txn': genesis_file_path})


    # Delete the existing pool ledger configuration if it already exists
    try:
        await pool.delete_pool_ledger_config(pool_name)
    except IndyError as ex:
        if ex.error_code != ErrorCode.PoolLedgerConfigNotFoundError:
            raise ex

    # Create and open the pool ledger configuration
    await pool.create_pool_ledger_config(pool_name, pool_config)
    pool_handle = await pool.open_pool_ledger(pool_name, None)

    return pool_handle


async def submit_transaction(pool_handle, wallet_handle, submitter_did, request_json):
    # Sign and submit the transaction request to the pool ledger
    response = await ledger.sign_and_submit_request(pool_handle, wallet_handle, submitter_did, request_json)
    return response

async def create_pool_ledger_config(pool_name, pool_config):
    try:
        await pool.create_pool_ledger_config(pool_name, pool_config)
        print(f"Pool ledger configuration '{pool_name}' created successfully.")
    except IndyError as e:
        if e.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            await pool.delete_pool_ledger_config(pool_name)
            print(f"Existing pool ledger configuration '{pool_name}' deleted.")
            await pool.create_pool_ledger_config(pool_name, pool_config)
            print(f"New pool ledger configuration '{pool_name}' created.")
        else:
            print(f"Error creating pool ledger configuration '{pool_name}': {e}")



async def steward_setup():
    # Set up the wallet and connection details
    wallet_name = 'my_wallet'
    wallet_config = json.dumps({'id': wallet_name})
    wallet_credentials = json.dumps({'key': 'wallet_key'})
    did_info = json.dumps({'seed': '000000000000000000000000Steward1'})

    # Create the wallet
    try:
        await wallet.create_wallet(wallet_config, wallet_credentials)
        print(f"Wallet '{wallet_name}' created successfully.")
    except IndyError as e:
        if e.error_code == ErrorCode.WalletAlreadyExistsError:
            await wallet.delete_wallet(wallet_config, wallet_credentials)
            print(f"Existing wallet '{wallet_name}' deleted.")
            await wallet.create_wallet(wallet_config, wallet_credentials)
            print(f"New wallet '{wallet_name}' created.")
        else:
            print(f"Error creating wallet '{wallet_name}': {e}")

    # Open the wallet
    steward_wallet = await wallet.open_wallet(wallet_config, wallet_credentials)

    # Create and store the DID
    (submitter_did, submitter_verkey) = await did.create_and_store_my_did(steward_wallet, did_info)

    return (submitter_did, steward_wallet)



#****************************************
# MAIN FUNCTIONS
#****************************************

async def createDID():
    print("=== Creating DID ===")
    time_start = time.time()
    did_governament_bls = await create_did_bbs()
    time_finish = time.time()
    sub = float(time_finish) - time_start
    print("time to execute->" + str(sub) + " seconds")

    print("NEW BBS DID: " + did_governament_bls)

async def chooseDID():
    print("=== Choose BBS(bls) DID to use ===")
    did_list = requests.get("http://10.154.0.3:8003/wallet/did")
    dids = json.loads(did_list.text)['results']
    j = 1
    for i in dids:
        print(str(j) + " - DID (type "+ i['key_type'] + "): "+ i['did']) 
        j = j + 1

    print("Choose DID to use:")
    did_index = input()

    return dids[int(did_index) - 1]['did']


    
async def acceptConnection(con_id_governament, con_id_broker, con_id_other):
    print("=== Add Connection ===")
    print(" 1 - Accept Governament connection")
    print(" 2 - Accept Broker connection")
    print(" 3 - Accept other connection")
    print(" 4 - (Demo) Use connections already created")
    print(" 5 - Exit")

    option = input()

    if option == "1":
        print("=== Enter Governament invitate: ===")
        invitation = input()
        global t_start
        t_start = time.time()
        print("time started->" + str(t_start))
        receive_invite = requests.post('http://10.154.0.3:8003/connections/receive-invitation?alias=GovernamentInvitation', json=json.loads(invitation))
        if debug: print("POST connections/receive-invitation -> " + receive_invite.text)
        con_id_governament= json.loads(receive_invite.text)['connection_id']
        print("Governament Connection ID: " + con_id_governament)
        return [con_id_governament, con_id_broker, con_id_other]

    
    elif option == "2":
        print("=== Enter Broker invitate: ===")
        invitation = input()
        receive_invite = requests.post('http://10.154.0.3:8003/connections/receive-invitation?alias=BrokerInvitation', json=json.loads(invitation))
        if debug: print("POST connections/receive-invitation -> " + receive_invite.text)
        con_id_broker = json.loads(receive_invite.text)['connection_id']
        print("Broker Connection ID: " + con_id_broker)
        return [con_id_governament, con_id_broker, con_id_other]

    elif option == "3":
        print("=== Enter Broker invitatoin: ===")
        invitation = input()
        receive_invite = requests.post('http://10.154.0.3:8003/connections/receive-invitation?alias=OtherInvitation', json=json.loads(invitation))
        if debug: print("POST connections/receive-invitation -> " + receive_invite.text)
        con_id_other = json.loads(receive_invite.text)['connection_id']
        print("Other Connection ID: " + con_id_other)
        return [con_id_governament, con_id_broker, con_id_other]

    elif option == "4":
        return [con_id_governament, con_id_broker, con_id_other]

    elif option == "5":
        return []

async def sendMessage(con_id, msg):
    response = requests.post("http://10.154.0.3:8003/connections/" + con_id + "/send-message", json={"content": msg})

async def presentCredential(pres_ex_id, record_id):
    
    data = await create_json_record_id(record_id)  
    
    send_presentation = requests.post("http://10.154.0.3:8003/present-proof-2.0/records/" + pres_ex_id + "/send-presentation", json=data )
    if debug: print("POST present-proof-2.0/records/" + pres_ex_id + "/send-presentation -> " + send_presentation.text)
    print(">>> Presentation sent ")

async def propose_credential(con_id_governament, did_user_bbs, did_governament_bbs, input_url):
    #propose credential
    proposal_json = await create_json_proposal(input_url, con_id_governament, did_user_bbs, did_governament_bbs)
    response = requests.post('http://10.154.0.3:8003/issue-credential-2.0/send-proposal', json=proposal_json)
    print("POST issue-credential-2.0/send-proposal -> " + response.text)



def execute_command(command):
    process = subprocess.Popen(['bash', '-c', command], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    output, _ = process.communicate()
    print(output.decode())
    global t_check
    t_check = time.time()
    print("time check->" + str(t_check))

async def storj(option):
    global t_start
    if option == "1":
        print("=== Enter bucket name: ===")
        bucket_name = input()
        command = f"uplink mb sj://{bucket_name}"
        execute_command(command)
    elif option == "2":
        print("=== Enter bucket name: ===")
        bucket_name = input()
        print("=== Enter file name (on images folder): ===")
        file_name = input()
        t_start = time.time()
        print("t_start->" + str(t_start))
        file_path = os.getcwd() + "/images/" + file_name
        command = f"uplink cp {file_path} sj://{bucket_name}"
        execute_command(command)
    elif option == "3":
        print("=== Enter bucket name: ===")
        bucket_name = input()
        command = f"uplink ls sj://{bucket_name}"
        execute_command(command)
    elif option == "4":
        print("=== Enter bucket name: ===")
        bucket_name = input()
        print("=== Enter file name: ===")
        file_name = input()
        t_start = time.time()
        print("t_start->" + str(t_start))
        command = f"uplink rm sj://{bucket_name}/{file_name}"
        execute_command(command)
    elif option == "5":
        print("=== Enter bucket name: ===")
        bucket_name = input()
        print("=== Enter file name: ===")
        file_name = input()
        t_start = time.time()
        print("t_start->" + str(t_start))
        command = f"uplink share --url sj://{bucket_name}/{file_name}"
        execute_command(command)

async def submit_attr_transaction(steward_did, steward_wallet, pool_handle, attribute_name, attribute_value):

    # START SYMMETRIC ENCRYPTION
    global t_start
    global t_check
    t_start = time.time()
    print("time started encypt->" + str(t_start))

    # Generate a session key for symmetric encryption (example only; implement secure key generation)
    session_key = os.urandom(32)

    # Encrypt data using the session key
    data_bytes = attribute_value.encode('utf-8')
    padder = PKCS7(256).padder()
    padded_data = padder.update(data_bytes) + padder.finalize()

    cipher = Cipher(algorithms.AES(session_key), modes.CFB(b'\x00' * 16), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Convert encrypted data to base64 string
    encrypted_data_base64 = base64.b64encode(encrypted_data).decode('utf-8')

    # Encrypt the session key with the user's public key
    # Load public key from file
    with open("keys/public_key.pem", "rb") as file:
        public_key_pem = file.read()
    
    user_public_key_obj = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
    encrypted_session_key = user_public_key_obj.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Convert encrypted session key to base64 string
    encrypted_session_key_base64 = base64.b64encode(encrypted_session_key).decode('utf-8')

    # FINISH SYMMETRIC ENCRYPTION
    t_check = time.time()
    print("time finished encypt->" + str(t_check))

    raw = {
        attribute_name: {
            "encrypted_data": encrypted_data_base64,
            "session_key": encrypted_session_key_base64,
        }
    }
    raw = json.dumps(raw)

    request_attr = await ledger.build_attrib_request(steward_did, steward_did, None, raw, None)

    response = await submit_transaction(pool_handle, steward_wallet, steward_did, request_attr)
    print(response)
    
    t_check = time.time()
    print("time finished write ledger->" + str(t_check))

async def get_attr_transaction(steward_did, pool_handle, attribute_name):

    # START READ LEDGER
    global t_start
    global t_check
    t_start = time.time()
    print("time started read ledger->" + str(t_start))

    # Read attribute from did
    request_json = await ledger.build_get_attrib_request(steward_did, steward_did, attribute_name, None, None)
    response_json = await ledger.submit_request(pool_handle, request_json)
    response = json.loads(response_json)

    # FINISH READ LEDGER & start encryption
    t_check = time.time()
    print("time finished read ledger->" + str(t_check))

    if response.get("result", {}).get("data"):
        data_json = response["result"]["data"]
        data = json.loads(data_json)

        print("Data JSON from blockchain:", data_json)  # Print the data received from the blockchain

        if attribute_name in data:
            encrypted_data_base64 = data[attribute_name]["encrypted_data"]
            encrypted_session_key_base64 = data[attribute_name]["session_key"]

            # Load private key from file
            with open("keys/private_key.pem", "rb") as file:
                private_key_pem = file.read()
                private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())

            # Decrypt the session key using the private key
            encrypted_session_key = base64.b64decode(encrypted_session_key_base64)
            decrypted_session_key = private_key.decrypt(
                encrypted_session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Decrypt data using the decrypted session key
            encrypted_data = base64.b64decode(encrypted_data_base64)
            cipher = Cipher(algorithms.AES(decrypted_session_key), modes.CFB(b'\x00' * 16), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data_padded = decryptor.update(encrypted_data) + decryptor.finalize()

            # Remove padding
            unpadder = PKCS7(128).unpadder()  # Adjust the block size accordingly (e.g., 128 or 256)
            decrypted_data = unpadder.update(decrypted_data_padded) + unpadder.finalize()

            # Convert decrypted data to string
            decrypted_data_str = decrypted_data.decode('utf-8')
            print("Decrypted Data-> " + decrypted_data_str)

            # FINISH DECRYPTION
            t_check = time.time()
            print("time finished decrypt->" + str(t_check))

        else:
            print("Invalid option: Data not in the expected format.")

    else:
        print("Invalid option: Attribute not found.")

async def other_options(con_id_governament, con_id_broker, con_id_other):

    while True:
        print("=== Other Options ===")
        print("1 - Choose and Exchange DID to use")
        print("2 - Send Message")
        print("3 - Tests")
        print("4 - Exit ")
        print("Choose option:")
        option = input()

        if option == "1":
            did_user_bbs = await chooseDID()
            print("DID chosen: " + did_user_bbs)
        elif option == "2":
            print("== Choose connection to send offer: ==")
            print("1 - Governament")
            print("2 - Broker")
            print("3 - Other")
            print("4 - Exit")

            option = input()

            print("=== Message to send: ===")
            msg = input()

            if option == "1":
                await sendMessage(con_id_governament, msg)
            elif option == "2":
                await sendMessage(con_id_broker, msg)
            elif option == "3":
                await sendMessage(con_id_other, msg)
            elif option == "4":
                return
            else:
                print("Invalid option")
                return 
            
        
        elif option == "3":
            #get cred_ex_id
            print("=== Enter cred_ex_id: ===")
            cred_ex_id = input()
            response = requests.get('http://10.154.0.3:8003/issue-credential-2.0/records/' + cred_ex_id) 
            print("GET issue-credential-2.0/records/cred_ex_id ->" + response.text)
            

        elif option == "4":
            break
        else:
            print("Invalid option")
            continue


async def test_propose(con_ids): 
    did_user_bbs = "did:key:zUC7LDAyMSQU45hsJ75xVkzLzmP3Mh3J5rCtZME4hBpp9Ec8dQvypf1zHT5ewxNMihky4zN5Pcin7wBfAmTKxunLU1cAmbcfWUNYugwAYRDbz1L4p63isjnBSc8SQWA9TJfMZZe"
    issuer_did = "did:key:zUC7FvCNvpitwXqacfV7JxvPUPCthJxdJd3tjWTQb6CmTUbMuaTMxe7Jmo36fiVu2Cvnr2BrGnkfSDnKpNYtkiTxgWxdiV5XvpDs9LY1Kvx2cB5Xja6uNdWd3wCnVFWBjMBmF3N"
    input_url = "ola"
    await propose_credential(con_ids[0], did_user_bbs, issuer_did, input_url)

    

async def run():

    #  --------------------------------------------------------------------------
    # Starting User Agent
    # --------------------------------------------------------------------------

    title = f"User Agent"
    #command = f"bash -c 'cd /home/brunopc/Documents/SOVERE_Prototype/final_version/aries-cloudagent-python-main && aca-py start --inbound-transport http 0.0.0.0 8002 --outbound-transport http --admin-insecure-mode --admin 0.0.0.0 8003 --seed 000000000000000000000000Stewar31 --auto-provision --wallet-type indy --genesis-url http://localhost:9000/genesis --webhook-url http://localhost:8006/webhooks --replace-public-did --wallet-name user_wallet --wallet-key user_wallet_key --log-level info --auto-accept-invites --auto-accept-requests --auto-store-credential --auto-ping-connection --auto-respond-credential-offer --trace-target log --trace-tag acapy.events --label user.Agent -e http://localhost:8002 --debug-connection --debug-presentations --debug-credentials; $SHELL'"	
    #subprocess.Popen(['gnome-terminal', '--window', '--title', title, '--command', command])

    print("====================================")
    print("== User Started  ==")
    print("====================================")
    time.sleep(5)

    # Setup
    #----------
    (steward_did, steward_wallet) = await steward_setup()
    # Open the pool ledger from the genesis file URL
    #pool_handle = await open_ledger_genesis_file()
    #----------
    con_id_governament = "8c800275-df3e-475f-80f6-f91ae3983939"
    con_id_broker = "bb2ce7bc-c178-4d74-9878-ca86fab976e1"
    con_id_other = "nothing"
    con_ids = [con_id_governament, con_id_broker, con_id_other]
    did_user_bbs = "did:key:zUC75K9H1dUAsAYS4WWStFUkxspttgxmvGnmu34xatdpktvbDUuBqQYDJUMXeso7WjFDt7XELcN9TLQ8p9jSrcqVrSBqXungJ4pYKAhVU9eXBrdJvtpKCHFjqftqRWJEPVTxMSg"
    did_governament_bbs = "did:key:zUC7HXaTTZKhMBa6sWnVhZ1tAEWuykJQcv1r2yQ3HMGjGWHSfn7ZoygmSC6q6ivHnRda2PT7ZHpDDG4TQHZ1h5NjtY3sZxAbgbt95yCzfKCUbVgktsozzuj2XCBBkm5G8G18Uv8"

    while True:
        print("****SoverChain****")
        print("1 - Create DID")
        print("2 - Create Secure Connection")
        print("9 - Ask Issuer DID")
        print("3 - Storj Interface")
        print("4 - Propose Credential")
        print("5 - My Credentials")
        print("6 - Access Broker Website")
        print("7 - Other options")
        print("8 - Exit")
        print("10 - write transaction")
        print("11 - read transaction")
        print("Choose option:")
        option = input()
        

        
        if option == "1":
            await createDID()

        elif option == "2":
            #govern,broker,other
            con_ids = await acceptConnection(con_id_governament, con_id_broker, con_id_other)

        elif option == "9":
            #send message to gov requesting non-public DID
            #maybe colocar isto dentro do Propose credential
            
            msg = "Requesting non-public DID"
            await sendMessage(con_ids[0], msg)

        elif option == "3":
            print("== Choose Storj Option ==")
            print("1 - Create bucket to store files")
            print("2 - Upload file to bucket")
            print("3 - List files in bucket")
            print("4 - Delete file from bucket")
            print("5 - Get Share Link of file")

            option = input()

            await storj(option)

        elif option == "4":
            #propose to governament
            print("=== Provide IssuerDID: ===")
            issuer_did = input()
            print("=== Provide url documents to share ===")
            input_url = input()
            time_start = time.time()
            # print("time started->" + str(time_start))
            await propose_credential(con_ids[0], did_user_bbs, issuer_did, input_url)

        elif option == "5":
            #TODO mudar para qualquer credential, testar
            await get_credentials_w3c(did_governament_bbs)
                
        elif option == "6":
            #access broker website
            global t_start
            t_start = time.time()
            print("time started access server->" + str(t_start))
            website_url = "http://10.132.0.3:8016" + "/obtain_access"
            response = requests.post(website_url)
            if response.status_code == 200:
                print('Request sent successfully.')
            else:
                print('Failed to send the request.')
            pass

        elif option == "7":
            await other_options(con_id_governament, con_id_broker, con_id_other)
 
        elif option == "8":
            exit(1)

              
        elif option == "10":
            #await submit_attr_transaction(steward_did, steward_wallet, pool_handle, "my_log", "VAMOSSSSSSSSSS credential residence")
            pass
    
        elif option == "11":
            #await get_attr_transaction(steward_did, pool_handle, "my_log")
            pass

        elif option == "y":
            print("*** Requests Received to Present credentials: ***")

            print("=== Enter the pres_ex_id: ===")
            pres_ex_id = input()

            fetch_cred = requests.get('http://10.154.0.3:8003/present-proof-2.0/records/' + pres_ex_id + '/credentials?count=30')
            available_creds = json.loads(fetch_cred.text)
            print("=== Credentials Available for Presentation: ===" )
            for i in available_creds:
                print("----------")
                print("Credential ->" + str(i["credentialSubject"]))
                print("* record_id ->" + str(i["record_id"]))
                print("----------")

            print("=== Provide record_id to send presentation: ===")
            record_id = input()

            time_start = time.time()
            print("time started->" + str(time_start))
            await presentCredential(pres_ex_id, record_id)
        elif option == "n":
            print("Presentation not sent")


        elif option == "12":
            #Test PROPOSE CREDENTIAL
            print("Provide number of executions:")
            #Number of times to propose credential
            n = input()
            time_start = time.time()
            print ("time started->" + str(time_start))
            int_n = int(n)
            while int_n:
                await test_propose(con_ids)
                int_n = int_n - 1

        elif option == "13":
            #GET TIME FINISH - START
            print("Provide start time :")
            time_start = input()
            print("Provide finish time :")
            time_finsih = input()
            sub = float(time_finsih) - float(time_start)
            print("time to execute->" + str(sub) + " seconds")

        
        
            
        
            

    
if __name__ == '__main__':  
    t1 = Thread(target=app.run, kwargs={'host': '0.0.0.0', 'port': 8006})
    t1.start()
    # Start Flask app  
    loop = asyncio.get_event_loop()
    loop.run_until_complete(run())