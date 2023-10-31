import asyncio
import json
import time
import subprocess
import requests
from threading import Thread
from flask import Flask, request
import logging

debug = False
con_id_constant_user = "5eb69e80-86db-4535-820b-8fa9e1ac641b"

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
    print("ehehehehhe")
    return 'Webhook received and processed successfully', 200


@app.route('/obtain_access/', methods=['POST'])
def obtain():
    print("=== Users wants access ===")
    print("=== Sending Presentation request to user ===")
    return requestPresentation2(con_id_constant_user)


@app.route('/webhooks/topic/present_proof_v2_0/', methods=['POST'])
def present_proof():
    
    event = request.json   
    #print("Received data: " + json.dumps(event)) 

    pres_ex_id = event['pres_ex_id']
    state = event['state']

    if state == "presentation-received":
        print("=== Presentation Received ===")
        print("pres_ex_id: " + pres_ex_id)
        print("=== Starting Verification of Presentation: ===")
        return verifyPresentation(pres_ex_id)
    else:
        print("=== Presentation State: " + state + " ===")


    return 'Webhook received and processed successfully', 200

@app.route('/webhooks/topic/connections/', methods=['POST'])
def connections():
    event = request.json

    state = event['state']

    if state == "active":  
        print("Event: " + str(event))

   
    return 'Webhook received and processed successfully', 200

#****************************************************
# AUX FUNCTIONS
#****************************************************

async def get_public_did():
    did_public = requests.get("http://10.132.0.2:8011/wallet/did/public")
    #print("GET did/public -> " + did_public.text)
    did = json.loads(did_public.text)['result']['did']
    return did

async def create_did_bbs():    
    data = {
            "method": "key",
            "options": {
                "key_type": "bls12381g2" # or ed25519
            },
            }
    create_did_response = requests.post("http://10.132.0.2:8011/wallet/did/create", json=data)
    print("POST wallet/did/create -> " + create_did_response.text)
    return json.loads(create_did_response.text)['result']['did']

def create_json_request_presentation(con_id):
    json_request_presentation = {
                                    "comment": "string",
                                    "connection_id": con_id,
                                    "presentation_request": {
                                        "dif": {
                                            "options": {
                                                "challenge": "3fa85f64-5717-4562-b3fc-2c963f66afa7",
                                                "domain": "4jt78h47fh47"
                        
                                            },
                                            "presentation_definition": {
                                                "id": "32f54163-7166-48f1-93d8-ff217bdb0654",
                                                "format": {
                                                    "ldp_vp": {
                                                        "proof_type": [
                                                            "BbsBlsSignature2020"
                                                        ]
                                                    }
                                                },
                                                "input_descriptors": [
                                                    {
                                                        "id": "citizenship_input_1",
                                                        "name": "Citizen Card",
                                                        "schema": [
                                                            {
                                                                "uri": "https://www.w3.org/2018/credentials#VerifiableCredential"
                                                            },
                                                            {
                                                                "uri": "https://w3id.org/citizenship#PermanentResident"
                                                            }
                                                        ],
                                                        "constraints": {
                                                            "limit_disclosure": "required",
                                                            "is_holder": [
                                                                {   
                                                                    "directive": "required",
                                                                    "field_id": [
                                                                        # "1f44d55f-f161-4938-a659-f8026467f126"
                                                                    ]
                                                                }
                                                            ],
                                                            "fields": [
                                                                {
                                                                    # id optional
                                                                    "path": [
                                                                        "$.credentialSubject.familyName"
                                                                    ],
                                                                    "purpose": "Please provide your surname",
                                                                    #"filter": { "const": "SMITH"} adds constraints to fields
                                                                },
                                                                {
                                                                    "path": [
                                                                        "$.credentialSubject.givenName"
                                                                    ],
                                                                    "purpose": "Please provide your first name",
                                                                },
                                                                {
                                                                    "path": [
                                                                        "$.credentialSubject.isAbove18"
                                                                    ],
                                                                    "purpose": "Please provide a proof of being above 18",

                                                                    "schema": [
                                                                            {
                                                                            "uri": "https://example.com/definitions#isAbove18"
                                                                        }
                                                                    ]
                                                                }
                                                            ]
                                                        }
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
    return json_request_presentation

#****************************************
# MAIN FUNCTIONS
#****************************************

async def createDID():
    print("=== Creating DID ===")
    did_governament_bbs = await create_did_bbs()
    print("BBS DID: " + did_governament_bbs)

async def chooseDID():
    print("=== Choose BBS DID to use ===")
    did_list = requests.get("http://10.132.0.2:8011/wallet/did")
    dids = json.loads(did_list.text)['results']
    j = 1
    for i in dids:
        print(str(j) + " - DID (type "+ i['key_type'] + "): "+ i['did']) 
        j = j + 1

    print("Choose DID to use:")
    did_index = input()

    if int(did_index) > len(dids):
        print("Invalid option")
        return None

    return dids[int(did_index) - 1]['did']


    
async def addConnection():
    print("=== Add Connection ===")
    print(" 1 - Create new connection invitation")
    print(" 2 - Exit")
    option = input()
    

    if option == "1":
        invitation = requests.post("http://10.132.0.2:8011/connections/create-invitation")
        if debug: print("POST connections/create-invitation -> " + invitation.text)

        invitation_json = json.loads(invitation.text)

        con_id = invitation_json['connection_id']
        print("Connection ID: " + con_id)
        print("-----------Invitation to copy -----------")
        print (json.dumps(invitation_json['invitation']))
        print("----------------------------------------")

    elif option == "2":
        con_id = con_id_constant_user
    else:
        print("Invalid option")
        con_id = con_id_constant_user
        
    return con_id
    

async def requestPresentation(con_id):
    data = await create_json_request_presentation(con_id)
    response = requests.post("http://10.132.0.2:8011/present-proof-2.0/send-request", json=data)
    pres_ex_id = json.loads(response.text)['pres_ex_id']
    print("Request pres_ex_id: " + pres_ex_id)

    return pres_ex_id
 

async def sendMessage(con_id):
    print("=== Message to send: ===")
    msg = input()
    response = requests.post("http://10.132.0.2:8011/connections/" + con_id + "/send-message", json={"content": msg})

def verifyPresentation(pres_ex_id):
    response = requests.post("http://10.132.0.2:8011/present-proof-2.0/records/" + pres_ex_id + "/verify-presentation")
    print(">>> Presentation verified: " + json.loads(response.text)['verified'])
    return 'Webhook received and processed successfully', 200

def requestPresentation2(con_id):
    data = create_json_request_presentation(con_id)
    response = requests.post("http://10.132.0.2:8011/present-proof-2.0/send-request", json=data)
    pres_ex_id = json.loads(response.text)['pres_ex_id']
    #print("Request pres_ex_id: " + pres_ex_id)

    return 'Webhook received and processed successfully', 200

async def run():

    #  --------------------------------------------------------------------------
    # Starting Steward Agent
    # --------------------------------------------------------------------------

    #title = f"Broker Agent (SP)"
    #command = f"bash -c 'cd /home/brunopc/Documents/SOVERE_Prototype/final_version/aries-cloudagent-python-main && aca-py start --inbound-transport http 0.0.0.0 8010 --seed 000000000000000000000000Stewar32 --outbound-transport http --admin-insecure-mode --admin 0.0.0.0 8011 --wallet-type indy --genesis-url http://10.132.0.2:9000/genesis --webhook-url http://localhost:8016/webhooks --replace-public-did --auto-provision --wallet-name broker_wallet --wallet-key broker_wallet_key --log-level info --auto-accept-invites --auto-accept-requests --auto-store-credential --auto-ping-connection --auto-respond-credential-offer --trace-target log --trace-tag acapy.events --label broker.Agent -e http://localhost:8010 --debug-connection --debug-credentials; $SHELL'"	
    #subprocess.Popen(['gnome-terminal', '--window', '--title', title, '--command', command])

    #print("====================================")
    print("== Broker Started  ==")
    #print("====================================")
    time.sleep(5)

    #setup
    con_id = con_id_constant_user
    did_broker_bbs = "did:key:zUC7CuDZAv2Z7T7PHsj4qrcnvRvfgym2Q1DFsapqHnhTSWAwMKzmUFRDqbSC5acu297hgn7SwMdBUZrxhqWdjBQgwv448Lc86uUe7S7ZdR9dcdQmntytpWPb58gKsSifxHPxUXM"

    while True:
        print("****Broker****")
        print("1 - Create DID")
        print("2 - Create Connection Invitation")
        print("3 - Request Presentation")
        print("4 - Verify Presentation")
        print("5 - Other options")
        print("6 - Exit")
        print("Choose option:")

        option = input()

        if option == "1":
            await createDID()

        elif option == "2":
            con_id = await addConnection()
            
        elif option == "5":
            pres_ex_id = await requestPresentation(con_id)
        elif option == "6":
            print("Provide pres_ex_id:")
            pres_ex_id = input()
            valid = await verifyPresentation(pres_ex_id)
            print("** Verified Presentation ?  " + valid + "**")

        elif option == "6":
            print("*** Other options ***")
            print("1 - Choose DID to use")
            print("2 - Send messade")
            print("3 - Exit")
            print("Choose option:")
            option = input()

            if option == "1":
                did_broker_bbs = await chooseDID()
            elif option == "2":
                await sendMessage(con_id)
            elif option == "3":
                continue
            else:
                print("Invalid option")
                continue
        
        elif option == "7":
            exit(1)
        else:
            print("Invalid option")

        await asyncio.sleep(0.1) # This is needed to avoid blocking the event loop


if __name__ == '__main__':
    t1 = Thread(target=app.run, kwargs={'host': '0.0.0.0', 'port': 8016})
    t1.start()
    # Start Flask app
    
    loop = asyncio.get_event_loop()
    loop.run_until_complete(run())