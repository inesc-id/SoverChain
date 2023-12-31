import asyncio
import json
import subprocess
import requests
import time
import socket
from threading import Thread
from flask import Flask, request
import logging

debug = False
prev_con_id = "88f9da2b-b90a-4991-8e59-e6c7685c82b9"
did_governament_bbs = "did:key:zUC7HXaTTZKhMBa6sWnVhZ1tAEWuykJQcv1r2yQ3HMGjGWHSfn7ZoygmSC6q6ivHnRda2PT7ZHpDDG4TQHZ1h5NjtY3sZxAbgbt95yCzfKCUbVgktsozzuj2XCBBkm5G8G18Uv8"

#---------------------------------
# FLASK
#---------------------------------
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
app = Flask(__name__)


@app.route('/webhooks', methods=['POST'])
def handle_webhook():
    event = request.json
    
    print("Received data: " + str(event))
          
    
    return 'Webhook received successfully', 200

@app.route('/webhooks/topic/basicmessages/', methods=['POST'])
def basic_messages():
    event = request.json

    content = event['content']
    print("content: " + content)
    if content == "Requesting non-public DID":
        print("===  Received request of non-public DID ===")
        print("===  Sending BBS DID ===")
        return sendBBS_DID()
    else:
        print("===  Received message: " + content + " ===")
    
    print("Received data: " + json.dumps(event)) 



    return 'Webhook received and processed successfully', 200

@app.route('/webhooks/topic/issue_credential_v2_0/', methods=['POST'])
def issue_credential():
    # Extract the event data from the request
    event = request.json

    #print("Bruno: " + json.dumps(event)) 

    #get credential exchange id
    cred_ex_id = event['cred_ex_id']
    state = event['state']
    print("state: " + state)
    if state == "proposal-received":
        print("=== Received proposal ===")

        # record = requests.get("http://10.128.0.3:9021/issue-credential-2.0/records/" + cred_ex_id)
        # print("GET issue-credential2.0/records/(cred_ex_id) -> " + record.text)

        # print("> Received proposal with cred_ex_id: " + cred_ex_id)
        # print("==== Validate document and data from proposal ====")
        # print("==== Send correspondent offer to user? (y/n) ====")
    elif state == "done":
        print("=== Credential issued with success ===")

    return 'Webhook received and processed successfully', 200


@app.route('/webhooks/topic/connections/', methods=['POST'])
def connections():
    event = request.json

    state = event['state']

    if state == "active":
        time_finish = time.time()
        print("time finished->" + str(time_finish))
        #print("Event: " + str(event))

   
    return 'Webhook received and processed successfully', 200

#****************************************************
# AUX FUNCTIONS
#****************************************************

async def check_available_connections():
    connections = requests.get("http://10.128.0.3:9021/connections?state=active")
    print("GET connections?state=active -> " + connections.text)

async def issue_credential(json_send_offer):
    #automate all the flow, stores credential on holder waller
    #No need to send more for now
    print("---  SEND CREDENTIAL -------")
    send_offer = requests.post("http://10.128.0.3:9021/issue-credential-2.0/send", json=json_send_offer)
    print("POST issue-credential2.0/send/(json) -> " + send_offer.text)
    cred_ex_id = json.loads(send_offer.text)['cred_ex_id']
    print("cred_ex_id from issue_credential(): " + cred_ex_id)

async def issue_credential_manual(cred_ex_id):
    #not automated, issue credential manually
    issue_cred = requests.post("http://10.128.0.3:9021/issue-credential-2.0/" + cred_ex_id + "/issue")
    print("POST issue-credential2.0/(cred_ex_id)/issue -> " + issue_cred.text) 

async def fetch_all_credential_records():
    records = requests.get("http://10.128.0.3:9021/issue-credential-2.0/records")
    print("GET issue-credential2.0/records -> " + records.text)
    return records.text

async def fetch_credential_record(cred_ex_id):
    record = requests.get("http://10.128.0.3:9021/issue-credential-2.0/records/" + cred_ex_id)
    print("GET issue-credential2.0/records/(cred_ex_id) -> " + record.text)

async def delete_credential_record(cred_ex_id):
    #Delete records
    records = fetch_all_credential_records() 
    for i in json.loads(records)['results']:
        cred_ex_id = str(i['cred_ex_record']['cred_ex_id'])
        delete_record = requests.delete("http://10.128.0.3:9021/issue-credential-2.0/records/" + cred_ex_id)
        print("DELETE issue-credential2.0/records/(cred_ex_id) -> " + delete_record.text)


async def get_public_did():
    did_public = requests.get("http://10.128.0.3:9021/wallet/did/public")
    #print("GET did/public -> " + did_public.text)
    did = json.loads(did_public.text)['result']['did']
    return did
    
async  def create_did_bbs():    
    data = {
                "method": "key",
                "options": {
                    "key_type": "bls12381g2" # or ed25519
                },

            }
    create_did_response = requests.post("http://10.128.0.3:9021/wallet/did/create", json=data)
    print("POST wallet/did/create -> " + create_did_response.text)
    return json.loads(create_did_response.text)['result']['did']

async def create_json_send_offer(con_id, did_governament_bbs, did_user_bbs):
    data_demo = {
                "connection_id": con_id,
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
                                }
                                }

                            ],
                            "type": [
                                "VerifiableCredential",
                                "PermanentResident"
                            ],
                            "id": "https://credential.example.com/residents/1313",
                            "issuer": did_governament_bbs,
                            "issuanceDate": "2023-06-03T19:23:24Z",
                            "expirationDate": "2025-06-27T19:23:24Z",
                            "credentialSubject": {
                                "type": [
                                    "PermanentResident"
                                ],
                                "id": did_user_bbs,
                                "givenName": "ALBERTO",
                                "familyName": "ALBERTO",
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
                }
            }
    return data_demo

def sendBBS_DID():
    response = requests.post("http://10.128.0.3:9021/connections/" + prev_con_id + "/send-message", json={"content": did_governament_bbs})
    return 'Webhook received successfully', 200



#****************************************
# MAIN FUNCTIONS
#****************************************

async def createDID():
    global did_governament_bbs
    print("=== Creating DID ===")
    did_governament_bbs = await create_did_bbs()
    print("BBS DID: " + did_governament_bbs)

async def chooseDID():
    print("=== Choose BBS DID to use ===")
    did_list = requests.get("http://10.128.0.3:9021/wallet/did")
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


    
async def addConnection(prev_con_id):
    print("=== Add Connection ===")
    print(" 1 - Create new connection invitation")
    print(" 2 - Exit")
    option = input()
    

    if option == "1":
        
        t_start = time.time()
        print("startcreating connection at->" + str(t_start))
        invitation = requests.post("http://10.128.0.3:9021/connections/create-invitation")
        if debug: print("POST connections/create-invitation -> " + invitation.text)

        invitation_json = json.loads(invitation.text)

        con_id = invitation_json['connection_id']
        print("Connection ID: " + con_id)
        print("-----------Invitation to copy -----------")
        print (json.dumps(invitation_json['invitation']))
        print("----------------------------------------")
        t_check = time.time()
        print("end creating invitation->" + str(t_start))
        print("time to create invitation->" + str(t_check - t_start))

    elif option == "2":
        con_id = prev_con_id
    else:
        con_id = prev_con_id
        print("Invalid option")
        
    return con_id
    
#senfing offer without proposal
# async def sendOffer(con_id, did_governament_bbs, did_user_bbs):
#     print("=== Sending Offer ===")
#     data = await create_json_send_offer(con_id, did_governament_bbs, did_user_bbs)
#     send_offer = requests.post("http://10.128.0.3:9021/issue-credential-2.0/send-offer", json=data)
#     print("POST issue-credential2.0/send-offer -> " + send_offer.text)
    

#senfing offer with proposal
async def sendOffer_proposal(cred_ex_id):
   
    print("=== Sending Offer ===")
    #data = await create_json_send_offer(con_id, did_governament_bbs, did_user_bbs)
    send_offer = requests.post("http://10.128.0.3:9021/issue-credential-2.0/records/" + cred_ex_id + "/send-offer")
    print("POST issue-credential2.0/records/cred_ex_id/send-offer -> " + send_offer.text)
   
 

async def sendMessage(con_id, msg):
    response = requests.post("http://10.128.0.3:9021/connections/" + con_id + "/send-message", json={"content": msg})


async def run():
    #  --------------------------------------------------------------------------
    # Starting Steward Agent
    # --------------------------------------------------------------------------


    title = f"governament  Agent (Issuer)"
    #command = f"bash -c 'cd /home/brunopc/Documents/SOVERE_Prototype/final_version/aries-cloudagent-python-main && aca-py start --inbound-transport http 0.0.0.0 9020 --outbound-transport http --admin-insecure-mode --admin 0.0.0.0 9021 --seed 000000000000000000000000Stewar33 --trace-target log --trace-tag acapy.events --log-level info --replace-public-did --wallet-type indy --genesis-url http://10.128.0.3:9000/genesis --webhook-url http://10.128.0.3:9002/webhooks --auto-provision --wallet-name theGovernament_wallet --wallet-key theGovernament_wallet_key --auto-respond-credential-proposal --auto-accept-invites --auto-accept-requests --auto-ping-connection --auto-respond-credential-request --label Governament.Agent -e http://10.128.0.3:9020 --debug-connection --debug-credentials; $SHELL'"	
    #subprocess.Popen(['gnome-terminal', '--window', '--title', title, '--command', command])
    
    #vm google
    #command = f"bash -c 'cd /SOVERE_Prototype/final_version/aries-cloudagent-python-main && aca-py start --inbound-transport http 0.0.0.0 9020 --outbound-transport http --admin-insecure-mode --admin 0.0.0.0 9021 --seed 000000000000000000000000Stewar33 --trace-target log --trace-tag acapy.events --log-level info --replace-public-did --wallet-type indy --genesis-url http://34.68.23.68:9000/genesis --webhook-url http://34.68.23.68:9002/webhooks --auto-provision --wallet-name theGovernament_wallet --wallet-key theGovernament_wallet_key --auto-respond-credential-proposal --auto-accept-invites --auto-accept-requests --auto-ping-connection --auto-respond-credential-request --label Governament.Agent -e http://34.68.23.68:9020 --debug-connection --debug-credentials; $SHELL'"	
    #subprocess.Popen(command, shell=True)

    print("====================================")
    print("== Governament Started  ==")
    print("====================================")
    time.sleep(5)
    con_id = prev_con_id

    #setup connection and dids
    global did_governament_bbs

    while True:
        print("****Governament****")
        print("1 - Create DID")
        print("2 - Create Connection Invitation")
        print("3 - Send Offer")
        print("4 - Other options")
        print("5 - Exit")
        print("Choose option:")

        option = input()

        if option == "1":
            await createDID()

        elif option == "2":
            con_id = await addConnection(prev_con_id)

        elif option == "3" or option == "y":
            print("=== Provide cred_ex_id: ===")
            cred_ex_id = input()
            await sendOffer_proposal(cred_ex_id)

        elif option == "4":
            print("*** Other options ***")
            print("1 - Choose DID")
            print("2 - Send Message")
            print("3 - Tests")
            
            print("4 - Exit")
            print("Choose option:")
            option = input()

            if option == "1":
                did_governament_bbs = await chooseDID()
            elif option == "2":
                print("=== Message to send: ===")
                msg = input()
                await sendMessage(con_id, msg)
            elif option == "3":
                print("Provide cred_ex_id:")
                cred_ex_id = input()
                await fetch_credential_record(cred_ex_id)
            elif option == "4":
                continue
            else:
                print("Invalid option")


        elif option == "5":
            exit(1)
        
        elif option == "n":
            print("=== Proposal not valid ===")
            msg = "Proposal not valid"
            await sendMessage(con_id, msg)
              
        else:
            print("Invalid option")

        await asyncio.sleep(0.1) 

            

if __name__ == '__main__':
    t1 = Thread(target=app.run, kwargs={'host': '0.0.0.0', 'port': 9002})
    t1.start()
    # Start Flask app
    
    loop = asyncio.get_event_loop()
    loop.run_until_complete(run())