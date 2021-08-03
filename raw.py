from paho.mqtt import client as mqtt
import ssl
import time
import urllib
import urllib.parse
import hmac
import hashlib
import base64
import json
import sys

def get_auth_token(deviceid, hostname, sharedaccesskey, expiry = 60, test = False):
    """
    Generates the MQTT password from the connection string
    """

    if hostname == '' or deviceid == '' or sharedaccesskey == '':
        print('Connection string does not all required elements')
        return ''

    if test: print (hostname, deviceid, sharedaccesskey) 

    resourceUri = urllib.parse.quote(hostname + '/devices/' + deviceid, safe='')
    if test: print(resourceUri)
    expiresAt = (expiry * 60) + int(time.time())
    decodedsak = base64.decodebytes(sharedaccesskey.encode())
    tosign = resourceUri + '\n' + str(expiresAt)
    if test: print(tosign)
    signed = hmac.HMAC(decodedsak, tosign.encode('utf8'), hashlib.sha256)
    signedstr = urllib.parse.quote(base64.b64encode(signed.digest()), safe='')
    if test: print(signedstr)
    token = 'SharedAccessSignature sr=' + resourceUri + '&sig=' + signedstr + '&se=' + str(expiresAt)
    print(token)

    return token

def extract_element(connection_string, element):
    
    workele = element.lower() + '='

    work = connection_string.lower() + ';'
    start = work.find(workele)

    if start == -1:
        print("Connection string is invalid")
        return ""

    start += len(workele)
    end = work.find(';', start)

    if end == -1:
        print("Connection string is invalid")
        return ""

    return connection_string[start:end]

def print_help():
    print("Arguments missing or invalid")
    print("Usage:")
    print(f"\t{sys.argv[0]} <root certificate pems> <device connection string> | <root certificate pems> <host> <deviceId> <x509 certifcate> <x509 private key>")
    exit(4)

print("Starting")

if len(sys.argv) < 3:
    print_help()

if len(sys.argv) != 3 and len(sys.argv) != 6:
    print_help()

# Root certificates
path_to_root_cert = ''
connection_string = ''
iot_hub_name = ''
device_id = ''
shared_access_key = ''
sas_token = ''
message_frequency = 3
SAS_TOKEN_TTL = 3
use_x509 = False
cert_file = None
cert_key = None
expiresAt = 0

if len(sys.argv) == 6:
    path_to_root_cert = sys.argv[1]
    iot_hub_name = sys.argv[2]
    device_id = sys.argv[3]
    cert_file = sys.argv[4]
    cert_key = sys.argv[5]
    use_x509 = True
else:
    connection_string = sys.argv[1]
    device_id = extract_element(connection_string, 'deviceid')
    iot_hub_name = extract_element(connection_string, 'hostname')
    shared_access_key = extract_element(connection_string, 'sharedaccesskey')
    
    if sys.argv[1] != 'x509' and (device_id == "" or iot_hub_name == "" or shared_access_key == ""):
        print("Invalid connection string")
        exit(4)

    sas_token = get_auth_token(device_id, iot_hub_name, shared_access_key, SAS_TOKEN_TTL)
    expiresAt = (SAS_TOKEN_TTL * 60) + int(time.time())

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Device connected with result code: " + str(rc))
        set_up_subscriptions(client)
    else:
        print("Device connection failed - " + rc + ' ' + mqtt.connack_string(rc))

def on_disconnect(client, userdata, rc):
    print("Device disconnected with result code: " + str(rc))
    print(mqtt.error_string(rc))

def on_publish(client, userdata, mid):
    print("Device sent message")

def on_message(client, userdata, message):
    print("Unknown message received")
    print(f"\t  topic={urllib.parse.unquote(message.topic.split('.')[0])}")
    print(f"\tmessage={message.payload.decode('UTF-8')}")

def on_message_C2D(client, userdata, message):
    print("C2D message received")
    print(f"\t  topic={urllib.parse.unquote(message.topic.split('.')[0])}")
    print(f"\tmessage={message.payload.decode('UTF-8')}")

def on_message_direct(client, userdata, message):
    global message_frequency

    print("Direct message received")
    topic = message.topic.split('.')[0]
    topicParts = topic.split('/')
    methodName = topicParts[3]
    rid = topicParts[4]
    print(f"\t method={methodName}")

    if methodName == 'update':
        payload = json.loads(message.payload)
        
        if 'interval' in payload:
            interval = 0

            if type(payload['interval']) == type(int()):
                interval = payload['interval']
            elif type(payload['interval']) == type(str()):
                try:
                    interval = int(payload['interval'])
                except:
                    print(f"\tInterval is invalid")
                    status = 200
                    client.publish(f'$iothub/methods/res/{status}/{rid}', '{ "result": "invalid interval" }')
                    return

            message_frequency = interval
            print(f'\tMessage interval updated to {message_frequency}')
            status = '200'
            client.publish(f'$iothub/methods/res/{status}/{rid}', '{ "result": "frequency updated" }')
            # Update twin
            print("Updating twin")
            reported = {}
            reported['interval'] = message_frequency
            client.publish(f'$iothub/twin/PATCH/properties/reported/?$rid={{{twinrid}}}', json.dumps(reported))
    else:
        print(f"\tmessage={message.payload.decode('UTF-8')}")
        status = '200'
        client.publish(f'$iothub/methods/res/{status}/{rid}', '{ "result": "noop" }')

def on_message_devicetwin(client, userdata, message):
    global message_frequency
    
    print("Device Twin message received")
    topic = message.topic.split('.')[0]
    topicParts = topic.split('/')
    print(f'status={topicParts[3]}')

    if topicParts[3] == '204':
        print('Empty payload')
    else:
        payload = json.loads(message.payload)

        if ('desired' in payload and 'interval' in payload['desired']):
            print(f"Setting interval to desired value of {str(payload['desired']['interval'])}")
            message_frequency = payload['desired']['interval']
            # Update twin
            print("Updating twin")
            reported = {}
            reported['interval'] = message_frequency
            client.publish(f'$iothub/twin/PATCH/properties/reported/?$rid={{{twinrid}}}', json.dumps(reported))
        elif ('reported' in payload and 'interval' in payload['reported']):
            print(f"Setting interval to last reported value of {str(payload['reported']['interval'])}")
            message_frequency = payload['reported']['interval']

        print(json.dumps(payload, indent=4))

def on_message_devicetwinupdate(client, userdata, message):
    global message_frequency
    
    print("Device Twin update message received")
    topic = message.topic.split('.')[0]
    topicParts = topic.split('/')
    print(f"\tVersion={topicParts[5]}")
    payload = json.loads(message.payload)

    if ('interval' in payload):
        print(f"Setting interval to last reported value of {str(payload['interval'])}")
        message_frequency = payload['interval']
        # Update twin
        print("Updating twin")
        reported = {}
        reported['interval'] = message_frequency
        client.publish(f'$iothub/twin/PATCH/properties/reported/?$rid={{{twinrid}}}', json.dumps(reported))

    print(json.dumps(payload, indent=4))

def set_up_subscriptions(client):

    # Subscribe to cloud to device messages 
    client.subscribe(f'devices/{device_id}/messages/devicebound/#')
    client.message_callback_add(f'devices/{device_id}/messages/devicebound/#', on_message_C2D)

    # Subscribe to direct methods
    client.subscribe('$iothub/methods/POST/#')
    client.message_callback_add('$iothub/methods/POST/#', on_message_direct)

    # Subscribe to device twin response messages
    client.subscribe('$iothub/twin/res/#')
    client.message_callback_add('$iothub/twin/res/#', on_message_devicetwin)

    # Subscribe to device twin update messages
    client.subscribe('$iothub/twin/PATCH/properties/desired/#')
    client.message_callback_add('$iothub/twin/PATCH/properties/desired/#', on_message_devicetwinupdate)

twinrid = 0
client = mqtt.Client(client_id=device_id, protocol=mqtt.MQTTv311)
client.username_pw_set(username=iot_hub_name + '/' + device_id + "/?api-version=2018-06-30&DeviceClientType=py-azure-iotdevice%2F2.0.0-preview.13", password=sas_token)

# Certificates will need to be in the same directory as the script
client.tls_set(ca_certs=path_to_root_cert, certfile=cert_file, keyfile=cert_key, cert_reqs=ssl.CERT_REQUIRED, tls_version=ssl.PROTOCOL_TLSv1_2, ciphers=None)
client.tls_insecure_set(False)
client.on_connect = on_connect
client.on_disconnect = on_disconnect
client.on_publish = on_publish
client.on_message = on_message
client.connect(iot_hub_name, port=8883)
client.loop_start()

while client.is_connected() == False:
    time.sleep(0.2)

client.publish(f'$iothub/twin/GET/?$rid={{{twinrid}}}')
twinrid += 1
counter = 0
messageNumber = 0

while True:
    counter += 1

    if counter / 10 >= message_frequency:
        message = {}
        message['data'] = {}
        message['data']['temperature'] = 72
        messageNumber += 1
        message['data']['messagenumber'] = messageNumber
        messageStr = json.dumps(message)
        client.publish("devices/" + device_id + "/messages/events/", messageStr, qos=1)
        counter = 0

    time.sleep(0.1)


    if use_x509 == False and (expiresAt - int(time.time())) < 30:
        print("Reconnecting")
        client.disconnect()
        sas_token = get_auth_token(device_id, iot_hub_name, shared_access_key, SAS_TOKEN_TTL)
        expiresAt = (SAS_TOKEN_TTL * 60) + int(time.time())
        client.username_pw_set(username=iot_hub_name + '/' + device_id + "/?api-version=2018-06-30", password=sas_token)
        client.connect(iot_hub_name, port=8883)

