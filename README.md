# Azure-IoT-No-SDK
Simple Python script that acts as a device using direct MQTT interaction that supports both connection string and X.509 authentication.

**Note** The file cert.pem is required. This contains the root certificates for the Azure IoT hub certificate and enables certificate validation.

## Usage

### Connection String
```
python raw.py <Connection String>
```
### X.509
```
python raw.py x509 <FQDN of IoT hub> <device identity> <path to certificate file> <path to private key file>
``` 
