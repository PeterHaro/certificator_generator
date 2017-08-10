# Path to openssl
import os

if os.name == "nt":
    CA_OPENSSL_PATH = "C:/openssl-0.9.8h-1-bin/bin/openssl"
else:
    CA_OPENSSL_PATH = '/opt/usr/bin/openssl'

# Path to log file folder
CA_LOG_FILE_FOLDER = '../log/'

# Validity of root certificate when
# creating the CA
CA_ROOT_CERTIFICATE_VALIDITY_DAYS = 3650

