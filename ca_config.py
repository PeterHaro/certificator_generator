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
SUB_CA_CERTIFICATE_VALIDITY_DAYS = 3650
USER_CERTIFICATE_VALIDITY_DAYS = 400


##############################################################################################
# Aircraft information to be used for generating csr tempate
#
##############################################################################################
tail_name = 'JA805A'
aircraft_type = 'B788'
airline = 'ANA'

# DNS1
icao1 = '76543210'
imsi1 = '000000003344156'

# DNS2
icao2 = 'O22334455'
imsi2 = '123456781234567'