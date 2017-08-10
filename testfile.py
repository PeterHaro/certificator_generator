ECDSA_parameters_command = CA_OPENSSL_PATH + " ecparam -name secp384r1 -out " + self.CA_PRIVATE_PATH + "/curve_secp384r1.pem"
ECDSA_dump_parameters = CA_OPENSSL_PATH + " ecparam -in " + self.CA_PRIVATE_PATH + "/curve_secp384r1.pem -text -param_enc explicit -noout"
CA_generate_keys_command = CA_OPENSSL_PATH + " ecparam -out " + self.CA_PRIVATE_PATH + "/cakey.pem -genkey -name secp384r1 -noout"
list_key_file_command = CA_OPENSSL_PATH + " ec -in " + self.CA_PRIVATE_PATH + "/cakey.pem -text -noout"
generate_certificate_command = CA_OPENSSL_PATH + " req -new -batch -x509 -sha256 -key " + self.CA_PRIVATE_PATH + "/cakey.pem -config openssl-ca-create.cnf " + \
                                            "-days " + str(CA_ROOT_CERTIFICATE_VALIDITY_DAYS) + " -out " + self.CA_PRIVATE_PATH + "/cacert.pem -outform PEM"
test_certificate_command = CA_OPENSSL_PATH + " x509 -purpose -in " + self.CA_PRIVATE_PATH + "/cacert.pem -inform PEM"
convert_certificate_to_der_command = CA_OPENSSL_PATH + " x509 -in " + self.CA_PRIVATE_PATH + "/cacert.pem -out cacert/cacert.der -outform DER"
dump_ca_certificate_command = CA_OPENSSL_PATH + " x509 -in " + self.CA_PRIVATE_PATH + "/cacert.der -inform DER -text -noout"
