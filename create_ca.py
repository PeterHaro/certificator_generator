#!/usr/bin/env python
import subprocess
import time

import sys

from ca_config import *
from logger import Logger
from utility import create_folder_if_not_exists, find_between


class CertificateCreator(object):
    TMP = "./log"
    LOG_FILENAME = TMP + "/%s_%d.log" % (time.strftime("%Y%m%d_%H%M%S"), os.getpid())
    LOG_LEVEL = Logger.ALL
    OUTPUT_FILENAME = TMP + "/output.log"
    OUTPUT_LOGLEVEL = Logger.ALL
    CA_CERT_PATH = "CA/certs"
    CA_CRL_PATH = "CA/crl"
    CA_NEW_CERTS_PATH = "CA/newcerts"
    CA_PRIVATE_PATH = "CA/private"
    CA_INTERMEDIATE_PATH = "CA/intermediate"
    """
            CA_INTERMEDIATE_CERTS_PATH = self.CA_INTERMEDIATE_PATH + "/certs"
            CA_INTERMEDIATE__CRL_PATH = self.CA_INTERMEDIATE_PATH + "/crl"
            CA_INTERMEDIATE_CSR_PATH = self.CA_INTERMEDIATE_PATH + "/csr"
            CA_INTERMEDIATE_NEWCERTS_PATH = self.CA_INTERMEDIATE_PATH + "/newcerts"
            CA_INTERMEDIATE_PRIVATE_PATH = self.CA_INTERMEDIATE_PATH + "/private"
    """

    def __init__(self):
        # logging
        self.logfile = open(self.LOG_FILENAME, "a+")
        self.l = Logger(self.logfile, self.LOG_LEVEL, str(os.getpid()))
        self.l.add_writer(sys.stdout, self.LOG_LEVEL)
        self.output = open(self.OUTPUT_FILENAME, "a+")
        self.l.add_writer(self.output, self.OUTPUT_LOGLEVEL)

        # CA parameters
        self.ca_names = ["irisca1", "irisca2"]
        self.ECDSA_parameters_command = CA_OPENSSL_PATH + " ecparam -name secp384r1 -out " + self.CA_PRIVATE_PATH + "/curve_secp384r1.pem"
        self.ECDSA_dump_parameters = CA_OPENSSL_PATH + " ecparam -in " + self.CA_PRIVATE_PATH + "/curve_secp384r1.pem -text -param_enc explicit -noout"
        self.CA_generate_keys_command = CA_OPENSSL_PATH + " ecparam -out " + self.CA_PRIVATE_PATH + "/cakey.pem -genkey -name secp384r1 -noout"
        self.list_key_file_command = CA_OPENSSL_PATH + " ec -in " + self.CA_PRIVATE_PATH + "/cakey.pem -text -noout"
        self.generate_certificate_command = CA_OPENSSL_PATH + " req -new -batch -x509 -sha256 -key " + self.CA_PRIVATE_PATH + "/cakey.pem -config CA/openssl.cnf " + \
                                            "-days " + str(
            CA_ROOT_CERTIFICATE_VALIDITY_DAYS) + " -out " + self.CA_PRIVATE_PATH + "/cacert.pem -outform PEM"
        self.test_certificate_command = CA_OPENSSL_PATH + " x509 -purpose -in " + self.CA_PRIVATE_PATH + "/cacert.pem -inform PEM"
        self.convert_certificate_to_der_command = CA_OPENSSL_PATH + " x509 -in " + self.CA_PRIVATE_PATH + "/cacert.pem -out " + self.CA_PRIVATE_PATH + "/cacert.der -outform DER"
        self.dump_ca_certificate_command = CA_OPENSSL_PATH + " x509 -in " + self.CA_PRIVATE_PATH + "/cacert.der -inform DER -text -noout"

        # Intermediate parameters
        self.intermediate_ca_names = ["sub-ca-air", "sub-ca-gnd"]
        # self.intermediate_ECDSA_parameters_command = CA_OPENSSL_PATH + " ecparam -name secp384r1 -out " + self.CA_INTERMEDIATE_PRIVATE_PATH + "/curve_secp384r1.pem"
        self.ECDSA_dump_parameters = CA_OPENSSL_PATH + " ecparam -in " + self.CA_PRIVATE_PATH + "/curve_secp384r1.pem -text -param_enc explicit -noout"
        self.CA_generate_keys_command = CA_OPENSSL_PATH + " ecparam -out " + self.CA_PRIVATE_PATH + "/cakey.pem -genkey -name secp384r1 -noout"
        self.list_key_file_command = CA_OPENSSL_PATH + " ec -in " + self.CA_PRIVATE_PATH + "/cakey.pem -text -noout"
        self.generate_certificate_command = CA_OPENSSL_PATH + " req -new -batch -x509 -sha256 -key " + self.CA_PRIVATE_PATH + "/cakey.pem -config CA/openssl.cnf " + \
                                            "-days " + str(
            CA_ROOT_CERTIFICATE_VALIDITY_DAYS) + " -out " + self.CA_PRIVATE_PATH + "/cacert.pem -outform PEM"
        self.test_certificate_command = CA_OPENSSL_PATH + " x509 -purpose -in " + self.CA_PRIVATE_PATH + "/cacert.pem -inform PEM"
        self.convert_certificate_to_der_command = CA_OPENSSL_PATH + " x509 -in " + self.CA_PRIVATE_PATH + "/cacert.pem -out " + self.CA_PRIVATE_PATH + "/cacert.der -outform DER"
        self.dump_ca_certificate_command = CA_OPENSSL_PATH + " x509 -in " + self.CA_PRIVATE_PATH + "/cacert.der -inform DER -text -noout"

        self.lastOperationOutput = None

        # Create file structures
        # ROOT CA STRUCTURE
        create_folder_if_not_exists(self.CA_CERT_PATH)
        create_folder_if_not_exists(self.CA_CRL_PATH)
        create_folder_if_not_exists(self.CA_NEW_CERTS_PATH)
        create_folder_if_not_exists(self.CA_PRIVATE_PATH)
        with open("CA/index.txt", "w+") as touchFile:
            pass
        with open("CA/serial", "w+") as writeFile:
            writeFile.write("1000")

        # Intermediate file structure
        create_folder_if_not_exists(self.CA_INTERMEDIATE_PATH)
        for sub_ca in self.intermediate_ca_names:
            sub_ca_path = self.CA_INTERMEDIATE_PATH + "/" + sub_ca
            create_folder_if_not_exists(sub_ca_path + "/certs")
            create_folder_if_not_exists(sub_ca_path + "/crl")
            create_folder_if_not_exists(sub_ca_path + "/csr")
            create_folder_if_not_exists(sub_ca_path + "/newcerts")
            create_folder_if_not_exists(sub_ca_path + "/private")
            with open(sub_ca_path + "/index.txt", "w+") as touchFile:
                pass
            with open(sub_ca_path + "/serial", "w+") as writeFile:
                writeFile.write("1000")
            with open(sub_ca_path + "/crlnumber", "w+") as writeFile:
                writeFile.write("1000")

    def dump_and_fetch_ca_certificate(self, store_output=False):
        self.l.info("Dumping CA certificate")
        self.execute_command(self.dump_ca_certificate_command, store_output)

    def convert_certificate_to_der(self):
        self.l.info("Converting certificate to DER")
        self.execute_command(self.convert_certificate_to_der_command)

    def test_certificate(self):
        self.l.info("Testing certificate")
        self.execute_command(self.test_certificate_command)

    def generate_certificate(self):
        self.l.info("Generating certificate")
        self.execute_command(self.generate_certificate_command)

    def dump_ecdsa_parameters(self):
        self.l.info("Entering dump_ecdsa_parameters")
        self.execute_command(self.ECDSA_dump_parameters)

    def generate_ECDSA_parameters(self):
        self.l.info("Entering generate_ECDSAparameters")
        self.execute_command(self.ECDSA_parameters_command)

    def generate_root_key(self):
        self.l.info("Generating a key pair for CA")
        self.execute_command(self.CA_generate_keys_command)
        self.l.info("Listing key file")
        self.execute_command(self.list_key_file_command)

    def execute_command(self, command, store_output=False):
        process = subprocess.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, err = process.communicate()
        if store_output:
            self.lastOperationOutput = output
        self.l.debug(output)
        self.l.debug(err)
        if process.returncode:
            self.l.critical('FAILURE - return code %d' % process.returncode)
            sys.exit(-1)

    # Vertification
    def validate_ca_certificate_entries(self):
        self.l.info("Validating CA certificate")
        validation_error_message = "\nThis CA is has aan invalid name compared to its position and MUST NOT BE USED." + \
                                   "\nCreating certificates will not be possible. Openssl configuration file error?"
        if self.lastOperationOutput is None:
            self.dump_and_fetch_ca_certificate(True)
        ca_issuer = find_between(find_between(self.lastOperationOutput, "Issuer", "\n") + "\n", "CN=", "\n")
        ca_subject = find_between(find_between(self.lastOperationOutput, "Subject", "\n") + "\n", "CN=", "\n")
        if ca_issuer not in self.ca_names:
            self.l.critical(self.lastOperationOutput)
            self.l.critical(
                'FAILURE - The CA issuer CN = %s, installed in %s. %s' % (ca_issuer, "", validation_error_message))
        if ca_subject not in self.ca_names:
            self.l.critical(self.lastOperationOutput)
            self.l.critical(
                'FAILURE - The CA issuer CN = %s, installed in %s. %s' % (ca_subject, "", validation_error_message))

    def perform_ca_certificate_generation(self):
        self.generate_ECDSA_parameters()
        self.dump_ecdsa_parameters()
        self.generate_root_key()
        self.generate_certificate()
        self.test_certificate()
        self.convert_certificate_to_der()
        self.dump_and_fetch_ca_certificate(True)

    def perform_intermediate_certificate_generation(self):
        for intermediate_certificate_name in self.intermediate_ca_names:
            self.generate_intermediate_key_parameters(intermediate_certificate_name)

    def dump_ecdsa_intermediate_key_parameters(self, name):
        self.l.info("Entering dump_intermediate_ecdsa_parameters")
        intermediate_private_path = self.CA_INTERMEDIATE_PATH + "/" + name + "/private/"
        command = CA_OPENSSL_PATH + " ecparam -in " + intermediate_private_path + name + ".pem -text -param_enc_explicit -noout"
        self.execute_command(command)

    def generate_intermediate_key_parameters(self, name):
        self.l.info("Creating intermediate key for: " + name)
        command = CA_OPENSSL_PATH + " ecparam -name secp384r1 -out " + self.CA_INTERMEDIATE_PATH + "/" + name + "/private/" + name + ".pem"
        self.execute_command(command)

    def generate_intermediate_key(self, name):
        self.l.info("Generating a key pair for INTERMEDIATE: " + name)
        self.execute_command(self.CA_generate_keys_command)
        self.l.info("Listing key file")
        self.execute_command(self.list_key_file_command)

if __name__ == "__main__":
    certificate_manager = CertificateCreator()
    certificate_manager.perform_ca_certificate_generation()
