import errno
import os
import sys

import psutil as psutil

from openssl_configuration_manager import OpensslConfigurationManager, OpensslCAPolicy, OpensslSigningRequest


def kill_process(proc_pid):
    process = psutil.Process(proc_pid)
    for proc in process.children(recursive=True):
        proc.kill()
    process.kill()

def create_folder_if_not_exists(directory):
    try:
        os.makedirs(directory)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise


def find_between(s, first, last):
    try:
        start = s.index(first) + len(first)
        end = s.index(last, start)
        return s[start:end]
    except ValueError:
        return ""


def create_root_ca_configuration():
    root_ca_openssl_configuration = OpensslConfigurationManager()
    #root_ca_openssl_configuration.add_writer(sys.stdout)
    strict_policy = OpensslCAPolicy(*OpensslCAPolicy.get_default_policy_strict())
    root_ca_openssl_configuration.add_policy(strict_policy)

    signing_policy_air = OpensslCAPolicy("signing_policy_air")
    signing_policy_air.set_policy_parameters("optional", "optional", "optional", "optional", "supplied", "optional")
    root_ca_openssl_configuration.add_policy(signing_policy_air)

    signing_policy_ground = OpensslCAPolicy("signing_policy_gnd")
    signing_policy_ground.set_policy_parameters("optional", "optional", "optional", "optional", "supplied",
                                                "optional")
    root_ca_openssl_configuration.add_policy(signing_policy_ground)

    signing_policy_certificate = OpensslCAPolicy("signing_policy_ser")
    signing_policy_certificate.set_policy_parameters("optional", "optional", "optional", "supplied", "optional",
                                                     "supplied")
    root_ca_openssl_configuration.add_policy(signing_policy_certificate)

    loose_policy = OpensslCAPolicy(*OpensslCAPolicy.get_default_policy_loose())
    root_ca_openssl_configuration.add_policy(loose_policy)

    default_signing_request = OpensslSigningRequest("signing_req")
    default_signing_request.set_signing_request_parameters()
    root_ca_openssl_configuration.add_signing_request(default_signing_request)

    signing_ground_request = OpensslSigningRequest("signing_gnd")
    signing_ground_request.set_signing_request_parameters(extended_key_usage="1.3.6.1.4.1.842.9999.2")
    root_ca_openssl_configuration.add_signing_request(signing_ground_request)

    signing_air_request = OpensslSigningRequest("signing_air")
    signing_air_request.set_signing_request_parameters(extended_key_usage="1.3.6.1.4.1.842.9999.1")
    root_ca_openssl_configuration.add_signing_request(signing_air_request)

    intermediate_ca_signing_request = OpensslSigningRequest("v3_intermediate_ca")
    intermediate_ca_signing_request.set_signing_request_parameters(authority_key_identifier="keyid:always,issuer",
                                                                   basic_constraints="critical, CA:true, pathlen:0",
                                                                   key_usage="critical, digitalSignature, cRLSign, keyCertSign")
    root_ca_openssl_configuration.add_signing_request(intermediate_ca_signing_request)
    return root_ca_openssl_configuration


def create_ca_configuration(sub_ca_name):
    root_ca_openssl_configuration = OpensslConfigurationManager()
    root_ca_openssl_configuration.certs = "$dir/CA/intermediate/" + sub_ca_name + "/certs"
    root_ca_openssl_configuration.crl_dir = "$dir/CA/intermediate/" + sub_ca_name + "/crl"
    root_ca_openssl_configuration.new_certs_dir = "$dir/CA/intermediate/" + sub_ca_name + "/newcerts"
    root_ca_openssl_configuration.database = "$dir/CA/intermediate/" + sub_ca_name + "/index.txt"
    root_ca_openssl_configuration.serial = "$dir/CA/intermediate/" + sub_ca_name + "/serial"
    root_ca_openssl_configuration.private_key = "$dir/CA/intermediate/" + sub_ca_name + "/private/cakey.pem"
    root_ca_openssl_configuration.certificate = "$dir/CA/intermediate/" + sub_ca_name + "/certs/intermediate.cert.pem"

    #root_ca_openssl_configuration.add_writer(sys.stdout)
    strict_policy = OpensslCAPolicy(*OpensslCAPolicy.get_default_policy_strict())
    root_ca_openssl_configuration.add_policy(strict_policy)

    signing_policy_air = OpensslCAPolicy("signing_policy_air")
    signing_policy_air.set_policy_parameters("optional", "optional", "optional", "optional", "supplied", "optional")
    root_ca_openssl_configuration.add_policy(signing_policy_air)

    signing_policy_ground = OpensslCAPolicy("signing_policy_gnd")
    signing_policy_ground.set_policy_parameters("optional", "optional", "optional", "optional", "supplied",
                                                "optional")
    root_ca_openssl_configuration.add_policy(signing_policy_ground)

    signing_policy_certificate = OpensslCAPolicy("signing_policy_ser")
    signing_policy_certificate.set_policy_parameters("optional", "optional", "optional", "supplied", "optional",
                                                     "supplied")
    root_ca_openssl_configuration.add_policy(signing_policy_certificate)

    loose_policy = OpensslCAPolicy(*OpensslCAPolicy.get_default_policy_loose())
    root_ca_openssl_configuration.add_policy(loose_policy)

    default_signing_request = OpensslSigningRequest("signing_req")
    default_signing_request.set_signing_request_parameters()
    root_ca_openssl_configuration.add_signing_request(default_signing_request)

    signing_ground_request = OpensslSigningRequest("signing_gnd")
    signing_ground_request.set_signing_request_parameters(extended_key_usage="1.3.6.1.4.1.842.9999.2")
    root_ca_openssl_configuration.add_signing_request(signing_ground_request)

    signing_air_request = OpensslSigningRequest("signing_air")
    signing_air_request.set_signing_request_parameters(extended_key_usage="1.3.6.1.4.1.842.9999.1")
    root_ca_openssl_configuration.add_signing_request(signing_air_request)

    intermediate_ca_signing_request = OpensslSigningRequest("v3_intermediate_ca")
    intermediate_ca_signing_request.set_signing_request_parameters(authority_key_identifier="keyid:always,issuer",
                                                                   basic_constraints="critical, CA:true, pathlen:0",
                                                                   key_usage="critical, digitalSignature, cRLSign, keyCertSign")
    root_ca_openssl_configuration.add_signing_request(intermediate_ca_signing_request)
    return root_ca_openssl_configuration
