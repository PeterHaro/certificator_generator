"""Copyright [2018] [Peter Haro]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License."""

import errno
import os

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


def create_signing_policy_air():
    air_signing_request = OpensslCAPolicy("signing_policy_air")
    air_signing_request.set_policy_parameters(common_name="supplied")
    return air_signing_request


def create_signing_policy_ground():
    air_signing_request = OpensslCAPolicy("signing_policy_gnd")
    air_signing_request.set_policy_parameters(common_name="supplied")
    return air_signing_request


def create_signing_policy_certificate():
    air_signing_request = OpensslCAPolicy("signing_policy_cer")
    air_signing_request.set_policy_parameters(common_name="supplied", serial_number="supplied")
    return air_signing_request


def create_signing_req():
    request = OpensslSigningRequest("signing_req")
    request.set_signing_request_parameters()
    return request


def create_signing_gnd():
    request = OpensslSigningRequest("signing_gnd")
    request.set_signing_request_parameters("1.3.6.1.4.1.842.9999.2")
    return request


def create_signing_air():
    request = OpensslSigningRequest("signing_air")
    request.set_signing_request_parameters("1.3.6.1.4.1.842.9999.1")
    return request


def create_root_ca_configuration(relative_path_to_root=""):
    root_ca_openssl_configuration = OpensslConfigurationManager()
    # root_ca_openssl_configuration.add_writer(sys.stdout)
    if relative_path_to_root != "":
        root_ca_openssl_configuration.dir = ("./" + relative_path_to_root)
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


def create_ca_configuration(sub_ca_name, relative_path_to_root=""):
    root_ca_openssl_configuration = OpensslConfigurationManager()
    if relative_path_to_root != "":
        if relative_path_to_root.startswith("."):
            root_ca_openssl_configuration.dir = relative_path_to_root
        else:
            root_ca_openssl_configuration.dir = ("." + relative_path_to_root)
    root_ca_openssl_configuration.certs = "$dir/intermediate/" + sub_ca_name + "/certs"
    root_ca_openssl_configuration.crl_dir = "$dir/intermediate/" + sub_ca_name + "/crl"
    root_ca_openssl_configuration.new_certs_dir = "$dir/intermediate/" + sub_ca_name + "/newcerts"
    root_ca_openssl_configuration.database = "$dir/intermediate/" + sub_ca_name + "/index.txt"
    root_ca_openssl_configuration.serial = "$dir/intermediate/" + sub_ca_name + "/serial"
    root_ca_openssl_configuration.private_key = "$dir/intermediate/" + sub_ca_name + "/private/cakey.pem"
    root_ca_openssl_configuration.certificate = "$dir/intermediate/" + sub_ca_name + "/certs/intermediate.cert.pem"

    root_ca_openssl_configuration.add_policy(create_signing_policy_air())
    root_ca_openssl_configuration.add_policy(create_signing_policy_ground())
    root_ca_openssl_configuration.add_policy(create_signing_policy_certificate())

    root_ca_openssl_configuration.add_signing_request(create_signing_req())
    root_ca_openssl_configuration.add_signing_request(create_signing_air())
    root_ca_openssl_configuration.add_signing_request(create_signing_gnd())

    return root_ca_openssl_configuration
