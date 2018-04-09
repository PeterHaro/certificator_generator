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


"""
    TODO: Missing implementations
        Load from File
        Partial load
        Generate intermediate based on CA
        cross config policies
        Add interactivemode
"""
import sys


class OpensslSigningRequest(object):
    def __init__(self, request_name, fields=None):
        self.header = "[ " + request_name + " ]"
        if not fields:
            self.fields = {}
        else:
            self.fields = fields

    def set_signing_request_parameters(self, subject_key_identifier="hash", authority_key_identifier="keyid,issuer",
                                       basic_constraints="CA:FALSE", key_usage="digitalSignature, keyEncipherment",
                                       extended_key_usage=None):
        self.fields["subjectKeyIdentifier"] = subject_key_identifier
        self.fields["authorityKeyIdentifier"] = authority_key_identifier
        self.fields["basicConstraints"] = basic_constraints
        self.fields["keyUsage"] = key_usage
        if extended_key_usage is not None:
            self.fields["extendedKeyUsage"] = extended_key_usage


class OpensslCAPolicy(object):
    def __init__(self, policy_name, fields=None):
        self.header = "[ " + policy_name + " ]"
        if not fields:
            self.fields = {}
        else:
            self.fields = fields

    def set_policy_parameters(self, country_name="optional", state_or_province_name="optional",
                              organization_name="optional", organizational_unit_name="optional",
                              common_name="optional", email_address="optional", serial_number=None):
        self.fields["countryName"] = country_name
        self.fields["stateOrProvinceName"] = state_or_province_name
        self.fields["organizationName"] = organization_name
        self.fields["organizationalUnitName"] = organizational_unit_name
        self.fields["commonName"] = common_name
        self.fields["emailAddress"] = email_address
        if serial_number is not None:
            self.fields["serialNumber"] = serial_number

    @staticmethod
    def get_default_policy_strict():
        fields = {"countryName": "match", "stateOrProvinceName": "match", "organizationName": "match",
                  "organizationalUnitName": "optional", "commonName": "supplied", "emailAddress": "optional"}
        return "policy_strict", fields

    @staticmethod
    def get_default_policy_loose():
        fields = {"countryName": "optional", "stateOrProvinceName": "optional", "organizationName": "optional",
                  "organizationalUnitName": "optional", "commonName": "supplied", "emailAddress": "optional"}
        return "policy_loose", fields


class OpensslConfigurationManager(object):
    CA_CERTIFICATE_DIRECTORY_NOTATION = "$dir"
    CA_HEADER_FIELD = "[ ca ]"
    CA_DEFAULT_HEADER_FIELD = "[ CA_default ]"
    CERTIFICATE_REQ_HEADER = "[ req ]"
    CA_DISTINGUISHED_NAME = "[ ca_distinguished_name ]"
    CA_EXTENSIONS_HEADER = "[ ca_extensions ]"
    CERTIFICATE_SIGNING_REQUEST_HEADER = "[ signing_req ]"
    CRL_EXTENSION_HEADER = "[ crl_ext ]"

    SECTION_DIVIDER = "####################################################################"

    def __init__(self):
        self.writers = []

        ##############################################################################################
        # Openssl parameters
        ##############################################################################################
        self.default_ca = "CA_default"
        self.dir = "."
        self.certs = "$dir/certs"
        self.crl_dir = "$dir/crl"
        self.new_certs_dir = "$dir/newcerts"
        self.database = "$dir/index.txt"
        self.serial = "$dir/serial"
        self.randfile = "$dir/private/.rand"

        # The root key and root certificate.
        self.private_key = "$dir/private/cakey.pem"
        self.certificate = "$dir/private/cacert.pem"

        # For certificate revocation lists.
        self.crlnumber = "$dir/crlnumber"
        self.crl = "$dir/crl/ca.crl.pem"
        self.crl_extensions = "crl_ext"
        self.default_crl_days = 30

        self.default_days = 1095  # how long to certify for (3 years=1095)
        self.default_md = "sha256"  # use public key default MD
        self.preserve = "no"  # keep passed DN ordering

        self.name_opt = "ca_default"
        self.cert_opt = "ca_default"
        self.preserve = "no"
        self.policy = "policy_loose"

        self.x509_extensions = "ca_extensions"  # The extensions to add to the cert
        self.email_in_dn = "no"  # Don't concat the email in the DN
        self.copy_extensions = "copy"  # Required to copy SANs from CSR to cert
        self.unique_subject = "no"  # Set to 'no' to allow creation of several certificates with same subject.
        self.crl_extensions = "crl_ext"  # Extensions to add to a CRL

        self.default_bits = 4096
        self.default_keyfile = "cakey.pem"
        self.distinguished_name = "ca_distinguished_name"
        self.string_mask = "utf8only"

        self.countryName = "CountryName(2 letter code)"
        self.stateOrProvinceName = "State or Province Name (full name)"
        self.localityName = "Locality Name (eg, city)"
        self.organizationName = "Organization Name (eg, company)"
        self.organizationalUnitName = "Organizational Unit (eg, division)"
        self.commonName = "Common Name (e.g. server FQDN or YOUR name)"
        self.emailAddress = "Email Address"
        self.countryName_default = "GB"
        self.stateOrProvinceName_default = ""
        self.localityName_default = ""
        self.organizationName_default = "Iris Service Provider"
        self.organizationalUnitName_default = ""
        self.commonName_default = "irisca1"
        self.emailAddress_default = ""

        self.subjectKeyIdentifier = "hash"
        self.authorityKeyIdentifier = "keyid:always, issuer"
        self.basicConstraints = "critical, CA:true"
        self.keyUsage = "keyCertSign, cRLSign"

        self.policies = []
        self.signing_requests = []

    def add_policy(self, policy):  # TODO: IF EMPTY ADD DEFAULT
        if type(policy) is OpensslCAPolicy:
            self.policies.append(policy)
        else:
            # Log throw warning raise?
            print "INVALID POLICY"

    def add_signing_request(self, request):  # TODO: IF EMPTY ADD DEFAULT
        if type(request) is OpensslSigningRequest:
            self.signing_requests.append(request)
        else:
            print "INVALID SIGNING REQUEST"

    def writeline_to_output(self, line):
        for writer in self.writers:
            writer.write(line + "\n")

    def write_padded_key_value_to_output(self, key, value, length):
        for writer in self.writers:
            writer.write(key.ljust(length, " ") + "= " + value + "\n")

    def write_ca_header(self, default_ca="CA_default"):
        self.writeline_to_output(self.CA_HEADER_FIELD)
        if self.default_ca != default_ca:
            self.default_ca = default_ca

        self.writeline_to_output("default_ca = " + self.default_ca)
        self.writeline_to_output("")

    def write_default_authority(self):
        self.writeline_to_output(self.CA_DEFAULT_HEADER_FIELD)
        self.writeline_to_output("dir               = " + self.dir)
        self.writeline_to_output("certs             = " + self.certs)
        self.writeline_to_output("crl_dir           = " + self.crl_dir)
        self.writeline_to_output(
            "new_certs_dir     = " + self.new_certs_dir)
        self.writeline_to_output("database          = " + self.database)
        self.writeline_to_output("serial            = " + self.serial)
        self.writeline_to_output("RANDFILE          = " + self.randfile)
        self.writeline_to_output("")  # Seperator between key and certificate
        self.writeline_to_output(
            "private_key       = " + self.private_key)
        self.writeline_to_output(
            "certificate       = " + self.certificate)
        self.writeline_to_output("")  # Seperator for CRL section
        self.writeline_to_output("crlnumber         = " + self.crlnumber)
        self.writeline_to_output("crl               = " + self.crl)
        self.writeline_to_output("crl_extensions    = " + self.crl_extensions)
        self.writeline_to_output("default_crl_days  = " + str(self.default_crl_days))  # how long before next CRL
        self.writeline_to_output("")  #
        self.writeline_to_output(
            "default_days     = " + str(self.default_days))  # how long to certify for (3 years=1095)
        self.writeline_to_output("default_md       = " + self.default_md)
        self.writeline_to_output("preserve         = " + self.preserve)  # keep passed DN ordering
        self.writeline_to_output("")
        self.writeline_to_output("name_opt          = " + self.default_ca.lower())
        self.writeline_to_output("cert_opt          = " + self.default_ca.lower())
        self.writeline_to_output("policy            = " + self.policy)
        self.writeline_to_output("")
        self.writeline_to_output("x509_extensions  = " + self.x509_extensions)  # The extensions to add to the cert
        self.writeline_to_output("email_in_dn      = " + self.email_in_dn)  # Concat the email in the DN ?
        self.writeline_to_output("copy_extensions  = " + self.copy_extensions)  # Required to copy SANs from CSR to cert
        self.writeline_to_output("unique_subject   = " + self.unique_subject)
        self.writeline_to_output("crl_extensions   = " + self.crl_extensions)
        self.writeline_to_output("")

    def write_req(self):
        self.writeline_to_output(self.SECTION_DIVIDER)
        self.writeline_to_output(self.CERTIFICATE_REQ_HEADER)
        self.writeline_to_output("default_bits        = " + str(self.default_bits))
        self.writeline_to_output("default_keyfile     = " + self.default_keyfile)
        self.writeline_to_output("distinguished_name  = " + self.distinguished_name)
        self.writeline_to_output("x509_extensions     = " + self.x509_extensions)
        self.writeline_to_output("string_mask         = " + self.string_mask)
        self.writeline_to_output("")

    def write_ca_distinguished_name(self):
        self.writeline_to_output(self.SECTION_DIVIDER)
        self.writeline_to_output(self.CA_DISTINGUISHED_NAME)
        self.writeline_to_output("countryName                     = " + self.countryName)
        self.writeline_to_output("stateOrProvinceName             = " + self.stateOrProvinceName)
        self.writeline_to_output("localityName                    = " + self.localityName)
        self.writeline_to_output("organizationName                = " + self.organizationName)
        self.writeline_to_output("organizationalUnitName          = " + self.organizationalUnitName)
        self.writeline_to_output("commonName                      = " + self.commonName)
        self.writeline_to_output("emailAddress                    = " + self.emailAddress)
        self.writeline_to_output("")
        self.writeline_to_output("countryName_default             = " + self.countryName_default)
        self.writeline_to_output("stateOrProvinceName_default     = " + self.stateOrProvinceName_default)
        self.writeline_to_output("localityName_default            = " + self.localityName_default)
        self.writeline_to_output("organizationName_default        = " + self.organizationName_default)
        self.writeline_to_output("organizationalUnitName_default  = " + self.organizationalUnitName_default)
        self.writeline_to_output("commonName_default              = " + self.commonName_default)
        self.writeline_to_output("emailAddress_default            = " + self.emailAddress_default)
        self.writeline_to_output("")

    def write_ca_extensions(self):
        self.writeline_to_output(self.SECTION_DIVIDER)
        self.writeline_to_output(self.CA_EXTENSIONS_HEADER)
        self.writeline_to_output("subjectKeyIdentifier    = " + self.subjectKeyIdentifier)
        self.writeline_to_output("authorityKeyIdentifier  = " + self.authorityKeyIdentifier)
        self.writeline_to_output("basicConstraints        = " + self.basicConstraints)
        self.writeline_to_output("keyUsage                = " + self.keyUsage)
        self.writeline_to_output("")

    def write_policies(self):
        self.writeline_to_output(self.SECTION_DIVIDER)
        for policy in self.policies:
            self.writeline_to_output(policy.header)
            for key, value in policy.fields.iteritems():
                self.write_padded_key_value_to_output(key, value, 25)
            self.writeline_to_output("")

    def write_signing_requests(self):
        self.writeline_to_output(self.SECTION_DIVIDER)
        for request in self.signing_requests:
            self.writeline_to_output(request.header)
            for key, value in request.fields.iteritems():
                self.write_padded_key_value_to_output(key, value, 25)
            self.writeline_to_output("")

    def write_crl_extensions(self):
        self.writeline_to_output(self.SECTION_DIVIDER)
        self.writeline_to_output(self.CRL_EXTENSION_HEADER)
        self.writeline_to_output("authorityKeyIdentifier = keyid:always")
        self.writeline_to_output("")

    def write_oscp(self):
        self.writeline_to_output("[ ocsp ]")
        self.writeline_to_output("basicConstraints = CA:FALSE")
        self.writeline_to_output("subjectKeyIdentifier = hash")
        self.writeline_to_output("authorityKeyIdentifier = keyid,issuer")
        self.writeline_to_output("keyUsage = critical, digitalSignature")
        self.writeline_to_output("extendedKeyUsage = critical, OCSPSigning")
        self.writeline_to_output("")

    def write_user_certificate(self):
        self.writeline_to_output("[ usr_cert ]")
        self.writeline_to_output("basicConstraints = CA:FALSE")
        self.writeline_to_output("nsCertType = client, email")
        self.writeline_to_output('nsComment = "OpenSSL Generated Server Certificate"')
        self.writeline_to_output("subjectKeyIdentifier = hash")
        self.writeline_to_output("authorityKeyIdentifier = keyid,issuer")
        self.writeline_to_output("keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment")
        self.writeline_to_output("extendedKeyUsage = clientAuth, emailProtection")

    def write_config_file(self, default_ca=None, should_write_oscp=False, should_write_user_certificate=False):
        if not self.writers:
            self.writers.append(sys.stdout)
        if default_ca is not None:
            self.write_ca_header(default_ca)
        else:
            self.write_ca_header()
        self.write_default_authority()
        self.write_req()
        self.write_ca_distinguished_name()
        self.write_ca_extensions()
        self.write_policies()
        self.write_signing_requests()
        self.write_crl_extensions()
        if should_write_oscp:
            self.write_oscp()
        if should_write_user_certificate:
            self.write_user_certificate()

    def add_writer(self, writer):
        self.writers.append(writer)

    def cleanup(self):
        for writer in self.writers:
            writer.close()


if __name__ == "__main__":
    pass
