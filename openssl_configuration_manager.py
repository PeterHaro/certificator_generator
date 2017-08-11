class OpensslConfigurationManager(object):
    CA_HEADER_FIELD = "[ ca ]"
    CA_DEFAULT_HEADER_FIELD = "[ CA_default ]"

    def __init__(self, output_configuration_filename = "CA/openssl.cnf"):
        self.output_configuration_filename = output_configuration_filename
        self.output_configuration_file = open(self.output_configuration_filename) #TODO: CHANGE TIS

        ##############################################################################################
        # Openssl parameters
        ##############################################################################################
        self.default_ca = "CA_default"
        self.dir = "."
        self.certs = "$dir/CA/certs"
        self.crl_dir = "$dir/CA/crl"
        self.new_certs.dir = "$dir/CA/newcerts"
        self.database = "$dir/CA/index.txt"
        self.serial = "$dir/CA/serial"
        self.randfile = "$dir/CA/private/.rand"

        # The root key and root certificate.
        self.private_key = "$dir/CA/private/cakey.pem"
        self.certificate = "$dir/CA/private/cacert.pem"

        # For certificate revocation lists.
        self.crlnumber = "$dir/CA/crlnumber"



    def writeline_to_output(self, line):
        self.output_configuration_file.write(line + "\n")

    def write_ca_header(self, default_ca="CA_default"):
        self.writeline_to_output(self.CA_HEADER_FIELD)
        if self.default_ca != default_ca:
            self.default_ca = default_ca

        self.writeline_to_output(self.default_ca)
        self.writeline_to_output("")

    def write_default_authority(self, base_directory="."):
        self.writeline_to_output(self.CA_DEFAULT_HEADER_FIELD)
        self.writeline_to_output("dir               = " + base_directory)
        self.writeline_to_output("certs             = " + base_directory)
        self.writeline_to_output("crl_dir           = " + base_directory)
        self.writeline_to_output("database          = " + base_directory)
        self.writeline_to_output("serial            = " + base_directory)
        self.writeline_to_output("RANDFILE          = " + base_directory)





if __name__ == "__main__":
    pass