# Self-signed CA certificate generator

This repository were written as a helper-script(s) for the SINTEF projects in the ESA IRIS programme which is all about satellite communication with airplanes

The code in this repository creates a self-hosted CA hierarchy, with intermediate certificates for generation of user certificates. It allows for generation of N-certificates in depths, which are all validated by the scripts. The program creates a file system-tree as by openssl. The hierarchy is as follows: CA/intermediate/{IntermediateName} and for each CA, including the root-CA the following folders are generated: certs, crl, newcerts and private. The naming follows the regular convention and can be found in the man pages.

For each certificate the index, config and serial files are created and populated. The config files are generated and the "create_ca" file contains examples on how this is done 

### Usage
Right now to get an example of how the application can be used se main in create_ca.py
```sh
certificate_manager = CertificateCreator(root_ca_configuration=create_root_ca_configuration())
certificate_manager.perform_ca_certificate_generation()
certificate_manager.perform_intermediate_certificate_generation()
certificate_manager.perform_aircraft_certification_generation()
```
These commands will generate fully valid certificate chains with a generated user certificate in the end. If you'd like to get an actual chain in a single file, you can simply run
```sh
cat CA/intermediate/sub-ca-air/certs/intermediate.cert.pem CA/private/cacert.pem > CA/intermediate/sub-ca-air/certs/ca-chain.cert.pem
```