# KIRK Engine
Near complete implementation of the original kirk-engine

## Updates

* Updated with all known keys (Services 4/7)
* New support for Fuse based encryption/decryption (Services 5/8 and 6/9)
* New Support for Fuse based service 3 decryption and verification
* Updated services for Encryption for use with Service 1 and 3
* Corrected Service 0 to actual kbooti decryption algorithm - missing keys, see to-dos
* Updated Key Vault to be more consistent with actual processor

## To-do

* Missing Key Vault keys 0,1 and 3 (for use with Service 0 and Service 2)
* Missing ECDSA signing support for Service 1 Encryption
* Missing ECDSA support for Service 3
* Missing support for Service 2
* Missing support for Service 18
