Sign File Contents
------------------
* Certificate and key files must be in pem format
* Files must not use passsword in this version
* Signatures will be PKCS#7 using SHA1withRSA encoded in Base64

---
Usage: SignFileContents separate [path to certificate] [path to private key] [path to data to sign] [encapsulate true or false]

or:    SignFileContents combined [path to pem] [path to data to sign] [encapsulate true or false]
