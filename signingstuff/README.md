Sign File Contents
------------------
* Certificate and key files must be in pem format
* Files must not use passsword in this version
* Signatures will be PKCS#7 encoded in Base64

---
To execute with Maven:

mvn exec:java -Dexec.args="<parameters>"

To build a jar with dependencies:

mvn clean compile assembly:single

To run the jar with dependencies:

java -jar signingstuff-1.0-jar-with-dependencies.jar 

---

Sign and Verify  File Contents v2.0
-----------------------------------------------------------------
https://github.com/danielajgrout/signing/tree/master/signingstuff
------------------------------------------------------------------

usage: SignVerifyFileContents
 -certAndKeyFile <path>   path to combined certificate and key file
 -certFile <path>         path to certificate file
 -hashMode <mode>         Hashing Mode: SHA1 or SHA256 or SHA512
 -in <path>               path to the input data
 -keyFile <path>          path to key file
 -keyType <mode>          how are the keys presented: combined or seperate
 -mode <mode>             mode in which to operate: sign or verify