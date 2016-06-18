Sign File Contents
------------------
* Certificate and key files must be in pem format
* Files must not use passsword in this version
* Signatures will be PKCS#7 encoded in Base64

---
To execute with Maven: mvn exec:java -Dexec.args="<parameters>"

To build a jar with dependencies: mvn clean compile assembly:single

To run the jar with dependencies: java -jar signingstuff-1.0-jar-with-dependencies.jar 

---

<pre>
[-------------------------------------------------------------------]
|              Sign and Verify File Contents v2.1                   |
|-------------------------------------------------------------------|
| https://github.com/danielajgrout/signing/tree/master/signingstuff |
[-------------------------------------------------------------------]

usage: SignVerifyFileContents
 -certAndKeyFile <path>   path to combined certificate and key file
 -certFile <path>         path to certificate file
 -det                     detached signature
 -encap                   encapsulated signature
 -hash <mode>             Hashing Mode: SHA1 or SHA256 or SHA512
 -in <path>               path to the input data to sign or verify
 -keyFile <path>          path to key file
 -keyType <mode>          how are the keys presented: combined or separate
 -mode <mode>             mode in which to operate: sign or verify
 -sig <path>              path to the detached signature for verification
                          mode
 -url                     encode/decode as URL
</pre>
