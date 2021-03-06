Sign File Contents
------------------
* Certificate and key files must be in pem format
* Files must not use passsword in this version
* Signatures will be PKCS#7 encoded in Base64

---
To execute with Maven: mvn exec:java -Dexec.args="<parameters>"

To build a jar with dependencies: mvn clean compile assembly:single

To run the jar with dependencies: java -jar signingstuff-x.x-jar-with-dependencies.jar 

---

#####Example Commands

######writing signature
```
java -jar signingstuff-x.x-jar-with-dependencies.jar -mode sign -keyType separate -keyFile test.pem -certFile test.cert -in test.txt -det -hash SHA1 > test.signature
```
######writing encapsulated signature
```
java -jar signingstuff-x.x-jar-with-dependencies.jar -mode sign -keyType separate -keyFile test.pem -certFile test.cert -in test.txt -encap -hash SHA256 > test_encap.signature
```
######writing URL encoded signature
```
java -jar signingstuff-x.x-jar-with-dependencies.jar -mode sign -keyType separate -keyFile test.pem -certFile test.cert -in test.txt -det -hash SHA1 -url > testurl.signature
```
######verifying signature
```
java -jar signingstuff-x.x-jar-with-dependencies.jar -mode verify -keyType separate -certFile test.cert -in test.txt -sig test.signature -det -hash SHA1
```
######verifying encapsulated signature
```
java -jar signingstuff-x.x-jar-with-dependencies.jar -mode verify -keyType separate -certFile test.cert -in test_encap.signature -encap -hash SHA256
```
######verifying URL encoded signature
```
java -jar signingstuff-x.x-jar-with-dependencies.jar -mode verify -keyType separate -certFile test.cert -in test.txt -sig testurl.signature -det -hash SHA1 -url
```
---

<pre>
[-------------------------------------------------------------------------]
|              Sign and Verify File Contents v3.0                         |
|-------------------------------------------------------------------------|
| https://github.com/danielmatthewsgrout/signing/tree/master/signingstuff |
[-------------------------------------------------------------------------]

usage: SignVerifyFileContents
 -certAndKeyFile <path>   path to combined certificate and key file
 -certFile <path>         path to certificate file
 -det                     detached signature (not for XML)
 -encap                   encapsulated signature (not for XML)
 -hash <mode>             Hashing Mode: SHA1 or SHA256, SHA384, or SHA512
 -in <path>               path to the input data to sign or verify
 -keyFile <path>          path to key file
 -keyType <type>          how are the keys presented: combined or separate
 -mode <mode>             mode in which to operate: sign or verify - for
                          xml use: xmlSign or xmlVerify
 -sig <path>              path to the detached signature for verification
 -url                     encode/decode signature as URL data
 -v                       display verbose information
</pre>


