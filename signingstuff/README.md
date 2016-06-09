Sign File Contents
------------------
* Certificate and key files must be in pem format
* Files must not use passsword in this version
* Signatures will be PKCS#7 using SHA1withRSA encoded in Base64

---
To execute with Maven:

mvn exec:java -Dexec.args="combined ./src/test/resources/test.pem ./src/test/resources/test.txt false"

To build a jar with dependencies:

mvn clean compile assembly:single

To run the jar with dependencies:

java -jar signingstuff-1.0-jar-with-dependencies.jar