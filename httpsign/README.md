# HTTPSign v1

## About

This will send a payload to a URL via POST or PUT.  

It will put a PKCS7 signature of the payload, encoded in B64-URL, in the header as "Signature.

## Usage

```none

mvn install

java -jar target/httpsign-1.0-jar-with-dependencies.jar

[-------------------------------------------------------------------------]
|                           HTTPSign v1.0                                 |
|-------------------------------------------------------------------------|
| https://github.com/danielmatthewsgrout/signing/tree/master/httpsign     |
[-------------------------------------------------------------------------]

usage: HTTPSign
 -hash <mode>          Hashing Mode: SHA1 or SHA256, SHA384, or SHA512
 -headersFile <path>   path to headers file - use properties format - key=value
 -in <path>            path to the input data to sign or verify
 -keyFile <path>       path to signing key file in PEM format
 -method <method>      PUT or POST
 -url <url>            URL to use
 -v                    display verbose information
```

## Configuring TLS Mutal Authentication (Client Certificate)

* keystore is where the public/private keys are
* truststore is where the CA goes

```bash
-Djavax.net.ssl.keyStore=client-keystore.jks
-Djavax.net.ssl.keyStorePassword=<password>
-Djavax.net.ssl.trustStore=client-truststore.jks
-Djavax.net.ssl.trustStorePassword=<password>
```

### Enable debugging of SSL

```bash
-Djavax.net.debug=ssl
```

### Testing against Dummy Endpoint

```Bash
java -jar target/httpsign-1.0-jar-with-dependencies.jar -v -hash SHA256 -in test.txt -headersFile headers.txt -keyFile keys/mykey.pem -method POST -url https://postman-echo.com/post
```

### Generating PEM key and X509 cert for testing

#### If you have a keystore then skip first line and amend lines to your config

```bash
keytool -genkeypair -alias mykeys -keyalg RSA -dname "CN=dmg,OU=dev,O=vl,L=bd,C=UK" -keystore mykeys.jks -keypass password -storepass password

keytool -importkeystore -srckeystore mykeys.jks -destkeystore mykeys.p12 -srcstoretype jks -deststoretype pkcs12 -destkeypass password

openssl pkcs12 -in mykeys.p12 -out mykeys.pem

openssl x509 -outform der -in mykeys.pem -out mycert.cert

openssl rsa -in mykeys.pem -nocrypt -out mykey.key
```
