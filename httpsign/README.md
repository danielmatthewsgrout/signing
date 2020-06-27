# HTTPSign v1

## Usage

```none
[-------------------------------------------------------------------------]
|                           HTTPSign v1.0                                 |
|-------------------------------------------------------------------------|
| https://github.com/danielmatthewsgrout/signing/tree/master/httpsign     |
[-------------------------------------------------------------------------]

usage: HTTPSign
 -hash <mode>          Hashing Mode: SHA1 or SHA256, SHA384, or SHA512
 -headersFile <path>   path to headers file - use properties format -
                       key=value
 -in <path>            path to the input data to sign or verify
 -keyFile <path>       path to key file
 -method <method>      PUT or POST
 -url <url>            URL to use
 -v                    display verbose information
```

## Configuring TLS Mutal Authentication (Client Certificate)

* keystore is where the keys are
* truststore is where the CA goes

```bash
-Djavax.net.ssl.keyStore=client-keystore.jks
-Djavax.net.ssl.keyStorePassword=<password>
-Djavax.net.ssl.trustStore=client-truststore.jks
-Djavax.net.ssl.trustStorePassword=whatever
```

### Enable debugging of SSL

```bash
-Djavax.net.debug=ssl
```
