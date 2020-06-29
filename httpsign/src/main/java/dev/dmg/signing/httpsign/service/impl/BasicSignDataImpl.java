package dev.dmg.signing.httpsign.service.impl;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;

import dev.dmg.signing.httpsign.service.SignData;

public enum BasicSignDataImpl implements SignData {
    INSTANCE;
    public static SignData getData() {
        return INSTANCE;
    }

    @Override
    public byte[] sign(final byte[] data,final PrivateKey privateKey,final String algo, boolean verbose) throws GeneralSecurityException {
       if (verbose) System.out.println("signing " + data.length + "bytes of data with algo: " + algo);
        Signature privateSignature = Signature.getInstance(algo);
        privateSignature.initSign(privateKey);
        privateSignature.update(data);
        return privateSignature.sign();       
    }
}