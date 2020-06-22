package dev.dmg.signing.httpsign.service;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;

public interface SignData {
 
    
    public byte[] sign(byte[] data, PrivateKey privateKey, String algo) throws GeneralSecurityException;

}