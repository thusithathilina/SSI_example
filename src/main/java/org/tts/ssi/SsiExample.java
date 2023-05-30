package org.tts.ssi;

import com.google.gson.JsonObject;
import org.ttd.did.sdk.DIDDocument;
import org.ttd.did.sdk.DidUtil;
import org.ttd.did.sdk.VerificationMethod;
import org.ttd.vc.*;
import org.ttd.vc.utils.VCUtil;

import java.io.IOException;
import java.net.URI;
import java.security.*;
import java.time.LocalDateTime;

public class SsiExample {
    public static void main(String[] args) throws NoSuchAlgorithmException, SignatureException, IOException, InvalidKeyException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519");
        KeyPair issuerKeyPair = keyPairGenerator.generateKeyPair();
        DIDDocument issuerDidDoc = DidUtil.createDid(issuerKeyPair);

        CredentialSubject credentialSubject = new CredentialSubject();
        credentialSubject.addClaim("name", "Thusitha Dayaratne");
        credentialSubject.addClaim("job", "Research Fellow");
        credentialSubject.addClaim("university", "Monash University");
        credentialSubject.addClaim("id", "0123456789");

        Credential credential = new Credential.Builder()
                .credentialSubject(credentialSubject)
                .build();
        var dateTime = LocalDateTime.now();
        CredentialMetaData credentialMetaData = new CredentialMetaData.Builder()
                .id("vc12345")
                .issuer("MonashUniversity")
                .additionalType("MonashCredential")
                .issuanceDate(dateTime)
                .expirationDate(dateTime.plusYears(1))
                .build();

        VerificationMethod verificationMethod = issuerDidDoc.getVerificationMethods().iterator().next();
        URI uri = URI.create(verificationMethod.getId().getFullQualifiedUrl());
        Proof proof = new Ed25519Signature2020(dateTime, credential, credentialMetaData, uri, "assertion",
                issuerKeyPair.getPrivate());

        VerifiableCredential verifiableCredential = new VerifiableCredential.Builder()
                .credential(credential)
                .metadata(credentialMetaData)
                .proof(proof)
                .build();
        
        JsonObject jsonRepresentation = VCUtil.getJsonRepresentation(verifiableCredential);
        System.out.println(jsonRepresentation);

    }
}
