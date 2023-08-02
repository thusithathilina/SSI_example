package org.tts.ssi;

import com.auth0.jwt.algorithms.Algorithm;
import com.google.gson.JsonObject;
import org.bouncycastle.crypto.prng.FixedSecureRandom;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ttd.did.sdk.DIDDocument;
import org.ttd.did.sdk.DidUtil;
import org.ttd.did.sdk.VerificationMethod;
import org.ttd.vc.*;
import org.ttd.vc.utils.Mnemonic;
import org.ttd.vc.utils.VCUtil;

import java.io.IOException;
import java.net.URI;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.LocalDateTime;

public class SsiExample {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    public static void main(String[] args) throws GeneralSecurityException, IOException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
        byte[] keyBytesForSender = Mnemonic.toKey("sponsor ride say achieve senior height crumble promote " +
                "universe write dove bomb faculty side human taste paper grocery robot grab reason fork soul above " +
                "sphere");
        keyPairGenerator.initialize(256, new FixedSecureRandom(keyBytesForSender));
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

        /* embedded proof is not required when using JWT
        Proof proof = new Ed25519Signature2020(dateTime, credential, credentialMetaData, uri, "assertion",
                issuerKeyPair.getPrivate());
         */

        VerifiableCredential verifiableCredential = new VerifiableCredential.Builder()
                .credential(credential)
                .metadata(credentialMetaData)
//                .proof(proof) //embedded proof is not required when using JWT
                .build();
        
        JsonObject jsonRepresentation = VCUtil.getJsonRepresentation(verifiableCredential);
        System.out.println(jsonRepresentation);

        Algorithm algorithm = Algorithm.ECDSA256(null, (ECPrivateKey) issuerKeyPair.getPrivate());

        // Generate an external proof for the VC (JWT)
        String vcJwt = VCUtil.vcToJwT(verifiableCredential, algorithm);
        System.out.println(vcJwt);

        // Verify the JWT
        Verifier.verify(vcJwt, Algorithm.ECDSA256((ECPublicKey) issuerKeyPair.getPublic(), null));
        System.out.println("JWT verification success");

    }
}
