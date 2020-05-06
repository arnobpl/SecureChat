package com.arnobpaul.client;

import com.arnobpaul.common.AppConfig;
import com.arnobpaul.common.ClientEntity;
import com.arnobpaul.common.crypto.AsymmetricKeyPair;
import com.arnobpaul.common.crypto.RsaGenEncDec;
import com.arnobpaul.common.crypto.RsaSignVerify;
import org.jetbrains.annotations.NotNull;

import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.sql.SQLException;
import java.util.logging.Logger;

public class RenewService {
    private final ClientTask clientTask;

    private final DbService dbService;
    private final SignupLoginService signupLoginService;

    private final RsaGenEncDec rsaGenEncDec;
    private final RsaSignVerify rsaSignVerify;

    private ClientEntity loginClient = null;
    private AsymmetricKeyPair newAsymmetricKeyPair = null;

    private static final Logger logger = Logger.getLogger(RenewService.class.getName());

    public RenewService(@NotNull ClientTask clientTask,
                        @NotNull DbService dbService,
                        @NotNull SignupLoginService signupLoginService,
                        @NotNull RsaGenEncDec rsaGenEncDec,
                        @NotNull RsaSignVerify rsaSignVerify) {
        this.clientTask = clientTask;
        this.dbService = dbService;
        this.signupLoginService = signupLoginService;
        this.rsaGenEncDec = rsaGenEncDec;
        this.rsaSignVerify = rsaSignVerify;
    }

    synchronized public boolean requestRenew(String data) {
        loginClient = signupLoginService.getLoginClient();
        if (loginClient == null) {
            System.err.println("Client must be logged in to renew public key.");
            return false;
        }

        if (data == null) {
            System.err.println("Please provide your Client_ID to renew public key.");
            return false;
        }

        int clientId;
        try {
            clientId = Integer.parseInt(data);
        } catch (NumberFormatException e) {
            e.printStackTrace();
            logger.warning(e.getMessage());
            return false;
        }

        if (clientId != loginClient.clientId) {
            System.err.println("ERROR! Client_ID must be matched with the loginClientId.");
            return false;
        }

        newAsymmetricKeyPair = rsaGenEncDec.generateKey(AppConfig.RSA_KEY_SIZE);

        clientTask.sendRaw(AppConfig.NetworkCommand.RENEW_KEY_REQUEST);

        System.out.println("Renew request sent to the server.");
        return true;
    }

    synchronized public boolean processRenew(String header, String data) {
        switch (header) {
            case AppConfig.NetworkCommand.RENEW_KEY_OK:
                if (data == null) {
                    System.err.println(String.format("Null data received for Header: %s",
                            header));
                    return false;
                }

                if (newAsymmetricKeyPair == null) {
                    System.err.println(String.format("Unexpected data received for Header: %s ; Data: %s",
                            header,
                            data));
                    return false;
                }

                String oldSignature;
                try {
                    oldSignature = rsaSignVerify.sign(newAsymmetricKeyPair.publicKey, loginClient.clientPrivateKey);
                } catch (InvalidKeySpecException | InvalidKeyException | SignatureException e) {
                    e.printStackTrace();
                    logger.warning(e.getMessage());
                    return false;
                }

                String[] dataItems = data.split(" ", 2);
                if (dataItems.length != 2) {
                    System.err.println(String.format("Data error for Header: %s ; Data: %s",
                            header,
                            data));
                    return false;
                }

                String renewNonce = dataItems[0];
                String renewTimestamp = dataItems[1];
                String newSignature;
                try {
                    newSignature = rsaSignVerify.sign(renewNonce + " " + renewTimestamp, newAsymmetricKeyPair.privateKey);
                } catch (InvalidKeySpecException | InvalidKeyException | SignatureException e) {
                    e.printStackTrace();
                    logger.warning(e.getMessage());
                    return false;
                }

                clientTask.sendRaw(String.format("%s %s %s %s",
                        AppConfig.NetworkCommand.RENEW_KEY,
                        oldSignature,
                        newAsymmetricKeyPair.publicKey,
                        newSignature));
                return true;
            case AppConfig.NetworkCommand.RENEW_KEY_SUCCESS:
                if (newAsymmetricKeyPair == null) {
                    System.err.println(String.format("Unexpected data received for Header: %s ; Data: %s",
                            header,
                            data));
                    return false;
                }

                try {
                    dbService.updateClientKey(loginClient.clientId, newAsymmetricKeyPair);
                } catch (SQLException e) {
                    e.printStackTrace();
                    logger.warning(e.getMessage());
                    return false;
                }

                signupLoginService.reloadLoginClient();

                System.out.println("Client public key successfully renewed.");
                return true;
            case AppConfig.NetworkCommand.RENEW_KEY_FAILURE:
                newAsymmetricKeyPair = null;

                System.err.println("Failed to renew client public key!");
                return false;
        }
        return false;
    }
}
