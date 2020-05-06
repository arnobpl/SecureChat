package com.arnobpaul.server;

import com.arnobpaul.common.AppConfig;
import com.arnobpaul.common.ClientEntity;
import com.arnobpaul.common.crypto.RsaSignVerify;
import org.jetbrains.annotations.NotNull;

import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.sql.SQLException;
import java.util.logging.Logger;

public class RenewService {
    private final ServerTask.PerClientRunnable perClientRunnable;

    private final DbService dbService;
    private final SignupLoginService signupLoginService;

    private final RsaSignVerify rsaSignVerify;

    private ClientEntity loginClient = null;
    private long renewNonce = 0;
    private long renewTimestamp = 0;

    private static final Logger logger = Logger.getLogger(RenewService.class.getName());

    public RenewService(@NotNull ServerTask.PerClientRunnable perClientRunnable,
                        @NotNull DbService dbService,
                        @NotNull SignupLoginService signupLoginService,
                        @NotNull RsaSignVerify rsaSignVerify) {
        this.perClientRunnable = perClientRunnable;
        this.dbService = dbService;
        this.signupLoginService = signupLoginService;
        this.rsaSignVerify = rsaSignVerify;
    }

    synchronized public boolean processRenew(String header, String data) {
        if (header.equals(AppConfig.NetworkCommand.RENEW_KEY_REQUEST)) {
            if ((loginClient = signupLoginService.getLoginClient()) != null) {
                renewNonce = AppConfig.SECURE_RANDOM.nextLong();
                renewTimestamp = System.currentTimeMillis();

                perClientRunnable.sendRaw(String.format("%s %d %d",
                        AppConfig.NetworkCommand.RENEW_KEY_OK,
                        renewNonce,
                        renewTimestamp));

                System.out.println(String.format("Renew request accepted for Client_ID: %d",
                        loginClient.clientId));
                return true;
            }
        } else if (header.equals(AppConfig.NetworkCommand.RENEW_KEY)) {
            if (loginClient == null) {
                perClientRunnable.sendRaw(AppConfig.NetworkCommand.RENEW_KEY_FAILURE);
                System.err.println(String.format("Renew failure, loginClient null; for Client_ID: %d",
                        loginClient.clientId));
                return false;
            }

            if (data == null) {
                perClientRunnable.sendRaw(AppConfig.NetworkCommand.RENEW_KEY_FAILURE);
                System.err.println(String.format("Renew failure, data null; for Client_ID: %d",
                        loginClient.clientId));
                return false;
            }

            String[] dataItems = data.split(" ", 3);
            if (dataItems.length != 3) {
                perClientRunnable.sendRaw(AppConfig.NetworkCommand.RENEW_KEY_FAILURE);
                System.err.println(String.format("Renew failure, parameter count incorrect; for Client_ID: %d",
                        loginClient.clientId));
                return false;
            }

            String oldSignature = dataItems[0];
            String newClientPublicKey = dataItems[1];
            String newSignature = dataItems[2];

            boolean isVerified;
            try {
                isVerified = rsaSignVerify.verify(newClientPublicKey, oldSignature, loginClient.clientPublicKey);
            } catch (SignatureException | InvalidKeyException | InvalidKeySpecException e) {
                e.printStackTrace();
                logger.severe(e.getMessage());
                perClientRunnable.sendRaw(AppConfig.NetworkCommand.RENEW_KEY_FAILURE);
                System.err.println(String.format("Renew failure, signature error; for Client_ID: %d",
                        loginClient.clientId));
                return false;
            }

            if (!isVerified) {
                perClientRunnable.sendRaw(AppConfig.NetworkCommand.RENEW_KEY_FAILURE);
                System.err.println(String.format("Renew failure, signature mismatch; for Client_ID: %d",
                        loginClient.clientId));
                return false;
            }

            try {
                isVerified = rsaSignVerify.verify(String.format("%d %d", renewNonce, renewTimestamp), newSignature, newClientPublicKey);
            } catch (SignatureException | InvalidKeyException | InvalidKeySpecException e) {
                e.printStackTrace();
                logger.severe(e.getMessage());
                perClientRunnable.sendRaw(AppConfig.NetworkCommand.RENEW_KEY_FAILURE);
                System.err.println(String.format("Renew failure, new signature error; for Client_ID: %d",
                        loginClient.clientId));
                return false;
            }

            if (!isVerified) {
                perClientRunnable.sendRaw(AppConfig.NetworkCommand.RENEW_KEY_FAILURE);
                System.err.println(String.format("Renew failure, new signature mismatch; for Client_ID: %d",
                        loginClient.clientId));
                return false;
            }

            try {
                dbService.updateClientPublicKey(loginClient.clientId, newClientPublicKey);
            } catch (SQLException e) {
                e.printStackTrace();
                logger.severe(e.getMessage());
                perClientRunnable.sendRaw(AppConfig.NetworkCommand.RENEW_KEY_FAILURE);
                return false;
            }
            signupLoginService.reloadLoginClient();

            perClientRunnable.sendRaw(AppConfig.NetworkCommand.RENEW_KEY_SUCCESS);

            System.out.println(String.format("Client public key successfully renewed for Client_ID: %d",
                    loginClient.clientId));
            return true;
        }
        return false;
    }
}
