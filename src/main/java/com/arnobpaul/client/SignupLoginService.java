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

public class SignupLoginService {
    private final ClientTask clientTask;

    private final DbService dbService;

    private final RsaGenEncDec rsaGenEncDec;
    private final RsaSignVerify rsaSignVerify;

    private boolean signupDone = false;
    private int signupClientId = 0;
    private String signupClientName = null;
    private AsymmetricKeyPair signupAsymmetricKeyPair = null;

    private boolean loginDone = false;
    private ClientEntity loginClient = null;

    private static final Logger logger = Logger.getLogger(SignupLoginService.class.getName());

    public SignupLoginService(@NotNull ClientTask clientTask,
                              @NotNull DbService dbService,
                              @NotNull RsaGenEncDec rsaGenEncDec,
                              @NotNull RsaSignVerify rsaSignVerify) {
        this.clientTask = clientTask;
        this.dbService = dbService;
        this.rsaGenEncDec = rsaGenEncDec;
        this.rsaSignVerify = rsaSignVerify;
    }

    synchronized public boolean requestSignup(String data) {
        if (data == null || data.isEmpty()) {
            System.err.println("Error! Please provide ClientName.");
            return false;
        }

        signupClientName = data;
        signupAsymmetricKeyPair = rsaGenEncDec.generateKey(AppConfig.RSA_KEY_SIZE);

        clientTask.sendRaw(String.format("%s %s %s",
                AppConfig.NetworkCommand.SIGNUP,
                signupClientName,
                signupAsymmetricKeyPair.publicKey));

        return true;
    }

    synchronized public boolean processSignup(String header, String data) {
        if (AppConfig.NetworkCommand.SIGNUP_SUCCESS.equals(header)) {
            try {
                signupClientId = Integer.parseInt(data);
                dbService.setLoginClient(new ClientEntity(signupClientId, signupClientName, signupAsymmetricKeyPair.publicKey, signupAsymmetricKeyPair.privateKey));
                System.out.println(String.format("Sign up success for Client_ID: %d", signupClientId));
                signupDone = true;
                return true;
            } catch (NumberFormatException | SQLException e) {
                e.printStackTrace();
                logger.warning(e.getMessage());
                return false;
            }
        }
        return false;
    }

    synchronized public boolean requestLogin() {
        try {
            loginClient = dbService.getLoginClient();
        } catch (SQLException e) {
            e.printStackTrace();
            logger.warning(e.getMessage());
            return false;
        }

        clientTask.sendRaw(String.format("%s %x",
                AppConfig.NetworkCommand.LOGIN,
                loginClient.clientId));

        return true;
    }

    synchronized public boolean processLogin(String header, String data) {
        switch (header) {
            case AppConfig.NetworkCommand.LOGIN_NONCE:
                if (data == null) return false;

                String[] dataItems = data.split(" ", 2);
                if (dataItems.length != 2) return false;

                String loginNonce = dataItems[0];
                String loginTimestamp = dataItems[1];
                String signature;
                try {
                    signature = rsaSignVerify.sign(loginNonce + " " + loginTimestamp, loginClient.clientPrivateKey);
                } catch (InvalidKeySpecException | InvalidKeyException | SignatureException e) {
                    e.printStackTrace();
                    logger.warning(e.getMessage());
                    return false;
                }

                clientTask.sendRaw(String.format("%s %s",
                        AppConfig.NetworkCommand.LOGIN_ACCEPT,
                        signature));

                return true;
            case AppConfig.NetworkCommand.LOGIN_SUCCESS:
                System.out.println(String.format("Login success for Client_ID: %d", loginClient.clientId));
                loginDone = true;
                return true;
            case AppConfig.NetworkCommand.LOGIN_FAILURE:
                System.out.println(String.format("Login failure for Client_ID: %d", loginClient.clientId));
                return false;
        }
        return false;
    }

    synchronized public boolean isLoginDone() {
        return loginDone;
    }

    synchronized public ClientEntity getLoginClient() {
        return loginClient;
    }

    synchronized public boolean reloadLoginClient() {
        if (loginDone) {
            try {
                loginClient = dbService.getLoginClient();
                return true;
            } catch (SQLException | NullPointerException e) {
                e.printStackTrace();
                logger.severe(e.getMessage());
                return false;
            }
        } else {
            return false;
        }
    }
}
