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

public class SignupLoginService {
    private final ServerTask.PerClientRunnable perClientRunnable;

    private final DbService dbService;

    private final RsaSignVerify rsaSignVerify;

    private final Router router;

    private int clientId = 0;
    private String clientName = null;
    private String clientPublicKey = null;

    private boolean signupDone = false;
    private long signupTimestamp = 0;

    private boolean loginDone = false;
    private ClientEntity loginClient = null;
    private long loginNonce = 0;
    private long loginTimestamp = 0;

    private static final Logger logger = Logger.getLogger(SignupLoginService.class.getName());

    public SignupLoginService(@NotNull ServerTask.PerClientRunnable perClientRunnable,
                              @NotNull DbService dbService,
                              @NotNull RsaSignVerify rsaSignVerify,
                              @NotNull Router router) {
        this.perClientRunnable = perClientRunnable;
        this.dbService = dbService;
        this.rsaSignVerify = rsaSignVerify;
        this.router = router;
    }

    synchronized public boolean processSignup(String header, String data) {
        if (!signupDone && header.equals(AppConfig.NetworkCommand.SIGNUP)) {
            if (data == null) return false;

            String[] dataItems = data.split(" ", 2);
            if (dataItems.length == 2) {
                clientName = dataItems[0];
                clientPublicKey = dataItems[1];

                try {
                    clientId = dbService.insert(clientName, clientPublicKey);
                } catch (SQLException e) {
                    e.printStackTrace();
                    logger.severe(e.getMessage());
                    perClientRunnable.sendRaw(AppConfig.NetworkCommand.SIGNUP_FAILURE);
                    return false;
                }

                signupTimestamp = System.currentTimeMillis();
                perClientRunnable.sendRaw(String.format("%s %d",
                        AppConfig.NetworkCommand.SIGNUP_SUCCESS,
                        clientId));

                System.out.println(String.format("Sign up done for Client_ID: %d",
                        clientId));
                signupDone = true;
                return true;
            }
        }
        perClientRunnable.sendRaw(AppConfig.NetworkCommand.SIGNUP_FAILURE);
        return false;
    }

    synchronized public boolean processLogin(String header, String data) {
        if (header.equals(AppConfig.NetworkCommand.LOGIN)) {
            if (data == null) return false;

            try {
                clientId = Integer.parseInt(data);
            } catch (NumberFormatException e) {
                e.printStackTrace();
                logger.warning(e.getMessage());
                perClientRunnable.sendRaw(AppConfig.NetworkCommand.LOGIN_FAILURE);
                resetService();
                return false;
            }

            try {
                loginClient = dbService.getClient(clientId);
            } catch (SQLException | NullPointerException e) {
                e.printStackTrace();
                logger.severe(e.getMessage());
                perClientRunnable.sendRaw(AppConfig.NetworkCommand.LOGIN_FAILURE);
                resetService();
                return false;
            }

            loginNonce = AppConfig.SECURE_RANDOM.nextLong();
            loginTimestamp = System.currentTimeMillis();
            perClientRunnable.sendRaw(String.format("%s %d %d",
                    AppConfig.NetworkCommand.LOGIN_NONCE,
                    loginNonce,
                    loginTimestamp));

            router.registerClientRunnable(clientId, perClientRunnable);
            return true;
        } else if (header.equals(AppConfig.NetworkCommand.LOGIN_ACCEPT)) {
            if (data == null) return false;

            //noinspection UnnecessaryLocalVariable
            String signature = data;

            if (loginClient == null) {
                perClientRunnable.sendRaw(AppConfig.NetworkCommand.LOGIN_FAILURE);
                System.err.println(String.format("Login failure for Client_ID: %d",
                        clientId));
                resetService();
                return false;
            }

            boolean isVerified;
            try {
                isVerified = rsaSignVerify.verify(String.format("%d %d", loginNonce, loginTimestamp), signature, loginClient.clientPublicKey);
            } catch (InvalidKeySpecException | InvalidKeyException | SignatureException e) {
                e.printStackTrace();
                logger.severe(e.getMessage());
                perClientRunnable.sendRaw(AppConfig.NetworkCommand.LOGIN_FAILURE);
                resetService();
                return false;
            }

            if (isVerified) {
                perClientRunnable.sendRaw(AppConfig.NetworkCommand.LOGIN_SUCCESS);
                System.out.println(String.format("Login success for Client_ID: %d",
                        loginClient.clientId));
                loginDone = true;
                return true;
            } else {
                perClientRunnable.sendRaw(AppConfig.NetworkCommand.LOGIN_FAILURE);
                System.err.println(String.format("Login failure for Client_ID: %d",
                        loginClient.clientId));
                resetService();
                return false;
            }
        }
        perClientRunnable.sendRaw(AppConfig.NetworkCommand.LOGIN_FAILURE);
        return false;
    }

    /**
     * This method deletes the signup entry if not logged in.
     */
    synchronized public void stopService() {
        if (signupDone && !loginDone) {
            try {
                dbService.delete(clientId);
            } catch (SQLException e) {
                e.printStackTrace();
                logger.severe(e.getMessage());
            }
        }
        if (loginDone) {
            router.deregisterClientRunnable(clientId);
        }
    }

    synchronized public boolean isLoginDone() {
        return loginDone;
    }

    synchronized public ClientEntity getLoginClient() {
        if (loginDone) return loginClient;
        return null;
    }

    synchronized public boolean reloadLoginClient() {
        if (loginDone) {
            clientId = loginClient.clientId;
            try {
                loginClient = dbService.getClient(clientId);
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

    /**
     * This method checks for <code>SERVER_SIGNUP_TIMEOUT</code> and deletes the client if appropriate.
     */
    private void resetService() {
        if (signupDone && !loginDone) {
            if ((System.currentTimeMillis() - signupTimestamp) >= AppConfig.SERVER_SIGNUP_TIMEOUT) {
                try {
                    dbService.delete(clientId);
                } catch (SQLException e) {
                    e.printStackTrace();
                    logger.severe(e.getMessage());
                }
            }
        }
    }
}
