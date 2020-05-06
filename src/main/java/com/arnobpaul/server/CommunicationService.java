package com.arnobpaul.server;

import com.arnobpaul.common.AppConfig;
import com.arnobpaul.common.ClientEntity;
import org.jetbrains.annotations.NotNull;

import java.util.logging.Logger;

public class CommunicationService {
    private final ServerTask.PerClientRunnable perClientRunnable;

    private final SignupLoginService signupLoginService;

    private final Router router;

    private ClientEntity loginClient = null;

    private ServerTask.PerClientRunnable otherClientRunnable = null;
    private int otherClientId = 0;
    private ClientEntity otherClient = null;

    private static final Logger logger = Logger.getLogger(CommunicationService.class.getName());

    public CommunicationService(@NotNull ServerTask.PerClientRunnable perClientRunnable,
                                @NotNull SignupLoginService signupLoginService,
                                @NotNull Router router) {
        this.perClientRunnable = perClientRunnable;
        this.signupLoginService = signupLoginService;
        this.router = router;
    }

    synchronized public boolean processSend(String header, String data) {
        if (data == null) {
            perClientRunnable.sendRaw(AppConfig.NetworkCommand.SEND_FAILURE);

            System.err.println(String.format("Send failure for null data; Data: %s null",
                    header));
            return false;
        }
        String[] dataItems = data.split(" ", 2);
        if (header.equals(AppConfig.NetworkCommand.SEND_START)) {
            if (!checkBothClientsAndPerformAction(header, dataItems[0])) return false;

            perClientRunnable.sendRaw(String.format("%s %d %s",
                    AppConfig.NetworkCommand.SEND_INVITE,
                    otherClientId,
                    otherClient.clientPublicKey));

            otherClientRunnable.sendRaw(String.format("%s %d %s",
                    AppConfig.NetworkCommand.SEND_INVITE,
                    loginClient.clientId,
                    loginClient.clientPublicKey));

            System.out.println(String.format("Client_Public_Key info exchanged for the clients: %d and %d",
                    loginClient.clientId,
                    otherClientId));
            return true;
        } else if (header.equals(AppConfig.NetworkCommand.SEND_DATA)) {
            if (!checkBothClientsAndPerformAction(header, dataItems[0])) return false;

            if (dataItems.length != 2) {
                perClientRunnable.sendRaw(String.format("%s %d",
                        AppConfig.NetworkCommand.SEND_FAILURE,
                        otherClientId));
                System.err.println(String.format("Send failure for null data; Data: %s %s",
                        header, data));
                return false;
            }

            otherClientRunnable.sendRaw(String.format("%s %d %s",
                    AppConfig.NetworkCommand.SEND_DATA,
                    loginClient.clientId,
                    dataItems[1]));

            System.out.println(String.format("Data passing: From Client_ID %d To Client_ID %d; Data: %s",
                    loginClient.clientId,
                    otherClientId,
                    dataItems[1]));
            return true;
        }
        return false;
    }

    private boolean checkBothClientsAndPerformAction(String header, String data) {
        // Check for initiator client logged in
        loginClient = signupLoginService.getLoginClient();
        if (loginClient == null) {
            perClientRunnable.sendRaw(String.format("%s %s",
                    AppConfig.NetworkCommand.SEND_FAILURE,
                    data));

            System.err.println(String.format("Send failure for not logged in; Data: %s %s",
                    header, data));
            return false;
        }

        // Initiator client logged in; Check for the other client
        try {
            otherClientId = Integer.parseInt(data);
        } catch (NumberFormatException e) {
            e.printStackTrace();
            logger.warning(e.getMessage());

            perClientRunnable.sendRaw(String.format("%s %s",
                    AppConfig.NetworkCommand.SEND_FAILURE,
                    data));
            return false;
        }
        otherClientRunnable = router.getClientRunnable(otherClientId);
        if (otherClientRunnable == null) {
            perClientRunnable.sendRaw(String.format("%s %s",
                    AppConfig.NetworkCommand.SEND_FAILURE,
                    data));
            System.err.println(String.format("Send failure for other client not connected; Data: %s %s",
                    header, data));
            return false;
        }
        if ((otherClient = otherClientRunnable.getSignupLoginService().getLoginClient()) == null) {
            perClientRunnable.sendRaw(String.format("%s %s",
                    AppConfig.NetworkCommand.SEND_FAILURE,
                    data));
            System.err.println(String.format("Send failure for other client not logged in; Data: %s %s",
                    header, data));
            return false;
        }
        return true;
    }
}
