package com.arnobpaul.client;

import org.jetbrains.annotations.NotNull;

import java.sql.SQLException;
import java.util.logging.Logger;

public class TrustAndBlockListService {
    private final DbService dbService;

    private static final Logger logger = Logger.getLogger(TrustAndBlockListService.class.getName());

    public TrustAndBlockListService(@NotNull DbService dbService) {
        this.dbService = dbService;
    }

    synchronized public boolean trustClient(String data) {
        unblockClient(data);

        if (data == null) {
            System.err.println("Error! Please provide ClientId and ClientPublickey.");
            return false;
        }

        String[] dataItems = data.split(" ", 2);
        if (dataItems.length != 2) {
            System.err.println("Error! Please provide ClientId and ClientPublickey.");
            return false;
        }

        try {
            int clientId = Integer.parseInt(dataItems[0]);
            String clientPublicKey = dataItems[1];
            if (clientPublicKey.isEmpty()) {
                System.err.println("Error! ClientPublickey is empty.");
                return false;
            }

            dbService.insertOrUpdateToTrustList(clientId, clientPublicKey);
            System.out.println(String.format("Client trusted for Client_ID: %d", clientId));
            return true;
        } catch (NumberFormatException | SQLException e) {
            e.printStackTrace();
            logger.warning(e.getMessage());
            return false;
        }
    }

    synchronized public boolean untrustClient(String data) {
        if (data == null || data.isEmpty()) {
            System.err.println("Error! Please provide ClientId.");
            return false;
        }

        try {
            int clientId = Integer.parseInt(data);

            boolean success = dbService.deleteFromTrustList(clientId);
            if (success) {
                System.out.println(String.format("Client untrusted for Client_ID: %d", clientId));
            }
            return success;
        } catch (NumberFormatException | SQLException e) {
            e.printStackTrace();
            logger.warning(e.getMessage());
            return false;
        }
    }

    public boolean isClientPublicKeyTrusted(int clientId, String clientPublicKey) {
        if (clientPublicKey == null || clientPublicKey.isEmpty()) {
            System.err.println("Error! Please provide clientId.");
            return false;
        }

        try {
            String foundClientPublicKey = dbService.getClientPublicKeyFromTrustList(clientId);
            return clientPublicKey.equals(foundClientPublicKey);
        } catch (SQLException e) {
            e.printStackTrace();
            logger.warning(e.getMessage());
            return false;
        }
    }

    synchronized public boolean blockClient(String data) {
        untrustClient(data);

        if (data == null || data.isEmpty()) {
            System.err.println("Error! Please provide clientId.");
            return false;
        }

        try {
            int clientId = Integer.parseInt(data);

            dbService.insertOrIgnoreToBlockList(clientId);
            System.out.println(String.format("Client blocked for Client_ID: %d", clientId));
            return true;
        } catch (NumberFormatException | SQLException e) {
            e.printStackTrace();
            logger.warning(e.getMessage());
            return false;
        }
    }

    synchronized public boolean unblockClient(String data) {
        if (data == null || data.isEmpty()) {
            System.err.println("Error! Please provide clientId.");
            return false;
        }

        try {
            int clientId = Integer.parseInt(data);

            boolean success = dbService.deleteFromBlockList(clientId);
            if (success) {
                System.out.println(String.format("Client unblocked for Client_ID: %d", clientId));
            }
            return success;
        } catch (NumberFormatException | SQLException e) {
            e.printStackTrace();
            logger.warning(e.getMessage());
            return false;
        }
    }

    public boolean isClientBlocked(int clientId) {
        try {
            return dbService.isClientIdInBlockList(clientId);
        } catch (SQLException e) {
            e.printStackTrace();
            logger.warning(e.getMessage());
            return false;
        }
    }
}
