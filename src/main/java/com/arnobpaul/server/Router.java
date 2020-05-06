package com.arnobpaul.server;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * This class helps to access/operate any client (i.e., passing data from a client to another client)
 * from a client instance inside the server.
 */
public class Router {
    private final Map<Integer, ServerTask.PerClientRunnable> clientIdToClientRunnableMap = new ConcurrentHashMap<>();

    private static final Logger logger = Logger.getLogger(Router.class.getName());

    public void registerClientRunnable(int clientId, ServerTask.PerClientRunnable perClientRunnable) {
        logger.info(String.format("PerClientRunnable registered for Client_ID: %d", clientId));

        clientIdToClientRunnableMap.put(clientId, perClientRunnable);
    }

    public ServerTask.PerClientRunnable getClientRunnable(int clientId) {
        logger.info(String.format("PerClientRunnable accessed for Client_ID: %d", clientId));

        return clientIdToClientRunnableMap.get(clientId);
    }

    public ServerTask.PerClientRunnable deregisterClientRunnable(int clientId) {
        logger.info(String.format("PerClientRunnable deregistered for Client_ID: %d", clientId));

        return clientIdToClientRunnableMap.remove(clientId);
    }
}
