package com.arnobpaul.common;

import org.jetbrains.annotations.NotNull;

public class ClientEntity {
    public final int clientId;
    public final String clientName;
    public final String clientPublicKey;
    public final String clientPrivateKey;

    public ClientEntity(int clientId, @NotNull String clientName, @NotNull String clientPublicKey, String clientPrivateKey) {
        this.clientId = clientId;
        this.clientName = clientName;
        this.clientPublicKey = clientPublicKey;
        this.clientPrivateKey = clientPrivateKey;
    }

    public ClientEntity(int clientId, String clientName, String clientPublicKey) {
        this(clientId, clientName, clientPublicKey, null);
    }
}
