package com.arnobpaul.client;

import com.arnobpaul.common.AppConfig;
import com.arnobpaul.common.ClientEntity;
import com.arnobpaul.common.RandomGeneratorHelper;
import com.arnobpaul.common.crypto.*;
import org.jetbrains.annotations.NotNull;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Logger;

public class CommunicationService {
    private final ClientTask clientTask;

    private final SignupLoginService signupLoginService;
    private final TrustAndBlockListService trustAndBlockListService;

    private final RsaSignVerify rsaSignVerify;
    private final DiffieHellmanKeyExchange diffieHellmanKeyExchange;
    private final HmacGenerateVerify hmacGenerateVerify;
    private final AesGenEncDec aesGenEncDec;

    private ClientEntity loginClient = null;

    private int otherClientId = 0;
    private String otherClientPublicKey = null;

    private boolean isMessageKeyUpdated = false;
    private String sharedSecretMessageKey = null;
    private String sharedSecretEncryptionKey = null;
    private String sharedSecretHmacKey = null;
    private AsymmetricKeyPair messageKey = null;
    private int messageSequenceNumber = 0;
    private String otherClientMessagePublicKey = null;
    private int otherClientMessageSequenceNumber = 0;

    private final BlockingQueue<String> messageQueue = new LinkedBlockingQueue<>();

    private static final Logger logger = Logger.getLogger(TrustAndBlockListService.class.getName());

    public CommunicationService(@NotNull ClientTask clientTask,
                                @NotNull SignupLoginService signupLoginService,
                                @NotNull TrustAndBlockListService trustAndBlockListService,
                                @NotNull RsaSignVerify rsaSignVerify,
                                @NotNull DiffieHellmanKeyExchange diffieHellmanKeyExchange,
                                @NotNull HmacGenerateVerify hmacGenerateVerify,
                                @NotNull AesGenEncDec aesGenEncDec) {
        this.clientTask = clientTask;
        this.signupLoginService = signupLoginService;
        this.trustAndBlockListService = trustAndBlockListService;
        this.rsaSignVerify = rsaSignVerify;
        this.diffieHellmanKeyExchange = diffieHellmanKeyExchange;
        this.hmacGenerateVerify = hmacGenerateVerify;
        this.aesGenEncDec = aesGenEncDec;
    }

    synchronized public boolean requestSend(String data) {
        loginClient = signupLoginService.getLoginClient();
        if (loginClient == null) {
            System.err.println("Client must be logged in to receive a message to another client.");
            return false;
        }

        int foundClientId;
        try {
            foundClientId = Integer.parseInt(data);
        } catch (NumberFormatException e) {
            e.printStackTrace();
            logger.warning(e.getMessage());
            return false;
        }

        if (foundClientId == loginClient.clientId) {
            System.err.println(String.format("ERROR! Can't send message to myself. Your Client_ID: %s",
                    loginClient.clientId));
            return false;
        }

        if (trustAndBlockListService.isClientBlocked(foundClientId)) {
            System.err.println(String.format("ERROR! Client blocked. Message cannot be sent to Client_ID: %d",
                    foundClientId));
            return false;
        }
        otherClientId = foundClientId;

        clientTask.sendRaw(String.format("%s %d",
                AppConfig.NetworkCommand.SEND_START,
                otherClientId));

        return true;
    }

    synchronized public boolean processSend(String header, String data) {
        loginClient = signupLoginService.getLoginClient();
        if (loginClient == null) {
            System.err.println("Client must be logged in to receive a message to another client.");
            return false;
        }

        if (data == null) {
            System.err.println(String.format("Null data received for Header: %s",
                    header));
            return false;
        }
        String[] dataItems = data.split(" ", 2);
        int foundClientId;
        try {
            foundClientId = Integer.parseInt(dataItems[0]);
        } catch (NumberFormatException e) {
            e.printStackTrace();
            logger.warning(e.getMessage());
            return false;
        }
        if (trustAndBlockListService.isClientBlocked(foundClientId)) {
            clientTask.sendRaw(String.format("%s %d %s",
                    AppConfig.NetworkCommand.SEND_DATA,
                    foundClientId,
                    AppConfig.NetworkCommand.DATA_MESSAGE_ERROR));

            logger.warning(String.format("Message received from a blocked client! Client_ID: %d",
                    foundClientId));
            return false;
        }
        switch (header) {
            case AppConfig.NetworkCommand.SEND_INVITE:
                if (dataItems.length != 2) {
                    System.err.println(String.format("Malformed data received for Header: %s ; Data: %s",
                            header, data));
                    return false;
                }
                otherClientId = foundClientId;
                otherClientPublicKey = dataItems[1];

                resetMessageObjects();
                return checkTrustListAndShowWarningIfNeeded();
            case AppConfig.NetworkCommand.SEND_DATA:
                if (dataItems.length != 2) {
                    System.err.println(String.format("Malformed data received for Header: %s ; Data: %s",
                            header, data));
                    return false;
                }
                if (foundClientId != otherClientId) {
                    clientTask.sendRaw(String.format("%s %d %s",
                            AppConfig.NetworkCommand.SEND_DATA,
                            foundClientId,
                            AppConfig.NetworkCommand.DATA_MESSAGE_ERROR));
                    System.err.println(String.format("Unexpected data received from Client_ID: %d\n" +
                                    "Data: %s\n" +
                                    "Expected Client_ID: %d",
                            foundClientId,
                            dataItems[1],
                            otherClientId));
                    return false;
                }
                if (!checkTrustListAndShowWarningIfNeeded()) {
                    clientTask.sendRaw(String.format("%s %d %s",
                            AppConfig.NetworkCommand.SEND_DATA,
                            otherClientId,
                            AppConfig.NetworkCommand.DATA_MESSAGE_ERROR));
                    return false;
                }

                String[] messageItems = dataItems[1].split(" ", 2);
                if (messageItems.length != 2) {
                    if (messageItems[0].equals(AppConfig.NetworkCommand.DATA_MESSAGE_ERROR)) {
                        System.err.println(String.format("The other client has something wrong. Client_ID: %d",
                                otherClientId));
                        return false;
                    }
                    System.err.println(String.format("Malformed data received for Header: %s ; Data: null ; Client_ID: %d",
                            messageItems[0],
                            otherClientId));
                    return false;
                }

                return processSendMessage(messageItems[0], messageItems[1]);
            case AppConfig.NetworkCommand.SEND_FAILURE:
                System.err.println(String.format("Failed to send data to Client_ID: %d",
                        foundClientId));
                return false;
        }
        return false;
    }

    synchronized public boolean requestSendTrust(String data) {
        int foundClientId;
        try {
            foundClientId = Integer.parseInt(data);
        } catch (NumberFormatException e) {
            e.printStackTrace();
            logger.warning(e.getMessage());
            return false;
        }

        if (foundClientId != otherClientId) {
            System.err.println(String.format("Unexpected input received for Client_ID: %d\n" +
                            "Expected Client_ID: %d",
                    foundClientId,
                    otherClientId));
            return false;
        }

        return trustAndBlockListService.trustClient(String.format("%d %s",
                otherClientId,
                otherClientPublicKey));
    }

    synchronized public boolean requestSendMessage(String data) {
        if (data == null || data.isEmpty()) {
            System.err.println("Sending message cannot be null or empty.");
            return false;
        }

        loginClient = signupLoginService.getLoginClient();
        if (loginClient == null) {
            System.err.println("Client must be logged in to send a message to another client.");
            return false;
        }

        if (otherClientId == 0) {
            System.err.println("Error! Please provide Client_ID before sending a message.");
            return false;
        }

        if (trustAndBlockListService.isClientBlocked(otherClientId)) {
            System.err.println(String.format("ERROR! Client blocked. Message cannot be sent to Client_ID: %d",
                    otherClientId));
            return false;
        }

        if (!checkTrustListAndShowWarningIfNeeded()) {
            return false;
        }

        try {
            messageQueue.put(data);
        } catch (InterruptedException e) {
            e.printStackTrace();
            logger.warning(e.getMessage());
            return false;
        }

        processMessageQueue();

        return messageQueue.isEmpty();
    }

    private boolean processSendMessage(String header, String data) {
        switch (header) {
            case AppConfig.NetworkCommand.DATA_DH_START:
            case AppConfig.NetworkCommand.DATA_DH_START_ACCEPT: {
                if (sharedSecretMessageKey != null) {
                    System.err.println(String.format("Unexpected header received! HMAC tag needed, but received digital signature. Header: %s",
                            header));
                    return false;
                }
                String[] dataItems = data.split(" ", 3);
                if (dataItems.length != 3) {
                    System.err.println(String.format("Malformed message data received for Header: %s ; Data: %s ; Client_ID: %d",
                            header,
                            data,
                            otherClientId));
                }
                String signature = dataItems[0];
                int foundOtherClientMessageSequenceNumber;
                try {
                    foundOtherClientMessageSequenceNumber = Integer.parseInt(dataItems[1]);
                } catch (NumberFormatException e) {
                    e.printStackTrace();
                    logger.severe(e.getMessage());
                    return false;
                }
                if (foundOtherClientMessageSequenceNumber != otherClientMessageSequenceNumber) {
                    System.err.println(String.format("The other client's message sequence number mismatched!\n" +
                                    "Found: %d\n" +
                                    "Expected: %d",
                            foundOtherClientMessageSequenceNumber,
                            otherClientMessageSequenceNumber));
                    return false;
                }
                String foundOtherClientMessagePublicKey = dataItems[2];
                String messageToBeVerified = String.format("%d %s",
                        foundOtherClientMessageSequenceNumber,
                        foundOtherClientMessagePublicKey);
                boolean isVerified;
                try {
                    isVerified = rsaSignVerify.verify(messageToBeVerified, signature, otherClientPublicKey);
                } catch (InvalidKeySpecException | InvalidKeyException | SignatureException e) {
                    e.printStackTrace();
                    logger.severe(e.getMessage());
                    return false;
                }
                if (!isVerified) {
                    System.err.println("The other client's message signature mismatched!");
                    return false;
                }
                otherClientMessagePublicKey = foundOtherClientMessagePublicKey;

                otherClientMessageSequenceNumber++;
                if (header.equals(AppConfig.NetworkCommand.DATA_DH_START)) {
                    isMessageKeyUpdated = false;
                    updateMessageKey();
                }
                processMessageQueue();
                return true;
            }
            case AppConfig.NetworkCommand.DATA_DH_CHANGE:
            case AppConfig.NetworkCommand.DATA_DH_CHANGE_ACCEPT: {
                String[] dataItems = data.split(" ", 3);
                if (dataItems.length != 3) {
                    System.err.println(String.format("Malformed message data received for Header: %s ; Data: %s ; Client_ID: %d",
                            header,
                            data,
                            otherClientId));
                }
                String hmacTag = dataItems[0];
                int foundOtherClientMessageSequenceNumber;
                try {
                    foundOtherClientMessageSequenceNumber = Integer.parseInt(dataItems[1]);
                } catch (NumberFormatException e) {
                    e.printStackTrace();
                    logger.severe(e.getMessage());
                    return false;
                }
                if (foundOtherClientMessageSequenceNumber != otherClientMessageSequenceNumber) {
                    System.err.println(String.format("The other client's message sequence number mismatched!\n" +
                                    "Found: %d\n" +
                                    "Expected: %d",
                            foundOtherClientMessageSequenceNumber,
                            otherClientMessageSequenceNumber));
                    return false;
                }
                String foundOtherClientMessagePublicKey = dataItems[2];
                String messageToBeVerified = String.format("%d %s",
                        foundOtherClientMessageSequenceNumber,
                        foundOtherClientMessagePublicKey);
                boolean isVerified;
                try {
                    isVerified = hmacGenerateVerify.verifyTag(messageToBeVerified, hmacTag, sharedSecretHmacKey);
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                    logger.severe(e.getMessage());
                    return false;
                }
                if (!isVerified) {
                    System.err.println("The other client's message HMAC tag mismatched!");
                    return false;
                }
                otherClientMessagePublicKey = foundOtherClientMessagePublicKey;

                otherClientMessageSequenceNumber++;
                if (header.equals(AppConfig.NetworkCommand.DATA_DH_CHANGE)) {
                    isMessageKeyUpdated = false;
                    updateMessageKey();
                }
                processMessageQueue();
                return true;
            }
            case AppConfig.NetworkCommand.DATA_MESSAGE: {
                String encryptedMessage = data;
                String decryptedMessage;
                try {
                    decryptedMessage = aesGenEncDec.decrypt(encryptedMessage, sharedSecretEncryptionKey);
                } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
                    e.printStackTrace();
                    logger.severe(e.getMessage());
                    return false;
                }
                String[] dataItems = decryptedMessage.split(" ", 3);
                if (dataItems.length != 3) {
                    System.err.println(String.format("Malformed message data received for Header: %s ; Data: %s ; Client_ID: %d",
                            header,
                            data,
                            otherClientId));
                }
                String hmacTag = dataItems[0];
                int foundOtherClientMessageSequenceNumber;
                try {
                    foundOtherClientMessageSequenceNumber = Integer.parseInt(dataItems[1]);
                } catch (NumberFormatException e) {
                    e.printStackTrace();
                    logger.severe(e.getMessage());
                    return false;
                }
                if (foundOtherClientMessageSequenceNumber != otherClientMessageSequenceNumber) {
                    System.err.println(String.format("The other client's message sequence number mismatched!\n" +
                                    "Found: %d\n" +
                                    "Expected: %d",
                            foundOtherClientMessageSequenceNumber,
                            otherClientMessageSequenceNumber));
                    return false;
                }
                String foundMessage = dataItems[2];
                String messageToBeVerified = String.format("%d %s",
                        foundOtherClientMessageSequenceNumber,
                        foundMessage);
                boolean isVerified;
                try {
                    isVerified = hmacGenerateVerify.verifyTag(messageToBeVerified, hmacTag, sharedSecretHmacKey);
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                    logger.severe(e.getMessage());
                    return false;
                }
                if (!isVerified) {
                    System.err.println("The other client's message HMAC tag mismatched!");
                    return false;
                }
                System.out.println(String.format("[Client_ID %d] %s",
                        otherClientId,
                        foundMessage));
                otherClientMessageSequenceNumber++;
                return true;
            }
        }
        return false;
    }

    private boolean checkTrustListAndShowWarningIfNeeded() {
        boolean isTrusted = trustAndBlockListService.isClientPublicKeyTrusted(
                otherClientId,
                otherClientPublicKey);

        if (!isTrusted) {
            System.out.println(String.format(
                    "WARNING: The public key of the client is not added into TrustList.\n" +
                            "Do you want to add/update the public key for the client? (Enter \"%s %d\")\n" +
                            "Client_ID: %d\n" +
                            "Client_Public_Key: %s",
                    AppConfig.UserCommand.SEND_TRUST,
                    otherClientId,
                    otherClientId,
                    otherClientPublicKey));
            return false;
        }
        return true;
    }

    private void processMessageQueue() {
        while (!messageQueue.isEmpty()) {
            try {
                if (!isMessageKeyUpdated) {
                    if (!updateMessageKey()) {
                        break;
                    }
                } else {
                    if (!sendMessage(messageQueue.take())) {
                        break;
                    }
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
                logger.warning(e.getMessage());
            }
        }
    }

    /**
     * @param message message to be sent
     * @return true if this client is not waiting for any response and no error, otherwise false
     */
    private boolean sendMessage(String message) {
        String messageToBeTagged = String.format("%d %s",
                messageSequenceNumber,
                message);
        String hmacTag;
        try {
            hmacTag = hmacGenerateVerify.generateTag(messageToBeTagged, sharedSecretHmacKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            logger.severe(e.getMessage());
            return false;
        }
        String messageToBeEncrypted = String.format("%s %s",
                hmacTag,
                messageToBeTagged);
        String encryptedMessage;
        try {
            encryptedMessage = aesGenEncDec.encrypt(messageToBeEncrypted, sharedSecretEncryptionKey);
        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            logger.severe(e.getMessage());
            return false;
        }
        clientTask.sendRaw(String.format("%s %d %s %s",
                AppConfig.NetworkCommand.SEND_DATA,
                otherClientId,
                AppConfig.NetworkCommand.DATA_MESSAGE,
                encryptedMessage));

        updateOwnMessageSequenceNumber();
        return true;
    }

    /**
     * @return true if this client is not waiting for any response and no error, otherwise false
     */
    private boolean updateMessageKey() {
        boolean isWaitNeeded = (otherClientMessagePublicKey == null);

        String messageToBeSent = generateMessageForMessageKeyAndPerformAction();
        if (messageToBeSent == null) {
            return !isWaitNeeded;
        }
        clientTask.sendRaw(String.format("%s %d %s",
                AppConfig.NetworkCommand.SEND_DATA,
                otherClientId,
                messageToBeSent));

        if (!isMessageKeyUpdated) {
            updateOwnMessageSequenceNumber();
        }
        return !isWaitNeeded;
    }

    /**
     * @return the message part to be sent to the other client (without the server header)
     */
    private String generateMessageForMessageKeyAndPerformAction() {
        String messageHeader = getMessageHeader();
        if (otherClientMessagePublicKey == null) {
            messageKey = diffieHellmanKeyExchange.generateKey(AppConfig.RSA_KEY_SIZE);
            String messageToBeSignedOrTagged = String.format("%d %s",
                    messageSequenceNumber,
                    messageKey.publicKey);
            return String.format("%s %s %s",
                    messageHeader,
                    generateSignatureOrTag(messageToBeSignedOrTagged, sharedSecretMessageKey),
                    messageToBeSignedOrTagged);
        } else {
            if (messageKey != null) {
                updateSharedSecretMessageKey();
                return null;
            }
            messageKey = diffieHellmanKeyExchange.generateKey(AppConfig.RSA_KEY_SIZE);
            AsymmetricKeyPair oldMessageKey = messageKey;
            String oldSharedSecretMessageKey = sharedSecretMessageKey;
            String messageToBeSignedOrTagged = String.format("%d %s",
                    messageSequenceNumber,
                    oldMessageKey.publicKey);
            updateSharedSecretMessageKey();
            return String.format("%s %s %s",
                    messageHeader,
                    generateSignatureOrTag(messageToBeSignedOrTagged, oldSharedSecretMessageKey),
                    messageToBeSignedOrTagged);
        }
    }

    private String getMessageHeader() {
        if (sharedSecretMessageKey == null) {
            if (otherClientMessagePublicKey == null) {
                return AppConfig.NetworkCommand.DATA_DH_START;
            } else {
                return AppConfig.NetworkCommand.DATA_DH_START_ACCEPT;
            }
        } else {
            if (otherClientMessagePublicKey == null) {
                return AppConfig.NetworkCommand.DATA_DH_CHANGE;
            } else {
                return AppConfig.NetworkCommand.DATA_DH_CHANGE_ACCEPT;
            }
        }
    }

    private void updateSharedSecretMessageKey() {
        try {
            sharedSecretMessageKey = diffieHellmanKeyExchange.getSharedSecretKey(messageKey, otherClientMessagePublicKey);
        } catch (InvalidKeySpecException | InvalidKeyException e) {
            e.printStackTrace();
            logger.severe(e.getMessage());
            return;
        }
        RandomGeneratorHelper randomGeneratorHelper = new RandomGeneratorHelper(sharedSecretMessageKey);
        sharedSecretEncryptionKey = randomGeneratorHelper.nextBase64String(AppConfig.AES_KEY_SIZE / 8);
        sharedSecretHmacKey = randomGeneratorHelper.nextBase64String(AppConfig.RSA_KEY_SIZE / 8);

        logger.info(String.format("MessageKey.PrivateKey: %s\n" +
                        "MessageKey.PublicKey: %s\n" +
                        "OtherClientMessagePublicKey: %s\n" +
                        "SharedSecretMessageKey: %s\n" +
                        "SharedSecretEncryptionKey: %s\n" +
                        "SharedSecretHmacKey: %s",
                messageKey.privateKey,
                messageKey.publicKey,
                otherClientMessagePublicKey,
                sharedSecretMessageKey,
                sharedSecretEncryptionKey,
                sharedSecretHmacKey));

        isMessageKeyUpdated = true;
        messageKey = null;
        otherClientMessagePublicKey = null;
        messageSequenceNumber = 0;
        otherClientMessageSequenceNumber = 0;
    }

    private String generateSignatureOrTag(String messageToBeSignedOrTagged, String sharedSecretMessageKeyToBeUsed) {
        if (sharedSecretMessageKeyToBeUsed == null) {
            try {
                return rsaSignVerify.sign(messageToBeSignedOrTagged, loginClient.clientPrivateKey);
            } catch (InvalidKeySpecException | InvalidKeyException | SignatureException e) {
                e.printStackTrace();
                logger.severe(e.getMessage());
            }
        } else {
            try {
                String hmacKeyToBeUsed;
                if (sharedSecretMessageKeyToBeUsed.equals(sharedSecretMessageKey)) {
                    hmacKeyToBeUsed = sharedSecretHmacKey;
                } else {
                    RandomGeneratorHelper randomGeneratorHelper = new RandomGeneratorHelper(sharedSecretMessageKeyToBeUsed);
                    randomGeneratorHelper.nextBase64String(AppConfig.AES_KEY_SIZE / 8);
                    hmacKeyToBeUsed = randomGeneratorHelper.nextBase64String(AppConfig.RSA_KEY_SIZE / 8);
                }
                return hmacGenerateVerify.generateTag(messageToBeSignedOrTagged, hmacKeyToBeUsed);
            } catch (InvalidKeyException e) {
                e.printStackTrace();
                logger.severe(e.getMessage());
            }
        }
        return null;
    }

    private void updateOwnMessageSequenceNumber() {
        messageSequenceNumber++;
        // otherClientMessageSequenceNumber++; // this is updated after receiving the other client's message

        if (isMessageKeyUpdated) {
            if (messageSequenceNumber > AppConfig.MESSAGE_SEQUENCE_NUMBER_UPDATE_MIN) {
                isMessageKeyUpdated = AppConfig.SECURE_RANDOM.nextBoolean();
            }
        }
    }

    private void resetMessageObjects() {
        isMessageKeyUpdated = false;
        sharedSecretMessageKey = null;
        sharedSecretEncryptionKey = null;
        sharedSecretHmacKey = null;
        messageKey = null;
        otherClientMessagePublicKey = null;
        messageSequenceNumber = 0;
        otherClientMessageSequenceNumber = 0;

        messageQueue.clear();
    }
}
