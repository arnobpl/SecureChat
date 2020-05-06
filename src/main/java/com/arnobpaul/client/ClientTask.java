package com.arnobpaul.client;

import com.arnobpaul.common.AppConfig;
import com.arnobpaul.common.crypto.*;

import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.net.Socket;
import java.nio.file.FileSystemException;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;
import java.util.NoSuchElementException;
import java.util.Scanner;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.logging.Logger;

public class ClientTask implements Runnable {
    private static final String SERVER_IP = "127.0.0.1";

    private Socket socket = null;
    private Scanner scanner = null;
    private PrintWriter printWriter = null;

    private ThreadPoolExecutor threadPoolExecutor = null;

    private static volatile boolean isRunning = true;

    private final DbService dbService;
    private final String dataFolder;

    private final RsaGenEncDec rsaGenEncDec;
    private final RsaSignVerify rsaSignVerify;
    private final DiffieHellmanKeyExchange diffieHellmanKeyExchange;
    private final HmacGenerateVerify hmacGenerateVerify;
    private final AesGenEncDec aesGenEncDec;

    private final SignupLoginService signupLoginService;
    private final TrustAndBlockListService trustAndBlockListService;
    private final CommunicationService communicationService;
    private final RenewService renewService;

    private static final Logger logger = Logger.getLogger(ClientTask.class.getName());

    public ClientTask(String dataFolder) throws FileSystemException, SQLException, NoSuchPaddingException, NoSuchAlgorithmException {
        this.dataFolder = dataFolder;
        this.dbService = new DbService(dataFolder);

        this.rsaGenEncDec = new RsaGenEncDec();
        this.rsaSignVerify = new RsaSignVerify();
        this.diffieHellmanKeyExchange = new DiffieHellmanKeyExchange();
        this.hmacGenerateVerify = new HmacGenerateVerify();
        this.aesGenEncDec = new AesGenEncDec();

        this.signupLoginService = new SignupLoginService(
                this,
                this.dbService,
                this.rsaGenEncDec,
                this.rsaSignVerify
        );

        this.trustAndBlockListService = new TrustAndBlockListService(
                this.dbService
        );

        this.communicationService = new CommunicationService(
                this,
                this.signupLoginService,
                this.trustAndBlockListService,
                this.rsaSignVerify,
                this.diffieHellmanKeyExchange,
                this.hmacGenerateVerify,
                this.aesGenEncDec
        );

        this.renewService = new RenewService(
                this,
                this.dbService,
                this.signupLoginService,
                this.rsaGenEncDec,
                this.rsaSignVerify
        );
    }

    public void connectToServer() {
        System.out.println("Connecting to server...");

        try {
            socket = new Socket(SERVER_IP, AppConfig.SERVER_PORT);
            scanner = new Scanner(socket.getInputStream());
            printWriter = new PrintWriter(socket.getOutputStream(), true);
        } catch (IOException e) {
            e.printStackTrace();
            logger.severe(e.getMessage());
            return;
        }

        System.out.println("Connected to server.");

        // network output thread
        threadPoolExecutor = (ThreadPoolExecutor) Executors.newFixedThreadPool(1);

        // network input thread
        new Thread(this, "ClientNetworkInputLoop").start();

        // user input thread
        new Thread(new InputTask(this), "ClientUserInputLoop").start();
    }

    @Override
    public void run() {
        while (isRunning) {
            try {
                String dataReceived = scanner.nextLine().trim();

                logger.info(String.format("Received \"%s\" from %s:%s",
                        dataReceived,
                        socket.getInetAddress().getHostAddress(),
                        socket.getPort()));

                String[] dataReceivedItems = dataReceived.split(" ", 2);
                String header = dataReceivedItems[0];
                String data = null;
                if (dataReceivedItems.length == 2) {
                    data = dataReceivedItems[1];
                }
                if (header.startsWith(AppConfig.NetworkCommand.SIGNUP)) {
                    signupLoginService.processSignup(header, data);
                } else if (header.startsWith(AppConfig.NetworkCommand.LOGIN)) {
                    signupLoginService.processLogin(header, data);
                } else if (header.startsWith(AppConfig.NetworkCommand.SEND_DATA)) {
                    communicationService.processSend(header, data);
                } else if (header.startsWith(AppConfig.NetworkCommand.RENEW_KEY)) {
                    renewService.processRenew(header, data);
                }
            } catch (NoSuchElementException e) {
                e.printStackTrace();
                logger.severe(e.getMessage());
                threadPoolExecutor.shutdown();
                return;
            }
        }

        threadPoolExecutor.shutdown();
        logger.info("ClientTask is terminated");
    }

    public boolean sendRaw(String dataToSend) {
        if (!threadPoolExecutor.isShutdown()) {
            threadPoolExecutor.submit(() -> printWriter.println(dataToSend));

            logger.info(String.format("Sent \"%s\" to %s:%s",
                    dataToSend,
                    socket.getInetAddress().getHostAddress(),
                    socket.getPort()));

            return true;
        }
        return false;
    }

    private static class InputTask implements Runnable {
        private final ClientTask clientTask;

        public InputTask(ClientTask clientTask) {
            this.clientTask = clientTask;
        }

        @Override
        public void run() {
            Scanner scanner = new Scanner(System.in);

            while (isRunning) {
                String dataInput = scanner.nextLine().trim();

                logger.info(String.format("Input received:  \"%s\"", dataInput));

                String[] dataInputItems = dataInput.split(" ", 2);
                String header = dataInputItems[0];

                if (header.startsWith("-")) {
                    header = header.toLowerCase();
                    String data = null;
                    if (dataInputItems.length == 2) {
                        data = dataInputItems[1];
                    }
                    switch (header) {
                        case AppConfig.UserCommand.HELP:
                            try {
                                for (Field field : AppConfig.UserCommand.class.getDeclaredFields()) {
                                    System.out.println(field.getName() + " : " + field.get(null));
                                }
                            } catch (IllegalAccessException e) {
                                e.printStackTrace();
                            }
                            break;
                        case AppConfig.UserCommand.EXIT:
                            isRunning = false;
                            try {
                                clientTask.socket.close();
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                            break;
                        case AppConfig.UserCommand.SIGN_UP:
                            clientTask.signupLoginService.requestSignup(data);
                            break;
                        case AppConfig.UserCommand.LOGIN:
                            clientTask.signupLoginService.requestLogin();
                            break;
                        case AppConfig.UserCommand.SEND:
                            clientTask.communicationService.requestSend(data);
                            break;
                        case AppConfig.UserCommand.SEND_TRUST:
                            clientTask.communicationService.requestSendTrust(data);
                            break;
                        case AppConfig.UserCommand.TRUST:
                            clientTask.trustAndBlockListService.trustClient(data);
                            break;
                        case AppConfig.UserCommand.UNTRUST:
                            clientTask.trustAndBlockListService.untrustClient(data);
                            break;
                        case AppConfig.UserCommand.BLOCK:
                            clientTask.trustAndBlockListService.blockClient(data);
                            break;
                        case AppConfig.UserCommand.UNBLOCK:
                            clientTask.trustAndBlockListService.unblockClient(data);
                            break;
                        case AppConfig.UserCommand.RENEW_KEY:
                            clientTask.renewService.requestRenew(data);
                            break;
                    }
                } else {
                    clientTask.communicationService.requestSendMessage(dataInput);
                }
            }

            logger.info("InputTask is terminated");
        }
    }
}
