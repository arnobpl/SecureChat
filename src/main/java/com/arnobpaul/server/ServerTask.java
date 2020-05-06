package com.arnobpaul.server;

import com.arnobpaul.common.AppConfig;
import com.arnobpaul.common.crypto.RsaSignVerify;

import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;
import java.util.NoSuchElementException;
import java.util.Scanner;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.logging.Logger;

public class ServerTask implements Runnable {
    private static final int CONCURRENT_CLIENT = 100;

    private ServerSocket serverSocket = null;
    private volatile boolean isRunning = true;

    private final DbService dbService;

    private final RsaSignVerify rsaSignVerify;

    private final Router router;

    private static final Logger logger = Logger.getLogger(ServerTask.class.getName());

    public ServerTask() throws SQLException, NoSuchPaddingException, NoSuchAlgorithmException {
        this.dbService = new DbService();

        this.rsaSignVerify = new RsaSignVerify();

        this.router = new Router();
    }

    public void startServer() {
        System.out.println("Starting server...");

        try {
            serverSocket = new ServerSocket(AppConfig.SERVER_PORT);
            System.out.println("Server started.");
            new Thread(this, "ServerLoop").start();
        } catch (IOException e) {
            e.printStackTrace();
            logger.severe(e.getMessage());
        }
    }

    @Override
    public void run() {
        ThreadPoolExecutor threadPoolExecutor = (ThreadPoolExecutor) Executors.newFixedThreadPool(CONCURRENT_CLIENT);

        while (isRunning) {
            try {
                Socket socket = serverSocket.accept();

                Runnable perClientRunnable = new PerClientRunnable(socket, this);

                threadPoolExecutor.submit(perClientRunnable);
            } catch (IOException e) {
                e.printStackTrace();
                logger.severe(e.getMessage());
            }
        }

        threadPoolExecutor.shutdown();
        logger.info("ServerTask is terminated");
    }

    public void stopServer() {
        isRunning = false;
    }

    public static class PerClientRunnable implements Runnable {
        private final Socket socket;
        private final Scanner scanner;
        private final PrintWriter printWriter;

        private final ServerTask serverTask;

        private final ThreadPoolExecutor threadPoolExecutor;

        private final SignupLoginService signupLoginService;
        private final CommunicationService communicationService;
        private final RenewService renewService;

        public PerClientRunnable(Socket socket, ServerTask serverTask) throws IOException {
            this.socket = socket;
            this.scanner = new Scanner(socket.getInputStream());
            this.printWriter = new PrintWriter(socket.getOutputStream(), true);

            this.serverTask = serverTask;

            logger.info(String.format("Server connected to %s:%s",
                    socket.getInetAddress().getHostAddress(),
                    socket.getPort()));

            threadPoolExecutor = (ThreadPoolExecutor) Executors.newFixedThreadPool(1);

            this.signupLoginService = new SignupLoginService(
                    this,
                    serverTask.dbService,
                    serverTask.rsaSignVerify,
                    serverTask.router
            );

            this.communicationService = new CommunicationService(
                    this,
                    signupLoginService,
                    serverTask.router
            );

            this.renewService = new RenewService(
                    this,
                    serverTask.dbService,
                    signupLoginService,
                    serverTask.rsaSignVerify
            );
        }

        @Override
        public void run() {
            while (serverTask.isRunning) {
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
                    threadPoolExecutor.shutdown();
                    signupLoginService.stopService();
                    break;
                }
            }

            logger.info("PerClientRunnable is terminated");
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

        public SignupLoginService getSignupLoginService() {
            return signupLoginService;
        }
    }
}
