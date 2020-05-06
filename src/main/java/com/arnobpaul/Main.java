package com.arnobpaul;

import com.arnobpaul.client.ClientTask;
import com.arnobpaul.common.AppConfig;
import com.arnobpaul.server.ServerTask;

import javax.crypto.NoSuchPaddingException;
import java.nio.file.FileSystemException;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;
import java.util.Random;
import java.util.logging.Logger;

public class Main {
    public static final String SERVER_ARG = "-s"; // "-s"
    public static final String CLIENT_ARG = "-c"; // "-c <Data_folder>"

    private static final Logger logger = Logger.getLogger(Main.class.getName());

    public static void main(String[] args) {
        System.out.println("Welcome to " + AppConfig.APP_NAME);

        if (args.length == 0) {
            System.out.println("Please use the following commands:");
            System.out.println(SERVER_ARG + " : Run as a server.");
            System.out.println(CLIENT_ARG + " : Run as a client.");
            return;
        }

        if (args[0].equals(SERVER_ARG)) {
            try {
                new ServerTask().startServer();
            } catch (SQLException | NoSuchPaddingException | NoSuchAlgorithmException e) {
                e.printStackTrace();
                logger.severe(e.getMessage());
            }
        } else if (args[0].equals(CLIENT_ARG)) {
            String dataFolder;
            if (args.length == 2) {
                dataFolder = args[1];
            } else {
                dataFolder = Integer.toHexString(new Random().nextInt());
            }

            try {
                new ClientTask(dataFolder).connectToServer();
            } catch (FileSystemException | SQLException | NoSuchPaddingException | NoSuchAlgorithmException e) {
                e.printStackTrace();
                logger.severe(e.getMessage());
            }
        }
    }
}
