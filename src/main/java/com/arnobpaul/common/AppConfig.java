package com.arnobpaul.common;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class AppConfig {
    public static final int SERVER_PORT = 35360;

    public static final String APP_NAME = "SecureChat";

    public static final long SERVER_SIGNUP_TIMEOUT = 300000;

    public static final int RSA_KEY_SIZE = 2048;
    public static final int AES_KEY_SIZE = 256;

    public static final int MESSAGE_SEQUENCE_NUMBER_UPDATE_MIN = 5;

    public static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;

    public static class UserCommand {
        // Help
        public static final String HELP = "-help"; // "-help"

        // Help
        public static final String EXIT = "-exit"; // "-exit"

        // Sign up
        public static final String SIGN_UP = "-signup"; // "-signup <Client_Name>"

        // Login
        public static final String LOGIN = "-login"; // "-login"

        // Communication
        public static final String SEND = "-send"; // "-send <Client_ID>"
        public static final String SEND_TRUST = "-send_trust"; // "-send_trust <Client_ID>"
        // Sending a message does not have any especial command, just the message. The message will be sent to the <Client_ID> set by "-send" command.

        // Renew key
        public static final String RENEW_KEY = "-renew"; // "-renew <Client_ID>"

        // Trust list
        public static final String TRUST = "-trust"; // "-trust <Client_ID> <Public_Key>"
        public static final String UNTRUST = "-untrust"; // "-untrust <Client_ID>"

        // Block list
        public static final String BLOCK = "-block"; // "-block <Client_ID>"
        public static final String UNBLOCK = "-unblock"; // "-unblock <Client_ID>"
    }

    public static class NetworkCommand {
        // Sign up
        public static final String SIGNUP = "SIGNUP"; // "SIGNUP <Client_Name> <Client_Public_Key>"
        public static final String SIGNUP_SUCCESS = "SIGNUP_SUCCESS"; // "SIGNUP_SUCCESS <Client_ID>"
        public static final String SIGNUP_FAILURE = "SIGNUP_FAILURE"; // "SIGNUP_FAILURE"

        // Login
        public static final String LOGIN = "LOGIN"; // "LOGIN <Client_ID>"
        public static final String LOGIN_NONCE = "LOGIN_NONCE"; // "LOGIN_NONCE <Nonce> <Timestamp>"
        public static final String LOGIN_ACCEPT = "LOGIN_ACCEPT"; // "LOGIN_ACCEPT <Signature>"
        public static final String LOGIN_SUCCESS = "LOGIN_SUCCESS"; // "LOGIN_SUCCESS"
        public static final String LOGIN_FAILURE = "LOGIN_FAILURE"; // "LOGIN_FAILURE"

        // Communication (Server-Client)
        public static final String SEND_START = "SEND_START"; // "SEND_START <Client_ID>"
        public static final String SEND_INVITE = "SEND_INVITE"; // "SEND_INVITE <Client_ID> <Client_Public_Key>"
        public static final String SEND_DATA = "SEND"; // "SEND <Client_ID> <Data>"
        public static final String SEND_FAILURE = "SEND_FAILURE"; // "SEND_FAILURE <Client_ID>"

        // Communication data part (Client-Client via Server)
        public static final String DATA_DH_START = "DATA_DH_START"; // "DATA_DH_START <Signature> <Seq_Num> <Client_DH_Public_Key>"
        public static final String DATA_DH_START_ACCEPT = "DATA_DH_START_ACCEPT"; // "DATA_DH_START_ACCEPT <Signature> <Seq_Num> <Client_DH_Public_Key>"
        public static final String DATA_DH_CHANGE = "DATA_DH_CHANGE"; // "DATA_DH_CHANGE <HMAC> <Seq_Num> <Client_DH_Public_Key>"
        public static final String DATA_DH_CHANGE_ACCEPT = "DATA_DH_CHANGE_ACCEPT"; // "DATA_DH_CHANGE_ACCEPT <HMAC> <Seq_Num> <Client_DH_Public_Key>"
        public static final String DATA_MESSAGE = "DATA"; // "DATA Enc(<HMAC> <Seq_Num> <Message>)"
        public static final String DATA_MESSAGE_ERROR = "DATA_MESSAGE_ERROR"; // "DATA_MESSAGE_ERROR"

        // Renew key
        public static final String RENEW_KEY_REQUEST = "RENEW_KEY_REQUEST"; // "RENEW_KEY_REQUEST"
        public static final String RENEW_KEY_OK = "RENEW_KEY_REQUEST_OK"; // "RENEW_KEY_REQUEST_OK <Nonce> <Timestamp>"
        public static final String RENEW_KEY = "RENEW_KEY"; // "RENEW_KEY <Signature_Old> <New_Public_Key> <Signature_New>"
        public static final String RENEW_KEY_SUCCESS = "RENEW_KEY_SUCCESS"; // "RENEW_KEY_SUCCESS"
        public static final String RENEW_KEY_FAILURE = "RENEW_KEY_FAILURE"; // "RENEW_KEY_FAILURE"
    }

    public static final SecureRandom SECURE_RANDOM = new SecureRandom();
}
