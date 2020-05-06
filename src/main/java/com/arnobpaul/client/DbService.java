package com.arnobpaul.client;

import com.arnobpaul.common.ClientEntity;
import com.arnobpaul.common.crypto.AsymmetricKeyPair;

import java.io.File;
import java.nio.file.FileSystemException;
import java.sql.*;

public class DbService {
    private static final String DATABASE_URL_PREFIX = "jdbc:sqlite:";
    private static final String DATABASE_URL_SUFFIX = "client.db";

    private static final String CLIENT_DATA_TABLE = "client_data";
    private static final String CLIENT_ID_COL = "id";
    private static final String CLIENT_NAME_COL = "client_name";
    private static final String CLIENT_PUBLIC_KEY_COL = "public_key";
    private static final String CLIENT_PRIVATE_KEY_COL = "private_key";

    private static final String TRUST_LIST_TABLE = "trust_list";
    private static final String TRUST_LIST_CLIENT_ID_COL = "id";
    private static final String TRUST_LIST_CLIENT_PUBLIC_KEY_COL = "public_key";

    private static final String BLOCK_LIST_TABLE = "block_list";
    private static final String BLOCK_LIST_CLIENT_ID_COL = "id";

    private final Connection dbConnection;

    public DbService(String dataFolder) throws FileSystemException, SQLException {
        File dataFolderFile = new File(dataFolder);
        boolean isFolderCreated = new File(dataFolder).mkdir();
        if (!isFolderCreated && !dataFolderFile.exists()) {
            throw new FileSystemException("Data folder not created.");
        }

        dbConnection = DriverManager.getConnection(DATABASE_URL_PREFIX + dataFolder + "/" + DATABASE_URL_SUFFIX);

        dbConnection.createStatement().execute(
                "CREATE TABLE IF NOT EXISTS " + CLIENT_DATA_TABLE + " (\n"
                        + CLIENT_ID_COL + " integer PRIMARY KEY,\n"
                        + CLIENT_NAME_COL + " text NOT NULL,\n"
                        + CLIENT_PUBLIC_KEY_COL + " text NOT NULL,\n"
                        + CLIENT_PRIVATE_KEY_COL + " text NOT NULL\n"
                        + ");");

        dbConnection.createStatement().execute(
                "CREATE TABLE IF NOT EXISTS " + TRUST_LIST_TABLE + " (\n"
                        + TRUST_LIST_CLIENT_ID_COL + " integer PRIMARY KEY,\n"
                        + TRUST_LIST_CLIENT_PUBLIC_KEY_COL + " text NOT NULL\n"
                        + ");");

        dbConnection.createStatement().execute(
                "CREATE TABLE IF NOT EXISTS " + BLOCK_LIST_TABLE + " (\n"
                        + BLOCK_LIST_CLIENT_ID_COL + " integer PRIMARY KEY\n"
                        + ");");
    }

    public int setLoginClient(ClientEntity client) throws SQLException {
        //noinspection SqlWithoutWhere
        final String sqlDelete = "DELETE FROM " + CLIENT_DATA_TABLE;
        PreparedStatement statement = dbConnection.prepareStatement(sqlDelete);
        statement.executeUpdate();

        final String sqlInsert = "INSERT INTO " + CLIENT_DATA_TABLE +
                " (" + CLIENT_ID_COL + "," + CLIENT_NAME_COL + "," + CLIENT_PUBLIC_KEY_COL + "," + CLIENT_PRIVATE_KEY_COL + ") " +
                "VALUES(?,?,?,?)";

        statement = dbConnection.prepareStatement(sqlInsert);
        statement.setInt(1, client.clientId);
        statement.setString(2, client.clientName);
        statement.setString(3, client.clientPublicKey);
        statement.setString(4, client.clientPrivateKey);
        int affectedRows = statement.executeUpdate();

        if (affectedRows == 0) {
            throw new SQLException("Saving failed.");
        }

        try (ResultSet generatedKeys = statement.getGeneratedKeys()) {
            if (generatedKeys.next()) {
                return generatedKeys.getInt(1);
            } else {
                throw new SQLException("Saving failed.");
            }
        }
    }

    public ClientEntity getLoginClient() throws SQLException {
        final String sql = "SELECT * FROM " + CLIENT_DATA_TABLE + " LIMIT 1";

        PreparedStatement statement = dbConnection.prepareStatement(sql);
        ResultSet clientSet = statement.executeQuery();

        if (clientSet.next()) {
            return new ClientEntity(clientSet.getInt(CLIENT_ID_COL),
                    clientSet.getString(CLIENT_NAME_COL),
                    clientSet.getString(CLIENT_PUBLIC_KEY_COL),
                    clientSet.getString(CLIENT_PRIVATE_KEY_COL));
        } else {
            throw new SQLException("Could not be fetched.");
        }
    }

    public boolean updateClientKey(int clientId, AsymmetricKeyPair newClientKeyPair) throws SQLException {
        final String sql = "UPDATE " + CLIENT_DATA_TABLE + " SET " +
                CLIENT_PUBLIC_KEY_COL + " = ? , " + CLIENT_PRIVATE_KEY_COL + " = ? WHERE " + CLIENT_ID_COL + " = ?";

        PreparedStatement statement = dbConnection.prepareStatement(sql);
        statement.setString(1, newClientKeyPair.publicKey);
        statement.setString(2, newClientKeyPair.privateKey);
        statement.setInt(3, clientId);
        int affectedRows = statement.executeUpdate();

        if (affectedRows != 1) {
            throw new SQLException("Update failed.");
        }

        return true;
    }

    public int insertOrUpdateToTrustList(int clientId, String clientPublicKey) throws SQLException {
        final String sql = "INSERT OR REPLACE INTO " + TRUST_LIST_TABLE +
                " (" + TRUST_LIST_CLIENT_ID_COL + "," + TRUST_LIST_CLIENT_PUBLIC_KEY_COL + ") " +
                "VALUES(?,?)";

        PreparedStatement statement = dbConnection.prepareStatement(sql);
        statement.setInt(1, clientId);
        statement.setString(2, clientPublicKey);
        int affectedRows = statement.executeUpdate();

        if (affectedRows == 0) {
            throw new SQLException("Insert failed.");
        }

        try (ResultSet generatedKeys = statement.getGeneratedKeys()) {
            if (generatedKeys.next()) {
                return generatedKeys.getInt(1);
            } else {
                throw new SQLException("Insert failed.");
            }
        }
    }

    public String getClientPublicKeyFromTrustList(int clientId) throws SQLException {
        final String sql = "SELECT * FROM " + TRUST_LIST_TABLE + " WHERE " + TRUST_LIST_CLIENT_ID_COL + " = ?";

        PreparedStatement statement = dbConnection.prepareStatement(sql);
        statement.setInt(1, clientId);
        ResultSet clientSet = statement.executeQuery();

        if (clientSet.next()) {
            return clientSet.getString(TRUST_LIST_CLIENT_PUBLIC_KEY_COL);
        } else {
            return null;
        }
    }

    public boolean deleteFromTrustList(int clientId) throws SQLException {
        final String sql = "DELETE FROM " + TRUST_LIST_TABLE + " WHERE " + TRUST_LIST_CLIENT_ID_COL + " = ?";

        PreparedStatement statement = dbConnection.prepareStatement(sql);
        statement.setInt(1, clientId);
        int deletedRows = statement.executeUpdate();

        return (deletedRows > 0);
    }

    public int insertOrIgnoreToBlockList(int clientId) throws SQLException {
        final String sql = "INSERT OR IGNORE INTO " + BLOCK_LIST_TABLE +
                " (" + BLOCK_LIST_CLIENT_ID_COL + ") " +
                "VALUES(?)";

        PreparedStatement statement = dbConnection.prepareStatement(sql);
        statement.setInt(1, clientId);
        int affectedRows = statement.executeUpdate();

        if (affectedRows == 0) {
            throw new SQLException("Insert failed.");
        }

        try (ResultSet generatedKeys = statement.getGeneratedKeys()) {
            if (generatedKeys.next()) {
                return generatedKeys.getInt(1);
            } else {
                throw new SQLException("Insert failed.");
            }
        }
    }

    public boolean isClientIdInBlockList(int clientId) throws SQLException {
        final String sql = "SELECT * FROM " + BLOCK_LIST_TABLE + " WHERE " + BLOCK_LIST_CLIENT_ID_COL + " = ?";

        PreparedStatement statement = dbConnection.prepareStatement(sql);
        statement.setInt(1, clientId);
        ResultSet clientSet = statement.executeQuery();

        if (clientSet.next()) {
            return true;
        } else {
            return false;
        }
    }

    public boolean deleteFromBlockList(int clientId) throws SQLException {
        final String sql = "DELETE FROM " + BLOCK_LIST_TABLE + " WHERE " + BLOCK_LIST_CLIENT_ID_COL + " = ?";

        PreparedStatement statement = dbConnection.prepareStatement(sql);
        statement.setInt(1, clientId);
        int deletedRows = statement.executeUpdate();

        return (deletedRows > 0);
    }
}
