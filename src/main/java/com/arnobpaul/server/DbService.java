package com.arnobpaul.server;

import com.arnobpaul.common.ClientEntity;

import java.sql.*;
import java.util.logging.Logger;

public class DbService {
    private static final String DATABASE_URL = "jdbc:sqlite:server.db";

    private static final String CLIENT_DATA_TABLE = "client_data";
    private static final String CLIENT_ID_COL = "id";
    private static final String CLIENT_NAME_COL = "client_name";
    private static final String CLIENT_PUBLIC_KEY_COL = "public_key";

    private final Connection dbConnection;

    private static final Logger logger = Logger.getLogger(DbService.class.getName());

    public DbService() throws SQLException {
        dbConnection = DriverManager.getConnection(DATABASE_URL);

        dbConnection.createStatement().execute(
                "CREATE TABLE IF NOT EXISTS " + CLIENT_DATA_TABLE + " (\n"
                        + CLIENT_ID_COL + " integer PRIMARY KEY,\n"
                        + CLIENT_NAME_COL + " text NOT NULL,\n"
                        + CLIENT_PUBLIC_KEY_COL + " text NOT NULL\n"
                        + ");");
    }

    public int insert(String clientName, String clientPublicKey) throws SQLException {
        final String sql = "INSERT INTO " + CLIENT_DATA_TABLE +
                " (" + CLIENT_NAME_COL + "," + CLIENT_PUBLIC_KEY_COL + ") VALUES(?,?)";

        PreparedStatement statement = dbConnection.prepareStatement(sql);
        statement.setString(1, clientName);
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

    public boolean updateClientPublicKey(int clientId, String newClientPublicKey) throws SQLException {
        final String sql = "UPDATE " + CLIENT_DATA_TABLE + " SET " +
                CLIENT_PUBLIC_KEY_COL + " = ? WHERE " + CLIENT_ID_COL + " = ?";

        PreparedStatement statement = dbConnection.prepareStatement(sql);
        statement.setString(1, newClientPublicKey);
        statement.setInt(2, clientId);
        int affectedRows = statement.executeUpdate();

        if (affectedRows != 1) {
            throw new SQLException("Update failed.");
        }

        return true;
    }

    public ClientEntity getClient(int clientId) throws SQLException {
        final String sql = "SELECT * FROM " + CLIENT_DATA_TABLE + " WHERE " + CLIENT_ID_COL + " = ?";

        PreparedStatement statement = dbConnection.prepareStatement(sql);
        statement.setInt(1, clientId);
        ResultSet clientSet = statement.executeQuery();

        if (clientSet.next()) {
            return new ClientEntity(clientId,
                    clientSet.getString(CLIENT_NAME_COL),
                    clientSet.getString(CLIENT_PUBLIC_KEY_COL));
        } else {
            throw new SQLException("Could not be fetched.");
        }
    }

    public boolean delete(int clientId) throws SQLException {
        final String sql = "DELETE FROM " + CLIENT_DATA_TABLE + " WHERE " + CLIENT_ID_COL + " = ?";

        PreparedStatement statement = dbConnection.prepareStatement(sql);
        statement.setInt(1, clientId);
        int deletedRows = statement.executeUpdate();

        return (deletedRows > 0);
    }
}
