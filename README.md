# Overview of the project

The project is of secure chat.

## Target functionalities

1.  **Confidentiality:** Secure chat ensures the confidentiality of the message communication against outsiders including the service provider.

2.  **Authenticity:** Secure chat also ensures the authenticity of the message communication so that each client can verify the sender of the received secret messages.

3.  **Integrity:** Secure chat also ensures the integrity of the message communication so that each client can verify the contents of the received secret messages being unaltered by any third party.

4.  **Repudiability:** Secure chat provides the repudiability of all message communication between any two clients. So each client of the two clients cannot prove to others (i.e., any entities other than the two clients) that a specific message was sent by the other client.

5.  **Trust:** In secure chat, no clients need to trust the service provider to ensure all the above-mentioned security guarantees. Even if the service provider does some malicious actions (such as sending a fake message impersonating a specific client), the clients can easily detect these actions. So the message communication between any two clients always ensures all the mentioned security guarantees regardless of the behavior of the service provider (i.e., malicious server or legitimate server).

6.  **Forward secrecy:** Secure chat also includes forward secrecy. If an adversary (eavesdropper) records all the encrypted communication between two clients in the network traffic, and later somehow steal the private keys of one or both of the clients, then the adversary cannot decrypt the recorded encrypted messages. Even if the eavesdropper somehow manages to steal a shared secret key used in the message communication, it still only get access to a very small portion of messages. In this way, secure chat provides forward secrecy.

## Security model and objectives

1.  **What information is to be protected:** In this security model, all the message communication between any two clients is protected. It means that all messages between any two clients ensure confidentiality, integrity, and the authenticity of the messages.

2.  **From whom information is to be protected:** The message communication between any two clients is protected against any third parties other than the participating two clients. So the third parties also include the service provider itself.

3.  **What the adversary is capable of:** The adversary can alter any message in a communication channel of secure chat. It can try to impersonate a specific client. It can also hack the service provider and access the database in the provider. Even the adversary can be the service provider itself. In this way, the adversary may try to confuse other clients by sending fake packets.

4.  **What the adversary is not capable of:** The adversary cannot gain access to a client device. Thus, the adversary cannot fetch the private key of a client. The adversary also cannot hamper the network traffic for an unlimited amount of time (i.e., the adversary is assumed to unable to perform a denial-of-service attack). The adversary cannot achieve any confidential messages or a private key by breaking any security algorithm (i.e., encryption, decryption, signing, MAC) in polynomial time using its limited resource.

5.  **Trust assumptions:** The clients in this security model do not need to trust the service provider to ensure all the mentioned security properties. But a client needs to trust the public key of the other client who wants to communicate with the first client. How the public keys of the two communicating clients will be trusted by each other clients is out of the scope of this project. But the public keys may be exchanged by using any side-channel communication like even an in-person meeting. Besides, each client needs to trust that the private key of the other client is not leaked to an adversary. But if the private key of a client is stolen, the victim client will inform this event to all other clients using a side-channel before any secret message communication occurs after the stealing event.

6.  **Desired security objectives:** Secure chat ensures confidentiality, integrity, and authenticity of any message communication between two clients. It also ensures the repudiability of sent messages so that it cannot be claimed later to a third party that the sent message was sent by a specific client. Secure chat also does not rely on the service provider to ensure all the above security objectives. Rather the service provider just helps passing messages between a client to another client, and also provides the public key of a specific client. But whether the client will trust or distrust the provided public key of a specific client is up to the client. In the end, it is the client that ensures all the security objectives. Secure chat also ensures perfect forward secrecy of message communication against stealing the private keys of the communicating clients by a passive adversary (eavesdropper).

## Description of the complete cryptographic design

### Common things

Though the message formats are mentioned in this submission report, these can be checked in the source file called `AppConfig.java` directly. Unless otherwise stated, all the binary data such as encrypted data, keys, signatures, HMAC tags, etc. are encoded into base64 before transmitted into the network. In this project, binary data without any encoding are never sent/received. It ensures better debuggability since sent/received messages can be logged easily.

### Authentication (sign up)

Every client needs to sign up on a server for the first time. The goal is to store every client’s public key in the server so that it can distribute the public key of the client whenever needed by some clients (i.e., before initiating a message communication). The server authenticates the public key of the new client by checking if the client possesses the corresponding private key of the given public key. But it is not important to authenticate the public keys by the server under the security model. Anyways, the following things happen during sign up:

1.  The client generates a pair of 2048-bit RSA PKCS\#1  keys (public key and private key).

2.  The client sends the public key to the server along with the client’s name for requesting signup. Message format: `SIGNUP <Client_Name> <Client_Public_Key>`

3.  The server assigns a unique client ID to the client and saves the client’s name and public key into the server’s database (filename `server.db`). Here is the database table creation statement:  
    `CREATE TABLE client_data ( id integer PRIMARY KEY, client_name text NOT NULL, public_key text NOT NULL );`

4.  The server sends the unique client ID to the client. Message format: `SIGNUP_SUCCESS <Client_ID>`

5.  The client saves the user ID and the key pair in its local database (filename `client.db`) because it is needed for logging in next time. The entry is saved in the table created using the statement:  
    `CREATE TABLE client_data ( id integer PRIMARY KEY, client_name text NOT NULL, public_key text NOT NULL, private_key text NOT NULL );`

6.  The server treats the client non-verified (whether the client owns the corresponding private key). The client needs to login to the server within 5 minutes (it is currently stored in the variable `SERVER_SIGNUP_TIMEOUT` in the source file `AppConfig.java` instead of a configuration file). Otherwise, the server will delete the entry of the client. This step may somewhat prevent the DoS attack but it is not the main focus of the project.

### Authentication (login)

In this step, the goal is to tell the service provider that the client is active so that the server can pass messages from other clients being able to communicate with the client via the server. The server authenticates the client during login to verify that the client possesses the corresponding private key of the saved public key. But the verification process is not important to ensure the project’s security objectives. The verification is just for convenience (connecting via the server) rather than ensuring security. The following things happen during login:

1.  The client sends its client ID to a request for login to the server. Message format: `LOGIN <Client_ID>`

2.  The server replies a cryptographically random 64-bit nonce (`long`) and the current timestamp milliseconds (`long`) to the client. Message format: `LOGIN_NONCE <Nonce> <Timestamp>`

3.  The client replies to the server with the RSA signature signed to the text combining the nonce and the timestamp (`%d %d`) with the client’s private key. The signature scheme includes SHA-256 and the RSA encryption algorithm as defined in the OSI Interoperability Workshop, using the padding conventions described in PKCS\#1 . Message format: `LOGIN_ACCEPT <Signature>`

4.  The server verifies the signature with the client’s public key.

5.  The server replies to the client with the verification result (success or failure). Message format: `LOGIN_SUCCESS` or `LOGIN_FAILURE`

### Communication with another client (secure chat)

This is the most important step of the whole project. In this step, clients need to be vigilant to ensure the security objectives previously mentioned. With the following design and its corresponding implementation, clients can ensure the security objectives.  
Suppose, `Client_A` wants to communicate with `Client_B`. The following things will happen:

1.  After a successful login of `Client_A`, it sends a request for initiating the communication with `Client_B` using the `Client_B`’s client ID to the server. Message format: `SEND_START <Client_ID>`  
    By the current design, it is possible to send any arbitrary message to any other clients via the server even without any initialization. The server trivially passes the data from one client to another client. Message format in this case: `SEND <Client_ID> <Data>`  
    There is one thing to clarify. The subsequent message formats after Step 2 are actually the part of the `<data>` field. The server does not care about what types of messages in the `<data>` field are sent.

2.  After receiving the request for initiating the communication, the server replies to `Client_A` with the public key of `Client_B`. The server also sends a message to `Client_B` (if logged in) with the public key of `Client_A`. Message format for the both cases: `SEND_INVITE <Client_ID> <Client_Public_Key>`  
    If `Client_B` is not logged in, then server informs it to `Client_A`. Message format: `SEND_FAILURE <Client_ID>`

3.  If `Client_A` trusts the public key of `Client_B` provided by the server (or an attacker in a MITM attack), `Client_A` will continue executing the next steps. The similar things happen to `Client_B`. There is a trust list in each client to check for the trust of a client. The trust table creation is done using the statement:  
    `CREATE TABLE trust_list ( id integer PRIMARY KEY, public_key text NOT NULL );`

4.  Both of the clients will generate a symmetric key using the Diffie-Hellman key exchange through the server (i.e., no client-to-client connection). The key will be used as a seed to a specific pseudorandom generator (PRG) used by all the clients in the system. PRG will generate two keys from the shared seed – one for AES encryption, the other for integrity using HMAC. The details are in the following steps.

5.  In the very first step of the message communication, there is no shared secret key generated. So, to ensure the Diffie-Hellman key exchange without any key alteration, each client uses RSA with SHA-256 using the padding conventions described in PKCS\#1  to sign/verify the public portion of Diffie-Hellman key pairs. The Diffie-Hellman key size is 2048 bits. Each client includes its sequence number which is also in the text to sign so that send the same message twice will be invalidated, as the signature will not match. It will prevent the replay attack. Here are the pair of message formats for this step:
    
      - `DATA_DH_START <Signature> <Seq_Num> <Client_DH_Public_Key>`
    
      - `DATA_DH_START_ACCEPT <Signature> <Seq_Num> <Client_DH_Public_Key>`

6.  From the above step, each client can generate a secret key shared by both of the clients. Using the shared secret key and the PRG, both clients will generate two keys – one for encryption, another one for HMAC tags. Every message includes the ciphertext from the chat message, the sequence number, the valid tag using HMAC for integrity check. More specifically, the encryption algorithm is AES-256 with CBC mode and PKCS\#5 padding . The algorithm for HMAC tags is the HMAC-SHA-256 keyed hashing algorithm for message authentication . So, PRG will take the input of the 2048-bit shared secret key from Diffie-Hellman key exchange and provide the output of 256-bit key for AES-256 encryption and 2048-bit key for HMAC-SHA-256 tagging. Message format: `DATA Enc(<HMAC> <Seq_Num> <Message>)`

7.  One of the clients randomly-chosen periodically (and randomly) requests to the other client for renewing the two keys (i.e., one for encryption, the other for integrity). The other client must accept the request and both of the clients generate a new shared seed using Diffie-Hellman key exchange. PRG will renew the two keys from the shared seed. Renewing the keys will also reset the sequence numbers of both clients. In this way, no client needs to store the other client’s valid sequence number permanently because a valid sequence number always starts from 0 after every Diffie-Hellman key exchange.  
    But here is an important difference from the initial key exchange. Here instead of using the RSA signature, both of the clients use HMAC tags to exchange the public portion of Diffie-Hellman key pairs without any alteration. Here are the pair of message formats for this step:
    
      - `DATA_DH_CHANGE <HMAC> <Seq_Num> <Client_DH_Public_Key>`
    
      - `DATA_DH_CHANGE_ACCEPT <HMAC> <Seq_Num> <Client_DH_Public_Key>`
    
    There is a configuration variable called `MESSAGE_SEQUENCE_NUMBER_UPDATE_MIN` in  
    `AppConfig.java` file. The variable defines the minimum sequence number after which any of the clients may want to renew keys with a 50% chance. So this variable defines how frequently the clients will renew keys.

### Renew the RSA key if needed

A client may want to renew the pair of RSA keys and update the public key in the server. Here, the server verifies two things: (i) the client still possesses the old private key, (ii) the client possesses the private key of the newly requested public key. Once again, just like the login steps, the verification process is not important to ensure the project’s security objectives. The verification is just for convenience. After successful renewal, other clients can know the new public key of the client but whether they will trust the new public key or reject it, is up to them. If one of the other clients trust the new public key, then it must have to update the public key in the trust list to initiate any message communication. Anyways, in the renewal of the public key, the following things happen:

1.  After a successful login, the client sends a request for renewing its pair of RSA keys to the server. Message format: `RENEW_KEY_REQUEST`

2.  The server replies to the client with a cryptographically random 64-bit nonce (`long`) and the current timestamp milliseconds (`long`), just like the login step. Message format: `RENEW_KEY_REQUEST_OK <Nonce> <Timestamp>`

3.  The client generates a new pair of RSA keys (public key and private key) but keeps the old pair of RSA keys.

4.  The client sends the new public key with the RSA signature (same algorithm as mentioned in the login step) using the old private key to the server. The client also includes the signature that signs the nonce and the timestamp using the new private key (same as the login step). Message format: `RENEW_KEY <Signature_Old> <New_Public_Key> <Signature_New>`

5.  The server verifies the received signature with the currently stored public key of the client.

6.  If the verification succeeds, the server will update the public key of the client.

7.  The server replies to the client with the verification result (success or failure). Message format: `RENEW_KEY_SUCCESS` or `RENEW_KEY_FAILURE`

8.  If the client receives a positive verification result (i.e., success), the client will replace the old pair of RSA keys with the new one.

### Trust list

The role of the trust list has been already mentioned. Each client has its own trust list. Here are the detailed functionalities of the trust list.

1.  Every client has a trust list which includes client IDs and their corresponding public keys.

2.  If `Client_A` receives a connection request from a client, `Client_B`, then `Client_A` checks if the client ID and its public key exist in `Client_A`’s trust list.
    
    1.  If not exist, then `Client_A` needs to use side-channel communication to verify `Client_B`’s public key, and add the public key along with `Client_B`’s client ID to the trust list.
    
    2.  If exist, then `Client_A` can communicate with `Client_B` as usual.

3.  If something bad happens related to the client ID stored in the trust list, the client can choose one of the following steps:
    
    1.  Untrust a client ID or a public key: The client needs to delete the client ID from the trust list.
    
    2.  Distrust a client ID: The client needs to delete the client ID from the trust list and add the client ID to the blocklist.

### Blocklist

The role of the block list is similar to the trust list. But here, only client IDs are stored. Here is the database statement to create the block list:  
`CREATE TABLE block_list ( id integer PRIMARY KEY );`

1.  Every client has a blocklist of client IDs, which is stored locally in the client.

2.  If a client receives a connection request from a client ID from the blocklist, the client will refuse it. Message format: `DATA_MESSAGE_ERROR`

3.  A client cannot send a message to the clients whose client ID’s are in the blocklist.

4.  A client can insert and delete an entry of a client ID.

5.  The reasons for inserting a client ID to the blocklist:
    
    1.  The client ID is compromised by an attacker. I.e., the attacker has got access to the client ID and the public key is updated by the attacker.
    
    2.  The person behind the client ID is not an intended person to be contacted (i.e., having a bad relationship between the two persons).

6.  The reasons for deleting a client ID to the blocklist:
    
    1.  If the person behind the client ID becomes an intended person to be contacted again (i.e., having a good relationship between the two persons), the client can delete the client ID from the blocklist.

