# Design Doc

## Overview
This project introduces a client application for a secure file sharing system, leveraging various cryptographic primitives to ensure data security. Imagine something similar to Dropbox, but secured with cryptography so that the server cannot view or tamper with user data.

The client is implemented in Golang and offers a suite of features including:
- Authenticate with a username and password
- Save files to the server
- Load saved files from the server
- Overwrite saved files on the server
- Append to saved files on the server
- Share saved files with other users
- Revoke access to previously shared files

## Data Structures
```go
type User struct {
	Username              string
	Password              string
	PasswordHash          []byte
	PublicKey             userlib.PKEEncKey
	PrivateKey            userlib.PKEDecKey
	PublicVerificationKey userlib.DSVerifyKey
	PrivateSignKey        userlib.DSSignKey
	Namespace             map[string]FileMetadataNS
	ShareStructs          map[string]ShareStructsValue
}

// Stored at UUID(Hash(username+ns+filename))
type FlattenedNamespaceEntry struct {
	EncryptedFileMetadataNS       []byte
	SignedEncryptedFileMetadataNS []byte
}

type FlattenedNamespaceHybridPair struct {
	EncryptedFileMetadata []byte
	EncryptedSymKey       []byte
}

// Stored at UUID(Hash(username+sh+filename))
type FlattenedShareStructsEntry struct {
	EncryptedShareStructsValue       []byte
	SignedEncryptedShareStructsValue []byte
}

type FlattenedShareStructsHybridPair struct {
	EncryptedShareStructsValue []byte
	EncryptedSymKey            []byte
}

type ShareStructsValue struct {
	ShareStructPairUUID uuid.UUID
	SymKey              []byte
	HMACKey             []byte
	FileUUID            uuid.UUID
	FileSymKey          []byte
	HMACKeyFiles        []byte
	HMACKeyNode         []byte
}

type StoredShareData struct {
	EncryptedShareStruct     []byte
	EncryptedShareStructHMAC []byte
}

type Share struct {
	FileUUID        uuid.UUID
	SymKey          []byte
	HMACKeyFiles    []byte
	HMACKeyNode     []byte
	ParentUUID      uuid.UUID
	ShareStructsSet uuid.UUID // uuid to a ShareStructsSetUUID struct
}

type ShareStructsSetUUID struct {
	EncryptedShareStructsSet     []byte
	EncryptedShareStructsSetHMAC []byte
}

type ShareStructSet struct {
	ShareStructSet map[string]ShareStructSetValue
}

type ShareStructSetValue struct {
	Username  string
	ChildUUID uuid.UUID
}

type Invitation struct {
	Filename            string
	Sender              string
	Receiver            string
	Revoked             bool
	ShareStructPairUUID uuid.UUID
	ShareStructsSymKey  []byte
	ShareStructsHMACKey []byte
}

type InvitationHybridPair struct {
	EncryptedInvitation []byte
	EncryptedSymKey     []byte
}

type StoredInvitationData struct {
	InvitationHybridPair       []byte
	SignedInvitationHybridPair []byte
}

type StoredUserData struct {
	EncryptedUser        []byte
	SignedEncryptedUser  []byte
	Username             string
	HashedSerializedUser []byte
}

type FileMetadataNS struct {
	UUIDStart    uuid.UUID
	SymKey       []byte
	HMACKeyFiles []byte
	HMACKeyNodes []byte
}

type File struct {
	Content []byte
	Owner   uuid.UUID
}

type StoredFileData struct {
	EncryptedFile     []byte
	EncryptedFileHMAC []byte
}

type LinkedListNode struct {
	SerializedUUIDPair     []byte
	SerializedUUIDPairHMAC []byte
}

type NodeUUIDPair struct {
	FileUUID     uuid.UUID
	NextNodeUUID uuid.UUID
}
```

## User Authentication

### ` InitUser(username string, password string) `

#### High Level Overview
Constructor of the User class, used when a user logs in for the first time. Creates a new User object and returns a Go memory pointer to the new User struct. The User struct can include any instance variables for the corresponding User object.

Returns an error if:
- A user with the same username exists.
- An empty username is provided.

#### Implementation Details
Hash the username, take the first 16 bytes of the hash, and convert it to a
UUID using uuid.FromBytes. If this UUID already exists in Datastore or the username is empty, return an error.
Create a user struct using the username and password arguments (as specified by the fields in the user struct above).
Serialize the user struct using json.Marshal, encrypt the serialized user struct using the password Argon2Key hash as
the symmetric key and a RandomBytes(16) IV with SymEnc, and sign the encryption of the serialized user struct using
the user’s signing key with DSSign. Compute the Argon2Key hash of the serialized user struct, with any fixed salt.
Serialize [encryption of the serialized user struct, signature of the encryption of the serialized user struct, username,
Argon2Key hash of the serialized user struct] using json.Marshal, and store on Datastore at the previously generated
UUID. Store the user’s public key and verification key to Keystore using KeystoreSet, with names username+“PK”
and username+“DS” respectively

### ` GetUser(username string, password string) `

#### High Level Overview
Constructor of the User class, used when an existing user logs in. Creates a User object for a user who has already been initialized with InitUser, and returns a Go memory pointer to it.

Returns an error if:
- There is no initialized user for the given username.
- The user credentials are invalid.
- The User struct cannot be obtained due to malicious action, or the integrity of the user struct has been compromised.

#### Implementation Details
Compute the Hash on the username, keep the first 16 bytes, convert it to
UUID using uuid.FromBytes, and check if this UUID exists in Datastore using DatastoreGet. If the UUID exists,
deserialize the value with json.Unmarshal to get the encryption of the serialized user struct, signature of the
encryption of the serialized user struct, username, and Argon2Key hash of the serialized user struct. Else, return an
error. Use the signature to verify that the encryption of the serialized user struct hasn’t been tampered with using
DSVerify (retrieve the user’s verification key from Keystore using their username+“DS”). If DSVerify returns a
non-nil error, return an error. Else, compute the Argon2Key hash of the password, using the marshaled username as
the salt, and use it as the symmetric key to decrypt the encryption of the serialized user struct. Compute the
Argon2Key hash of the decrypted serialized user struct, and compare it to the received Argon2Key hash of the
serialized user struct using HMACEqual – they will be equal if and only if the provided password is the true password
for this user. If HMACEqual returns true, use the fields of this struct to create a new User object in local memory.



## File Operations

### ` User.StoreFile(filename string, content []byte) `

#### High Level Overview
Given a filename in the personal namespace of the caller, this function persistently stores the given content for future retrieval using the same filename. If the given filename already exists in the personal namespace of the caller, then the content of the corresponding file is overwritten.

Returns an error if:
- The write cannot occur due to malicious action.

#### Implementation Details
Check the user’s struct for the filename in the Namespace map. If
absent, create a new file struct, encrypt it after serialization (symmetric key and IV created with calls to
RandomBytes(16)), and compute the HMAC value on the encrypted serialized file struct (HMAC key created with
RandomBytes(16)). Store the serialized (encryption of the serialized file struct, HMAC of the encryption of the
serialized file struct) in the Datastore at a random UUID. Create and store the linked list node (serialized (UUID of
the actual file, None) pair, HMAC of the serialized pair) at another random UUID (HMAC key created with
RandomBytes(16)). Add this filename to (UUID_START, symmetric key, HMAC key for files, HMAC key for linked
list nodes) mapping to the Namespace map; store the user struct to Datastore. If the filename exists, create a new file
struct and follow the same process to store the serialized tuple representing the file struct to Datastore. The linked list
node should be stored at the existing UUID_START for filename. Update the symmetric key, HMAC key for the files,
and HMAC key for the nodes in the tuple mapped to by this filename in the Namespace map, store the user struct on
Datastore.

### ` User.LoadFile(filename string) `

#### High Level Overview
Given a filename in the personal namespace of the caller, this function downloads and returns the content of the corresponding file.

Returns an error if:
- The given filename does not exist in the personal file namespace of the caller.
- The integrity of the downloaded content cannot be verified (indicating there have been unauthorized modifications to the file).
- Loading the file cannot succeed due to any other malicious action.

#### Implementation Details
Verify that filename is in the user’s Namespace map; if absent, return an
error. Retrieve the symmetric key from Namespace and traverse the linked list starting at UUID_START, retrieving
and deserializing each node from Datastore to get (serialized (UUID of the file, UUID of the next node of the linked
list) pair, HMAC of the serialized pair). Verify each node’s HMAC value using the HMAC key for nodes with
HMACEval and then HMACEqual. If verification fails, return an error. Otherwise, retrieve the (encryption of the
serialized file struct, HMAC of the encryption) tuple at the UUID in the node, verify the HMAC value using the
HMAC key for files with HMACEval and then HMACEqual. If verification fails, return an error. Decrypt and
unmarshal the file struct, inserting the Content field to the beginning of a result byte array. After traversing each node,
return the result array. If the integrity of the user struct cannot be verified, then storing and loading the file cannot
succeed due to potential malicious activity.

### ` User.AppendToFile(filename string, content []byte) `

#### High Level Overview
Given a filename in the personal namespace of the caller, this function appends the given content to the end of the corresponding file.

Returns an error if:
- The given filename does not exist in the personal file namespace of the caller.
- Appending the file cannot succeed due to any other malicious action.

#### Implementation Details
In the Namespace map, UUID_START represents the start of a linked list of nodes
representing file chunks that make up the file. A linked list node is stored in Datastore as (serialized (UUID of the file
the node represents, the UUID of the next node of the linked list), HMAC of the serialized pair using the HMAC key
for nodes). The new file for this append is created similarly to how files are created with StoreFile, only now we
encrypt the serialized file struct with the existing symmetric key corresponding to this filename, and when we create
the new linked list node for this file, we set its next pointer to the updated UUID of the node that used to be the start
node of the linked list. Thus, the total bandwidth used in a call to append is n + size of the IV in the ciphertext of the
serialized file struct + HMAC of the encryption of the serialized file struct + bandwidth to read the current node at
UUID_START + bandwidth to write the current node at UUID_START to a new random UUID + bandwidth to
write the node corresponding to the appended file to UUID_START = n+16+64+96+96+96= n+368.



## Sharing and Revocation

### ` CreateInvitation(filename string, recipientUsername string) `

#### High Level Overview
Generates an invitation UUID invitationPtr, which can be used by the target user recipientUsername to gain access to the file filename. The recipient user will not be able to access the file (e.g. load, store) until they call AcceptInvitation, where they will choose their own (possibly different) filename for the file.

Returns an error if:
- The given filename does not exist in the personal file namespace of the caller.
- The given recipientUsername does not exist.
- Sharing cannot be completed due to any malicious action.

#### Implementation Details
Verify the existence of recipientUsername through a public key retrieval from the Keystore. If
the user is the owner of the file, then filename will be in their Namespace map. If not, and the filename is in the
ShareStructs map, the file has been shared with the user. Else, return an error. The value in the ShareStructs map is of
the form (UUID of the serialized (encrypted serialized share struct, HMAC on the encrypted serialized share struct)
pair, symmetric key, HMAC key). If the user is the owner and already has a share struct in the ShareStructs map for
this filename, retrieve the encrypted serialized share struct from Datastore, verify its HMAC, and decrypt and
deserialize. If the user is the owner and doesn’t have a share struct in the ShareStructs map for this filename, create the
share struct and store (encrypted serialized share struct, HMAC of the encrypted serialized share struct) to Datastore
at a random UUID. Add this UUID and the encryption and HMAC keys as the value for this filename in the
ShareStructs map. If the user is not the owner of the file, the process is similar to the case where the user is the owner
and already has a share struct in the ShareStructs map for the filename. Create a new share struct for this invitation,
where the ParentUUID is the UUID of the user’s share struct, and SharedStructsSet is empty. Store the serialized
(encryption of the new serialized share struct using the symmetric key used for the user’s share struct, HMAC of the
first value using the HMAC key used by the user’s share struct) to datastore at a random UUID, and add the
(recipientUsername, UUID) pair to the SharedStructsSet of the user’s share struct. Create an invitation struct, setting
ShareStructPair to the UUID, and the rest of the fields as specified in the struct definition. Store the serialized
(encryption of the serialized invitation struct using the recipient’s public key, signature of the first value using the user’s
sign key) at a random UUID, and return this UUID.

### ` AcceptInvitation(senderUsername string, invitationPtr UUID, filename string) `

#### High Level Overview
Accepts an invitation by inputting the username of the sender (senderUsername), and the invitation UUID (invitationPtr) that the sender previously generated with a call to CreateInvitation.

Returns an error if:
- The user already has a file with the chosen filename in their personal file namespace.
- Something about the invitationPtr is wrong (e.g. the value at that UUID on Datastore is corrupt or missing, or the user cannot verify that invitationPtr was provided by senderUsername).
- The invitation is no longer valid due to revocation.

#### Implementation Details
If the filename already exists in the recipient's Namespace or ShareStructs maps, return an
error. Retrieve the serialized tuple (encryption of the serialized invitation struct, signature of first value) from
Datastore at the invitationPtr UUID; deserialize, verify the signature using the sender's verify key from Keystore with
DSVerify, (if verified) decrypt with the user’s private key and deserialize to get the invitation struct. If Revoked, return
an error. The ShareStructPair field contains (UUID of the (encryption of the serialized share struct, HMAC on first
value), symmetric key, HMAC key) – add this value to the recipient’s ShareStructs map under the filename with which
the recipient accepted the invitation and store the updated user struct to Datastore. Use these values to get the share
struct from Datastore (verifying HMAC and decrypting as usual). Now, to access/interact with files, user checks if the
filename is in its Namespace – if true, interact with file as usual; else check if the filename is in the ShareStructs map –
if true, do the following until ParentUUID is nil (i.e. reached the owner’s share struct): get the share struct from
Datastore at the current UUID (same way as we did above – verifying HMAC and decrypting as usual), set the current
UUID to the ParentUUID. Once at the owner share struct, have all values necessary to access the file as usual.

### ` RevokeAccess(filename string, recipientUsername string) `

#### High Level Overview
Revokes access to filename from the target user recipientUsername, and all the users that recipientUsername shared the file with (either directly or indirectly).

Returns an error if:
- The given filename does not exist in the caller’s personal file namespace.
- The given filename is not currently shared with recipientUsername.
- Revocation cannot be completed due to malicious action.

#### Implementation Details
If the filename does not exist in the Namespace map of the user’s user struct, return an error. If
the filename does not exist in the ShareStructs map of the user’s user struct, return an error. Else, retrieve (UUID of
the serialized (encrypted serialized share struct, HMAC of first value) pair, symmetric key, HMAC key) from the
ShareStructs map at the filename. Get the share struct at the UUID (verifying HMAC and decrypting as before). If
recipientUsername exists in SharedStructsSet, get the UUID representing the recipient's share struct, else return an
error. Remove (recipientUsername, UUID) from the SharedStructsSet of the user’s share struct, store the share struct
to Datastore. Delete the value on the Datastore at the UUID representing the recipient's share struct using
DatastoreDelete. Update the UUID representing the user’s share struct to a new random UUID (NewOwnerUUID) –
go through each UUID in the SharedStructsSet of the user’s share struct, updating the ParentUUID field of the share
struct at this UUID to NewOwnerUUID (store the updated share struct to Datastore as in CreateInvitation). Change
the UUID_START of the file to a new random UUID, updating the user’s Namespace map in the user struct and
FileUUID field in the share struct for this filename.
