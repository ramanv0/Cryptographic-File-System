package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	// "strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
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
	FileUUID     uuid.UUID
	SymKey       []byte
	HMACKeyFiles []byte
	HMACKeyNode  []byte
	ParentUUID   uuid.UUID
	// ShareStructsSet map[string]ShareStructSetValue
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

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	if username == "" {
		return nil, errors.New("username is empty")
	}
	var userdata User
	userdata.Username = username
	userdata.Password = password

	usernameBytes, err := json.Marshal(username)
	if err != nil {
		return nil, err
	}
	usernameHash := userlib.Hash(usernameBytes)
	usernameUUID, err := uuid.FromBytes(usernameHash[:16])
	if err != nil {
		return nil, err
	}

	_, exists := userlib.DatastoreGet(usernameUUID)
	if exists {
		return nil, errors.New("user already exists")
	}

	passwordBytes, err := json.Marshal(password)
	if err != nil {
		return nil, err
	}

	passwordHash := userlib.Argon2Key(passwordBytes, usernameBytes, 16)
	userdata.PasswordHash = passwordHash

	publicKey, privateKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	userdata.PublicKey = publicKey
	userdata.PrivateKey = privateKey

	privateSignKey, publicVerificationKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}
	userdata.PublicVerificationKey = publicVerificationKey
	userdata.PrivateSignKey = privateSignKey

	namespace := make(map[string]FileMetadataNS)
	userdata.Namespace = namespace

	shareStructs := make(map[string]ShareStructsValue)
	userdata.ShareStructs = shareStructs

	serializedUser, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}

	iv := userlib.RandomBytes(16)
	encryptedUser := userlib.SymEnc(passwordHash, iv, serializedUser)

	signedEncryptedUser, err := userlib.DSSign(privateSignKey, encryptedUser)
	if err != nil {
		return nil, err
	}

	hashedSerializedUser := userlib.Argon2Key(serializedUser, []byte("fixedSaltForPasswordVerification"), 16)

	userdataToStore := StoredUserData{
		EncryptedUser:        encryptedUser,
		SignedEncryptedUser:  signedEncryptedUser,
		Username:             username,
		HashedSerializedUser: hashedSerializedUser,
	}

	serializedUserdataToStore, err := json.Marshal(userdataToStore)
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(usernameUUID, serializedUserdataToStore)

	err = userlib.KeystoreSet(username+"PK", publicKey)
	if err != nil {
		return nil, err
	}

	err = userlib.KeystoreSet(username+"DS", publicVerificationKey)
	if err != nil {
		return nil, err
	}

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	usernameBytes, err := json.Marshal(username)
	if err != nil {
		return nil, err
	}
	usernameHash := userlib.Hash(usernameBytes)
	usernameUUID, err := uuid.FromBytes(usernameHash[:16])
	if err != nil {
		return nil, err
	}

	storedUserdataBytes, exists := userlib.DatastoreGet(usernameUUID)
	if !exists {
		return nil, errors.New("user doesn't exist")
	}

	var storedUserData StoredUserData
	err = json.Unmarshal(storedUserdataBytes, &storedUserData)
	if err != nil {
		return nil, err
	}

	publicVerificationKey, exists := userlib.KeystoreGet(username + "DS")
	if !exists {
		return nil, errors.New("verification key not found")
	}

	err = userlib.DSVerify(publicVerificationKey, storedUserData.EncryptedUser, storedUserData.SignedEncryptedUser)
	if err != nil {
		return nil, errors.New("encryption of the serialized user struct has been tampered with")
	}

	passwordBytes, err := json.Marshal(password)
	if err != nil {
		return nil, err
	}
	passwordHash := userlib.Argon2Key(passwordBytes, usernameBytes, 16)

	decryptedUser := userlib.SymDec(passwordHash, storedUserData.EncryptedUser)

	hashedDecryptedUser := userlib.Argon2Key(decryptedUser, []byte("fixedSaltForPasswordVerification"), 16)
	if !userlib.HMACEqual(hashedDecryptedUser, storedUserData.HashedSerializedUser) {
		return nil, errors.New("incorrect password")
	}

	var userdata User
	err = json.Unmarshal(decryptedUser, &userdata)
	if err != nil {
		return nil, err
	}

	newUserdata := User{
		Username:              userdata.Username,
		Password:              userdata.Password,
		PasswordHash:          userdata.PasswordHash,
		PublicKey:             userdata.PublicKey,
		PrivateKey:            userdata.PrivateKey,
		PublicVerificationKey: userdata.PublicVerificationKey,
		PrivateSignKey:        userdata.PrivateSignKey,
		Namespace:             userdata.Namespace,
		ShareStructs:          userdata.ShareStructs,
	}

	return &newUserdata, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	//if err != nil {
	//	return err
	//}
	//contentBytes, err := json.Marshal(content)
	//if err != nil {
	//	return err
	//}
	//userlib.DatastoreSet(storageKey, contentBytes)
	//return

	mostRecentUserdata, err := GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return errors.New("Could not retrieve most up to date user from Datastore")
	}

	userdata.Namespace = mostRecentUserdata.Namespace
	userdata.ShareStructs = mostRecentUserdata.ShareStructs

	usernameBytes, err := json.Marshal(userdata.Username)
	if err != nil {
		return err
	}
	usernameHash := userlib.Hash(usernameBytes)
	usernameUUID, err := uuid.FromBytes(usernameHash[:16])
	if err != nil {
		return err
	}

	var fileEncKey []byte
	var fileHMACKey []byte
	var nodeHMACKey []byte
	if fileMetadata, exists := userdata.Namespace[filename]; exists {
		fileEncKey = fileMetadata.SymKey
		fileHMACKey = fileMetadata.HMACKeyFiles
		nodeHMACKey = fileMetadata.HMACKeyNodes
	} else if shareStructsValue, exists := userdata.ShareStructs[filename]; exists {
		fileEncKey = shareStructsValue.FileSymKey
		fileHMACKey = shareStructsValue.HMACKeyFiles
		nodeHMACKey = shareStructsValue.HMACKeyNode
	} else {
		fileEncKey = userlib.RandomBytes(16)
		fileHMACKey = userlib.RandomBytes(16)
		nodeHMACKey = userlib.RandomBytes(16)
	}

	fileData := File{
		Content: content,
		Owner:   usernameUUID,
	}

	fileDataBytes, err := json.Marshal(fileData)
	if err != nil {
		return err
	}

	fileIV := userlib.RandomBytes(16)
	encryptedFileData := userlib.SymEnc(fileEncKey, fileIV, fileDataBytes)

	encryptedFileHMACValue, err := userlib.HMACEval(fileHMACKey, encryptedFileData)
	if err != nil {
		return err
	}

	fileDataToStore := StoredFileData{
		EncryptedFile:     encryptedFileData,
		EncryptedFileHMAC: encryptedFileHMACValue,
	}
	fileDataToStoreBytes, err := json.Marshal(fileDataToStore)
	if err != nil {
		return err
	}
	fileUUID := uuid.New()
	userlib.DatastoreSet(fileUUID, fileDataToStoreBytes)

	nodeUUIDPair := NodeUUIDPair{
		FileUUID:     fileUUID,
		NextNodeUUID: uuid.Nil,
	}
	nodeUUIDPairBytes, err := json.Marshal(nodeUUIDPair)
	if err != nil {
		return err
	}

	nodeUUIDPairHMAC, err := userlib.HMACEval(nodeHMACKey, nodeUUIDPairBytes)
	if err != nil {
		return err
	}

	node := LinkedListNode{
		SerializedUUIDPair:     nodeUUIDPairBytes,
		SerializedUUIDPairHMAC: nodeUUIDPairHMAC,
	}
	nodeBytes, err := json.Marshal(node)
	if err != nil {
		return err
	}

	// TODO: a user with which the file is shared should be able to store (i.e. overwrite) a file that was shared with them
	// when this is done, the symkey and HMAC keys used should be available to all users with which the file is shared
	// this is why having a single source of truth in the owner share struct was good – when retrieving or storing, it was used...
	if fileMetadata, exists := userdata.Namespace[filename]; exists {
		userlib.DatastoreSet(fileMetadata.UUIDStart, nodeBytes)
	} else if shareStructsValue, exists := userdata.ShareStructs[filename]; exists {
		shareDataPtr, err := loadShareStruct(shareStructsValue.ShareStructPairUUID, shareStructsValue)
		if err != nil {
			return err
		}
		shareData := *shareDataPtr
		userlib.DatastoreSet(shareData.FileUUID, nodeBytes)
	} else {
		nodeUUID := uuid.New()
		userlib.DatastoreSet(nodeUUID, nodeBytes)

		fileMetadata := FileMetadataNS{
			UUIDStart:    nodeUUID,
			SymKey:       fileEncKey,
			HMACKeyFiles: fileHMACKey,
			HMACKeyNodes: nodeHMACKey,
		}
		userdata.Namespace[filename] = fileMetadata

		serializedUser, err := json.Marshal(userdata)
		if err != nil {
			return err
		}

		iv := userlib.RandomBytes(16)
		encryptedUser := userlib.SymEnc(userdata.PasswordHash, iv, serializedUser)

		signedEncryptedUser, err := userlib.DSSign(userdata.PrivateSignKey, encryptedUser)
		if err != nil {
			return err
		}

		hashedSerializedUser := userlib.Argon2Key(serializedUser, []byte("fixedSaltForPasswordVerification"), 16)

		userdataToStore := StoredUserData{
			EncryptedUser:        encryptedUser,
			SignedEncryptedUser:  signedEncryptedUser,
			Username:             userdata.Username,
			HashedSerializedUser: hashedSerializedUser,
		}

		serializedUserdataToStore, err := json.Marshal(userdataToStore)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(usernameUUID, serializedUserdataToStore)

		// store flattened fileMetadataNS
		fileMetadataBytes, err := json.Marshal(fileMetadata)
		if err != nil {
			return err
		}

		hybridKey := userlib.RandomBytes(16)
		encryptedFileMetadata := userlib.SymEnc(hybridKey, userlib.RandomBytes(16), fileMetadataBytes)

		encryptedHybridKey, err := userlib.PKEEnc(userdata.PublicKey, hybridKey)
		if err != nil {
			return err
		}

		flattenedNamespaceHybridPair := FlattenedNamespaceHybridPair{
			EncryptedFileMetadata: encryptedFileMetadata,
			EncryptedSymKey:       encryptedHybridKey,
		}

		flattenedNamespaceHybridPairBytes, err := json.Marshal(flattenedNamespaceHybridPair)
		if err != nil {
			return err
		}

		signedEncryptedFileMetadata, err := userlib.DSSign(userdata.PrivateSignKey, flattenedNamespaceHybridPairBytes)

		flattenedNamespaceEntry := FlattenedNamespaceEntry{
			EncryptedFileMetadataNS:       flattenedNamespaceHybridPairBytes,
			SignedEncryptedFileMetadataNS: signedEncryptedFileMetadata,
		}

		flattenedNamespaceEntryBytes, err := json.Marshal(flattenedNamespaceEntry)
		if err != nil {
			return err
		}

		flattenedNSKeyBytes, err := json.Marshal(userdata.Username + "ns" + filename)
		if err != nil {
			return err
		}
		flattenedNSHash := userlib.Hash(flattenedNSKeyBytes)
		flattenedNSUUID, err := uuid.FromBytes(flattenedNSHash[:16])
		if err != nil {
			return err
		}

		userlib.DatastoreSet(flattenedNSUUID, flattenedNamespaceEntryBytes)
	}

	return nil
}

// required changes:
// for all functions other than the appendToFile function, load the user struct from datastore to make sure the most recent user is being used
// will probably need to store password in the user struct as well – just store as a field in plaintext, since the user struct is encrypted

// need to address the following problem with append: since we don't pull the most updated user struct (not bandwidth efficient), the current
// implementation doesn't work for the following: e.g. boblaptop stores a file a.txt, bobphone tries to append to a.txt.

// If user is the owner: Hash username+ns+filename and convert to UUID; at this UUID store (start_uuid, signature of start_uuid)
// If user is a shared user: Hash username+sh+filename and convert to UUID; at this UUID store (start_uuid, signature of start_uuid)

func (userdata *User) AppendToFile(filename string, content []byte) error {
	usernameBytes, err := json.Marshal(userdata.Username)
	if err != nil {
		return err
	}
	usernameHash := userlib.Hash(usernameBytes)
	usernameUUID, err := uuid.FromBytes(usernameHash[:16])
	if err != nil {
		return err
	}

	fileMetadataNSPtr, flattenedFileMetadataExists, err := getFlattenedNSEntry(userdata, filename)
	if err != nil {
		return err
	}

	var shareStructsValuePtr *ShareStructsValue
	var flattenedShareStructsValueExists bool
	if !flattenedFileMetadataExists {
		shareStructsValuePtr, flattenedShareStructsValueExists, err = getFlattenedShareStructsEntry(userdata, filename)
		if err != nil {
			return err
		}
	}

	var fileMetadata FileMetadataNS
	if flattenedFileMetadataExists {
		fileMetadata = *fileMetadataNSPtr
	} else if flattenedShareStructsValueExists {
		shareStructsValue := *shareStructsValuePtr
		shareDataPtr, err := loadShareStruct(shareStructsValue.ShareStructPairUUID, shareStructsValue)
		if err != nil {
			return err
		}
		shareData := *shareDataPtr
		fileMetadata = FileMetadataNS{
			UUIDStart:    shareData.FileUUID,
			SymKey:       shareStructsValue.FileSymKey,
			HMACKeyFiles: shareStructsValue.HMACKeyFiles,
			HMACKeyNodes: shareStructsValue.HMACKeyNode,
		}
	} else if _, ok := userdata.Namespace[filename]; ok {
		fileMetadata = userdata.Namespace[filename]
	} else if shareStructsValue, ok := userdata.ShareStructs[filename]; ok {
		// since share struct contains ShareStructsSet, this will not be bandwidth efficient
		// need to store ShareStructsSet separately on datastore (use existing keys for the share struct)
		// this way can replace the ShareStructsSet map with a UUID (16 bytes)
		shareDataPtr, err := loadShareStruct(shareStructsValue.ShareStructPairUUID, shareStructsValue)
		if err != nil {
			return err
		}
		shareData := *shareDataPtr
		fileMetadata = FileMetadataNS{
			UUIDStart:    shareData.FileUUID,
			SymKey:       shareStructsValue.FileSymKey,
			HMACKeyFiles: shareStructsValue.HMACKeyFiles,
			HMACKeyNodes: shareStructsValue.HMACKeyNode,
		}
	} else {
		return errors.New("filename does not exist in user's namespace")
	}

	newFileChunk := File{
		Content: content,
		Owner:   usernameUUID,
	}

	serializedFileChunk, err := json.Marshal(newFileChunk)
	if err != nil {
		return err
	}

	encryptedFileChunk := userlib.SymEnc(fileMetadata.SymKey, userlib.RandomBytes(16), serializedFileChunk)

	encryptedFileChunkHMACValue, err := userlib.HMACEval(fileMetadata.HMACKeyFiles, encryptedFileChunk)
	if err != nil {
		return err
	}

	fileChunkDataToStore := StoredFileData{
		EncryptedFile:     encryptedFileChunk,
		EncryptedFileHMAC: encryptedFileChunkHMACValue,
	}
	fileChunkDataToStoreBytes, err := json.Marshal(fileChunkDataToStore)
	if err != nil {
		return err
	}
	fileUUID := uuid.New()
	userlib.DatastoreSet(fileUUID, fileChunkDataToStoreBytes)

	storedNodeDataBytes, ok := userlib.DatastoreGet(fileMetadata.UUIDStart)
	if !ok {
		return errors.New("node not found in datastore")
	}

	var currNode LinkedListNode
	err = json.Unmarshal(storedNodeDataBytes, &currNode)

	expectedNodeHMAC, err := userlib.HMACEval(fileMetadata.HMACKeyNodes, currNode.SerializedUUIDPair)
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(expectedNodeHMAC, currNode.SerializedUUIDPairHMAC) {
		return errors.New("HMAC verification failed for the node")
	}

	newUUIDForCurrNode := uuid.New()
	userlib.DatastoreSet(newUUIDForCurrNode, storedNodeDataBytes)

	nodeUUIDPair := NodeUUIDPair{
		FileUUID:     fileUUID,
		NextNodeUUID: newUUIDForCurrNode,
	}
	nodeUUIDPairBytes, err := json.Marshal(nodeUUIDPair)
	if err != nil {
		return err
	}

	nodeUUIDPairHMAC, err := userlib.HMACEval(fileMetadata.HMACKeyNodes, nodeUUIDPairBytes)
	if err != nil {
		return err
	}

	newNode := LinkedListNode{
		SerializedUUIDPair:     nodeUUIDPairBytes,
		SerializedUUIDPairHMAC: nodeUUIDPairHMAC,
	}
	newNodeBytes, err := json.Marshal(newNode)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileMetadata.UUIDStart, newNodeBytes)

	return nil
}

func getFlattenedNSEntry(userdata *User, filename string) (*FileMetadataNS, bool, error) {
	flattenedNSKeyBytes, err := json.Marshal(userdata.Username + "ns" + filename)
	if err != nil {
		return nil, false, err
	}
	flattenedNSHash := userlib.Hash(flattenedNSKeyBytes)
	flattenedNSUUID, err := uuid.FromBytes(flattenedNSHash[:16])
	if err != nil {
		return nil, false, err
	}

	flattenedNamespaceEntryBytes, ok := userlib.DatastoreGet(flattenedNSUUID)
	if ok {
		var flattenedNamespaceEntry FlattenedNamespaceEntry
		err = json.Unmarshal(flattenedNamespaceEntryBytes, &flattenedNamespaceEntry)
		if err != nil {
			return nil, false, err
		}

		err = userlib.DSVerify(userdata.PublicVerificationKey, flattenedNamespaceEntry.EncryptedFileMetadataNS,
			flattenedNamespaceEntry.SignedEncryptedFileMetadataNS)
		if err != nil {
			return nil, false, err
		}

		var flattenedNamespaceHybridPair FlattenedNamespaceHybridPair
		err = json.Unmarshal(flattenedNamespaceEntry.EncryptedFileMetadataNS, &flattenedNamespaceHybridPair)

		hybridKey, err := userlib.PKEDec(userdata.PrivateKey, flattenedNamespaceHybridPair.EncryptedSymKey)

		namespaceEntryBytes := userlib.SymDec(hybridKey, flattenedNamespaceHybridPair.EncryptedFileMetadata)

		var fileMetadataNS FileMetadataNS
		err = json.Unmarshal(namespaceEntryBytes, &fileMetadataNS)
		if err != nil {
			return nil, false, err
		}

		return &fileMetadataNS, ok, nil
	}

	return nil, ok, nil
}

func getFlattenedShareStructsEntry(userdata *User, filename string) (*ShareStructsValue, bool, error) {
	flattenedShareStructsKeyBytes, err := json.Marshal(userdata.Username + "sh" + filename)
	if err != nil {
		return nil, false, err
	}
	flattenedShareStructsHash := userlib.Hash(flattenedShareStructsKeyBytes)
	flattenedShareStructsUUID, err := uuid.FromBytes(flattenedShareStructsHash[:16])
	if err != nil {
		return nil, false, err
	}

	flattenedShareStructsEntryBytes, ok := userlib.DatastoreGet(flattenedShareStructsUUID)
	if ok {
		var flattenedShareStructsEntry FlattenedShareStructsEntry
		json.Unmarshal(flattenedShareStructsEntryBytes, &flattenedShareStructsEntry)

		err = userlib.DSVerify(userdata.PublicVerificationKey, flattenedShareStructsEntry.EncryptedShareStructsValue,
			flattenedShareStructsEntry.SignedEncryptedShareStructsValue)
		if err != nil {
			return nil, false, err
		}

		var flattenedShareStructsHybridPair FlattenedShareStructsHybridPair
		err = json.Unmarshal(flattenedShareStructsEntry.EncryptedShareStructsValue, &flattenedShareStructsHybridPair)

		hybridKey, err := userlib.PKEDec(userdata.PrivateKey, flattenedShareStructsHybridPair.EncryptedSymKey)

		shareStructsEntryBytes := userlib.SymDec(hybridKey, flattenedShareStructsHybridPair.EncryptedShareStructsValue)

		var shareStructsValue ShareStructsValue
		err = json.Unmarshal(shareStructsEntryBytes, &shareStructsValue)
		if err != nil {
			return nil, false, err
		}

		return &shareStructsValue, ok, nil
	}

	return nil, ok, nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	//storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	//if err != nil {
	//	return nil, err
	//}
	//dataJSON, ok := userlib.DatastoreGet(storageKey)
	//if !ok {
	//	return nil, errors.New(strings.ToTitle("file not found"))
	//}
	//err = json.Unmarshal(dataJSON, &content)
	//return content, err

	mostRecentUserdata, err := GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return nil, errors.New("Could not retrieve most up to date user from Datastore")
	}

	userdata.Namespace = mostRecentUserdata.Namespace
	userdata.ShareStructs = mostRecentUserdata.ShareStructs

	var fileMetadata FileMetadataNS
	if _, exists := userdata.Namespace[filename]; exists {
		fileMetadata = userdata.Namespace[filename]
	} else if _, exists := userdata.ShareStructs[filename]; exists {
		shareStructsValue := userdata.ShareStructs[filename]
		shareDataPtr, err := loadShareStruct(shareStructsValue.ShareStructPairUUID, shareStructsValue)
		if err != nil {
			return nil, err
		}
		shareData := *shareDataPtr
		fileMetadata = FileMetadataNS{
			UUIDStart:    shareData.FileUUID,
			SymKey:       shareStructsValue.FileSymKey,
			HMACKeyFiles: shareStructsValue.HMACKeyFiles,
			HMACKeyNodes: shareStructsValue.HMACKeyNode,
		}
	} else {
		return nil, errors.New("filename doesn't exist for the user")
	}

	currentUUID := fileMetadata.UUIDStart
	for {
		storedNodeDataBytes, ok := userlib.DatastoreGet(currentUUID)
		if !ok {
			return nil, errors.New("node not found in datastore")
		}

		var node LinkedListNode
		err = json.Unmarshal(storedNodeDataBytes, &node)

		expectedNodeHMAC, err := userlib.HMACEval(fileMetadata.HMACKeyNodes, node.SerializedUUIDPair)
		if err != nil {
			return nil, err
		}
		if !userlib.HMACEqual(expectedNodeHMAC, node.SerializedUUIDPairHMAC) {
			return nil, errors.New("HMAC verification failed for the node")
		}

		var nodeUUIDPair NodeUUIDPair
		err = json.Unmarshal(node.SerializedUUIDPair, &nodeUUIDPair)

		storedFileDataBytes, ok := userlib.DatastoreGet(nodeUUIDPair.FileUUID)
		var storedFileData StoredFileData
		err = json.Unmarshal(storedFileDataBytes, &storedFileData)

		expectedFileHMAC, err := userlib.HMACEval(fileMetadata.HMACKeyFiles, storedFileData.EncryptedFile)
		if err != nil {
			return nil, err
		}
		if !userlib.HMACEqual(expectedFileHMAC, storedFileData.EncryptedFileHMAC) {
			return nil, errors.New("HMAC verification failed for the file")
		}

		fileDataBytes := userlib.SymDec(fileMetadata.SymKey, storedFileData.EncryptedFile)
		var fileData File
		err = json.Unmarshal(fileDataBytes, &fileData)
		if err != nil {
			return nil, err
		}

		content = append(fileData.Content, content...)

		if nodeUUIDPair.NextNodeUUID == uuid.Nil {
			break
		}
		currentUUID = nodeUUIDPair.NextNodeUUID
	}

	return content, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {

	mostRecentUserdata, err := GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return uuid.Nil, errors.New("Could not retrieve most up to date user from Datastore")
	}

	userdata.Namespace = mostRecentUserdata.Namespace
	userdata.ShareStructs = mostRecentUserdata.ShareStructs

	usernameBytes, err := json.Marshal(userdata.Username)
	if err != nil {
		return uuid.Nil, err
	}
	usernameHash := userlib.Hash(usernameBytes)
	usernameUUID, err := uuid.FromBytes(usernameHash[:16])
	if err != nil {
		return uuid.Nil, err
	}

	recipientPK, ok := userlib.KeystoreGet(recipientUsername + "PK")
	if !ok {
		return uuid.Nil, errors.New("recipientUsername doesn't exist")
	}

	isOwner := false
	isShared := false
	if _, exists := userdata.Namespace[filename]; exists {
		isOwner = true
	}
	if _, exists := userdata.ShareStructs[filename]; exists {
		isShared = true
	}
	if !(isOwner || isShared) {
		return uuid.Nil, errors.New("user does not have file with filename")
	}

	var shareData Share
	var shareUUID uuid.UUID
	var shareStructsValue ShareStructsValue
	if (isOwner && isShared) || isShared {
		shareStructsValue = userdata.ShareStructs[filename]
		shareUUID = shareStructsValue.ShareStructPairUUID
		storedShareDataBytes, ok := userlib.DatastoreGet(shareStructsValue.ShareStructPairUUID)
		if !ok {
			return uuid.Nil, errors.New("User doesn't have share data")
		}

		var storedShareData StoredShareData
		err := json.Unmarshal(storedShareDataBytes, &storedShareData)
		if err != nil {
			return uuid.Nil, err
		}

		expectedShareHMAC, err := userlib.HMACEval(shareStructsValue.HMACKey, storedShareData.EncryptedShareStruct)
		if err != nil {
			return uuid.Nil, err
		}
		if !userlib.HMACEqual(expectedShareHMAC, storedShareData.EncryptedShareStructHMAC) {
			return uuid.Nil, errors.New("HMAC verification failed for the share struct")
		}

		shareDataBytes := userlib.SymDec(shareStructsValue.SymKey, storedShareData.EncryptedShareStruct)
		err = json.Unmarshal(shareDataBytes, &shareData)
		if err != nil {
			return uuid.Nil, err
		}
	} else {
		shareEncKey := userlib.RandomBytes(16)
		shareHMACKey := userlib.RandomBytes(16)

		shareStructSet := ShareStructSet{
			ShareStructSet: make(map[string]ShareStructSetValue),
		}

		shareStructSetBytes, err := json.Marshal(shareStructSet)
		if err != nil {
			return uuid.Nil, err
		}

		encryptedShareStructSet := userlib.SymEnc(shareEncKey, userlib.RandomBytes(16), shareStructSetBytes)
		encryptedShareStructSetHMAC, err := userlib.HMACEval(shareHMACKey, encryptedShareStructSet)
		if err != nil {
			return uuid.Nil, err
		}

		shareStructsSetUUID := ShareStructsSetUUID{
			EncryptedShareStructsSet:     encryptedShareStructSet,
			EncryptedShareStructsSetHMAC: encryptedShareStructSetHMAC,
		}

		shareStructsSetUUIDBytes, err := json.Marshal(shareStructsSetUUID)
		if err != nil {
			return uuid.Nil, err
		}

		shareStructsSetStoreUUID := uuid.New()
		userlib.DatastoreSet(shareStructsSetStoreUUID, shareStructsSetUUIDBytes)

		fileMetadata := userdata.Namespace[filename]
		shareData = Share{
			FileUUID:     fileMetadata.UUIDStart,
			SymKey:       fileMetadata.SymKey,
			HMACKeyFiles: fileMetadata.HMACKeyFiles,
			HMACKeyNode:  fileMetadata.HMACKeyNodes,
			ParentUUID:   uuid.Nil,
			// ShareStructsSet: make(map[string]ShareStructSetValue),
			ShareStructsSet: shareStructsSetStoreUUID,
		}

		shareDataBytes, err := json.Marshal(shareData)
		if err != nil {
			return uuid.Nil, err
		}

		encryptedShareData := userlib.SymEnc(shareEncKey, userlib.RandomBytes(16), shareDataBytes)

		encryptedShareHMACValue, err := userlib.HMACEval(shareHMACKey, encryptedShareData)
		if err != nil {
			return uuid.Nil, err
		}

		shareDataToStore := StoredShareData{
			EncryptedShareStruct:     encryptedShareData,
			EncryptedShareStructHMAC: encryptedShareHMACValue,
		}
		shareDataToStoreBytes, err := json.Marshal(shareDataToStore)
		if err != nil {
			return uuid.Nil, err
		}

		shareUUID = uuid.New()
		userlib.DatastoreSet(shareUUID, shareDataToStoreBytes)

		shareStructsValue = ShareStructsValue{
			ShareStructPairUUID: shareUUID,
			SymKey:              shareEncKey,
			HMACKey:             shareHMACKey,
			FileUUID:            fileMetadata.UUIDStart,
			FileSymKey:          fileMetadata.SymKey,
			HMACKeyFiles:        fileMetadata.HMACKeyFiles,
			HMACKeyNode:         fileMetadata.HMACKeyNodes,
		}
		userdata.ShareStructs[filename] = shareStructsValue

		serializedUser, err := json.Marshal(userdata)
		if err != nil {
			return uuid.Nil, err
		}

		iv := userlib.RandomBytes(16)
		encryptedUser := userlib.SymEnc(userdata.PasswordHash, iv, serializedUser)

		signedEncryptedUser, err := userlib.DSSign(userdata.PrivateSignKey, encryptedUser)
		if err != nil {
			return uuid.Nil, err
		}

		hashedSerializedUser := userlib.Argon2Key(serializedUser, []byte("fixedSaltForPasswordVerification"), 16)

		userdataToStore := StoredUserData{
			EncryptedUser:        encryptedUser,
			SignedEncryptedUser:  signedEncryptedUser,
			Username:             userdata.Username,
			HashedSerializedUser: hashedSerializedUser,
		}

		serializedUserdataToStore, err := json.Marshal(userdataToStore)
		if err != nil {
			return uuid.Nil, err
		}
		userlib.DatastoreSet(usernameUUID, serializedUserdataToStore)
	}

	// CHILD SHARE DATA NEED FILEUUID, SYMKEY, HMAC KEYS IN ORDER TO BE ABLE TO APPEND TO THE FILE WITH EFFICIENT BANDWIDTH!!!
	// THIS WOULD MEAN THAT THE FOR LOOPS UP TO THE OWNER SHARE STRUCT ARE NOT NEEDED

	childShareStructSet := ShareStructSet{
		ShareStructSet: make(map[string]ShareStructSetValue),
	}

	childShareStructSetBytes, err := json.Marshal(childShareStructSet)
	if err != nil {
		return uuid.Nil, err
	}

	childEncryptedShareStructSet := userlib.SymEnc(shareStructsValue.SymKey, userlib.RandomBytes(16), childShareStructSetBytes)
	childEncryptedShareStructSetHMAC, err := userlib.HMACEval(shareStructsValue.HMACKey, childEncryptedShareStructSet)
	if err != nil {
		return uuid.Nil, err
	}

	childShareStructsSetUUID := ShareStructsSetUUID{
		EncryptedShareStructsSet:     childEncryptedShareStructSet,
		EncryptedShareStructsSetHMAC: childEncryptedShareStructSetHMAC,
	}

	childShareStructsSetUUIDBytes, err := json.Marshal(childShareStructsSetUUID)
	if err != nil {
		return uuid.Nil, err
	}

	childShareStructsSetStoreUUID := uuid.New()
	userlib.DatastoreSet(childShareStructsSetStoreUUID, childShareStructsSetUUIDBytes)

	shareDataForInvite := Share{
		FileUUID:        shareData.FileUUID,
		SymKey:          shareStructsValue.FileSymKey,
		HMACKeyFiles:    shareStructsValue.HMACKeyFiles,
		HMACKeyNode:     shareStructsValue.HMACKeyNode,
		ParentUUID:      shareUUID,
		ShareStructsSet: childShareStructsSetStoreUUID,
	}

	shareDataForInviteBytes, err := json.Marshal(shareDataForInvite)
	if err != nil {
		return uuid.Nil, err
	}

	encryptedShareDataForInvite := userlib.SymEnc(shareStructsValue.SymKey, userlib.RandomBytes(16), shareDataForInviteBytes)
	encryptedShareDataForInviteHMAC, err := userlib.HMACEval(shareStructsValue.HMACKey, encryptedShareDataForInvite)
	if err != nil {
		return uuid.Nil, err
	}

	newShareDataToStore := StoredShareData{
		EncryptedShareStruct:     encryptedShareDataForInvite,
		EncryptedShareStructHMAC: encryptedShareDataForInviteHMAC,
	}
	newShareDataToStoreBytes, err := json.Marshal(newShareDataToStore)
	if err != nil {
		return uuid.Nil, err
	}
	newShareDataUUID := uuid.New()
	userlib.DatastoreSet(newShareDataUUID, newShareDataToStoreBytes)

	shareStructSetValue := ShareStructSetValue{
		Username:  recipientUsername,
		ChildUUID: newShareDataUUID,
	}

	shareStructsSetPtr, err := getShareStructSet(shareStructsValue, shareData)
	if err != nil {
		return uuid.Nil, err
	}
	shareStructsSet := *shareStructsSetPtr

	shareStructsSet.ShareStructSet[recipientUsername] = shareStructSetValue

	err = storeShareStructSet(shareStructsValue, shareData.ShareStructsSet, shareStructsSet)
	if err != nil {
		return uuid.Nil, err
	}

	invite := Invitation{
		Filename:            filename,
		Sender:              userdata.Username,
		Receiver:            recipientUsername,
		Revoked:             false,
		ShareStructPairUUID: newShareDataUUID,
		ShareStructsSymKey:  shareStructsValue.SymKey,
		ShareStructsHMACKey: shareStructsValue.HMACKey,
	}

	inviteBytes, err := json.Marshal(invite)
	if err != nil {
		return uuid.Nil, err
	}

	// use hybrid encryption -> encrypt the invitation struct with a RandomBytes(16) key, encrypt the symmetric key using the recipients's public key
	// send the symmetrically encrypted invitation struct and asymmetrically encrypted key
	invitationSymKey := userlib.RandomBytes(16)
	encryptedInviteBytes := userlib.SymEnc(invitationSymKey, userlib.RandomBytes(16), inviteBytes)
	encryptedInvitationSymKey, err := userlib.PKEEnc(recipientPK, invitationSymKey)
	if err != nil {
		return uuid.Nil, err
	}

	hybridPair := InvitationHybridPair{
		EncryptedInvitation: encryptedInviteBytes,
		EncryptedSymKey:     encryptedInvitationSymKey,
	}

	hybridPairBytes, err := json.Marshal(hybridPair)
	if err != nil {
		return uuid.Nil, err
	}

	hybridPairSign, err := userlib.DSSign(userdata.PrivateSignKey, hybridPairBytes)
	if err != nil {
		return uuid.Nil, err
	}

	inviteToStore := StoredInvitationData{
		InvitationHybridPair:       hybridPairBytes,
		SignedInvitationHybridPair: hybridPairSign,
	}

	inviteToStoreBytes, err := json.Marshal(inviteToStore)
	if err != nil {
		return uuid.Nil, err
	}

	inviteUUID := uuid.New()
	userlib.DatastoreSet(inviteUUID, inviteToStoreBytes)

	return inviteUUID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	mostRecentUserdata, err := GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return errors.New("Could not retrieve most up to date user from Datastore")
	}

	userdata.Namespace = mostRecentUserdata.Namespace
	userdata.ShareStructs = mostRecentUserdata.ShareStructs

	if _, exists := userdata.Namespace[filename]; exists {
		return errors.New("User already has the file (owner)")
	} else if _, exists := userdata.ShareStructs[filename]; exists {
		return errors.New("User already has the file (shared)")
	}

	storedInviteBytes, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("Invite doesn't exist")
	}

	var storedInvitationData StoredInvitationData
	err = json.Unmarshal(storedInviteBytes, &storedInvitationData)
	if err != nil {
		return err
	}

	senderVerifyKey, ok := userlib.KeystoreGet(senderUsername + "DS")
	if !ok {
		return errors.New("Sender doesn't have verify key in Keystore")
	}

	err = userlib.DSVerify(senderVerifyKey, storedInvitationData.InvitationHybridPair, storedInvitationData.SignedInvitationHybridPair)
	if err != nil {
		return err
	}

	var invitationHybridPair InvitationHybridPair
	err = json.Unmarshal(storedInvitationData.InvitationHybridPair, &invitationHybridPair)
	if err != nil {
		return err
	}

	symKey, err := userlib.PKEDec(userdata.PrivateKey, invitationHybridPair.EncryptedSymKey)
	if err != nil {
		return err
	}

	inviteBytes := userlib.SymDec(symKey, invitationHybridPair.EncryptedInvitation)

	var invite Invitation
	err = json.Unmarshal(inviteBytes, &invite)
	if err != nil {
		return err
	}

	if invite.Revoked {
		return errors.New("Invite has been revoked")
	}

	storedShareDataBytes, ok := userlib.DatastoreGet(invite.ShareStructPairUUID)
	if !ok {
		return errors.New("Share data not in datstore")
	}

	var storedShareData StoredShareData
	err = json.Unmarshal(storedShareDataBytes, &storedShareData)
	if err != nil {
		return err
	}

	storedShareDataHMAC, err := userlib.HMACEval(invite.ShareStructsHMACKey, storedShareData.EncryptedShareStruct)
	if err != nil {
		return err
	}
	ok = userlib.HMACEqual(storedShareDataHMAC, storedShareData.EncryptedShareStructHMAC)
	if !ok {
		return errors.New("HMAC verification failed for the store share data")
	}

	shareBytes := userlib.SymDec(invite.ShareStructsSymKey, storedShareData.EncryptedShareStruct)
	var share Share
	err = json.Unmarshal(shareBytes, &share)
	if err != nil {
		return err
	}

	shareStructsValue := ShareStructsValue{
		ShareStructPairUUID: invite.ShareStructPairUUID,
		SymKey:              invite.ShareStructsSymKey,
		HMACKey:             invite.ShareStructsHMACKey,
		FileUUID:            share.FileUUID,
		FileSymKey:          share.SymKey,
		HMACKeyFiles:        share.HMACKeyFiles,
		HMACKeyNode:         share.HMACKeyNode,
	}

	userdata.ShareStructs[filename] = shareStructsValue

	usernameBytes, err := json.Marshal(userdata.Username)
	if err != nil {
		return err
	}
	usernameHash := userlib.Hash(usernameBytes)
	usernameUUID, err := uuid.FromBytes(usernameHash[:16])
	if err != nil {
		return err
	}

	serializedUser, err := json.Marshal(userdata)
	if err != nil {
		return err
	}

	encryptedUser := userlib.SymEnc(userdata.PasswordHash, userlib.RandomBytes(16), serializedUser)

	signedEncryptedUser, err := userlib.DSSign(userdata.PrivateSignKey, encryptedUser)
	if err != nil {
		return err
	}

	hashedSerializedUser := userlib.Argon2Key(serializedUser, []byte("fixedSaltForPasswordVerification"), 16)

	userdataToStore := StoredUserData{
		EncryptedUser:        encryptedUser,
		SignedEncryptedUser:  signedEncryptedUser,
		Username:             userdata.Username,
		HashedSerializedUser: hashedSerializedUser,
	}

	serializedUserdataToStore, err := json.Marshal(userdataToStore)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(usernameUUID, serializedUserdataToStore)

	// store flattened shareStructsValue
	shareStructsValueBytes, err := json.Marshal(shareStructsValue)
	if err != nil {
		return err
	}

	hybridKey := userlib.RandomBytes(16)
	encryptedShareStructsValue := userlib.SymEnc(hybridKey, userlib.RandomBytes(16), shareStructsValueBytes)

	encryptedHybridKey, err := userlib.PKEEnc(userdata.PublicKey, hybridKey)
	if err != nil {
		return err
	}

	flattenedShareStructsHybridPair := FlattenedShareStructsHybridPair{
		EncryptedShareStructsValue: encryptedShareStructsValue,
		EncryptedSymKey:            encryptedHybridKey,
	}

	flattenedShareStructsHybridPairBytes, err := json.Marshal(flattenedShareStructsHybridPair)
	if err != nil {
		return err
	}

	signedEncryptedShareStructsValue, err := userlib.DSSign(userdata.PrivateSignKey, flattenedShareStructsHybridPairBytes)

	flattenedShareStructsEntry := FlattenedShareStructsEntry{
		EncryptedShareStructsValue:       flattenedShareStructsHybridPairBytes,
		SignedEncryptedShareStructsValue: signedEncryptedShareStructsValue,
	}

	flattenedShareStructsEntryBytes, err := json.Marshal(flattenedShareStructsEntry)
	if err != nil {
		return err
	}

	flattenedShareStructsKeyBytes, err := json.Marshal(userdata.Username + "sh" + filename)
	if err != nil {
		return err
	}
	flattenedShareStructsHash := userlib.Hash(flattenedShareStructsKeyBytes)
	flattenedShareStructsUUID, err := uuid.FromBytes(flattenedShareStructsHash[:16])
	if err != nil {
		return err
	}

	userlib.DatastoreSet(flattenedShareStructsUUID, flattenedShareStructsEntryBytes)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	mostRecentUserdata, err := GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return errors.New("Could not retrieve most up to date user from Datastore")
	}

	userdata.Namespace = mostRecentUserdata.Namespace
	userdata.ShareStructs = mostRecentUserdata.ShareStructs

	if _, exists := userdata.Namespace[filename]; !exists {
		return errors.New("User does not own the file")
	} else if _, exists := userdata.ShareStructs[filename]; !exists {
		return errors.New("User never shared the file")
	}

	shareStructsValue := userdata.ShareStructs[filename]
	shareDataPtr, err := loadShareStruct(shareStructsValue.ShareStructPairUUID, shareStructsValue)
	if err != nil {
		return errors.New("Could not load share struct")
	}
	shareData := *shareDataPtr

	// first get the actual ShareStructsSet, which is stored encrypted at the share.ShareStructsSet uuid
	shareStructSetPtr, err := getShareStructSet(shareStructsValue, shareData)
	if err != nil {
		return err
	}
	shareStructSet := *shareStructSetPtr

	if _, exists := shareStructSet.ShareStructSet[recipientUsername]; !exists {
		return errors.New("recipientUsername doesn't exist in the SharedStructsSet")
	}

	recipientShareUUID := shareStructSet.ShareStructSet[recipientUsername].ChildUUID
	userlib.DatastoreDelete(recipientShareUUID)

	delete(shareStructSet.ShareStructSet, recipientUsername)

	newShareStructsSetUUID := uuid.New()
	err = storeShareStructSet(shareStructsValue, newShareStructsSetUUID, shareStructSet)
	if err != nil {
		return err
	}
	shareData.ShareStructsSet = newShareStructsSetUUID
	// need to get the start node, delete it from its curr uuid, and store it at a new uuid
	// when going through the child share structs, update their FileUUIDs as well. Also need to change current code to always use the Share struct
	// instead of ShareStructValues of user struct (because if we update the share struct below and use the ShareStructValues map to get the FileUUID,
	// they will be out of sync).

	userlib.DatastoreDelete(shareStructsValue.ShareStructPairUUID)
	newOwnerShareUUID := uuid.New()
	shareStructsValue.ShareStructPairUUID = newOwnerShareUUID
	userdata.ShareStructs[filename] = shareStructsValue
	err = storeShareStruct(shareStructsValue, shareData, shareStructsValue.ShareStructPairUUID)
	if err != nil {
		return err
	}

	for _, childShareStructSetValue := range shareStructSet.ShareStructSet {
		storedShareDataBytes, ok := userlib.DatastoreGet(childShareStructSetValue.ChildUUID)
		if !ok {
			return errors.New("User doesn't have share data")
		}

		var storedShareData StoredShareData
		err := json.Unmarshal(storedShareDataBytes, &storedShareData)
		if err != nil {
			return err
		}

		expectedShareHMAC, err := userlib.HMACEval(shareStructsValue.HMACKey, storedShareData.EncryptedShareStruct)
		if err != nil {
			return err
		}
		if !userlib.HMACEqual(expectedShareHMAC, storedShareData.EncryptedShareStructHMAC) {
			return errors.New("HMAC verification failed for the share struct")
		}

		shareDataBytes := userlib.SymDec(shareStructsValue.SymKey, storedShareData.EncryptedShareStruct)
		var childShareData Share
		err = json.Unmarshal(shareDataBytes, &childShareData)
		if err != nil {
			return err
		}

		childShareData.ParentUUID = newOwnerShareUUID

		newShareDataBytes, err := json.Marshal(childShareData)
		if err != nil {
			return err
		}

		encryptedNewShareData := userlib.SymEnc(shareStructsValue.SymKey, userlib.RandomBytes(16), newShareDataBytes)

		encryptedNewShareHMACValue, err := userlib.HMACEval(shareStructsValue.HMACKey, encryptedNewShareData)
		if err != nil {
			return err
		}

		newShareDataToStore := StoredShareData{
			EncryptedShareStruct:     encryptedNewShareData,
			EncryptedShareStructHMAC: encryptedNewShareHMACValue,
		}
		newShareDataToStoreBytes, err := json.Marshal(newShareDataToStore)
		if err != nil {
			return err
		}

		userlib.DatastoreSet(childShareStructSetValue.ChildUUID, newShareDataToStoreBytes)
	}

	startNodeStructBytes, ok := userlib.DatastoreGet(shareData.FileUUID)
	if !ok {
		return errors.New("Start node doesn't exist in Datastore")
	}
	var statNodeStruct LinkedListNode
	err = json.Unmarshal(startNodeStructBytes, &statNodeStruct)
	if err != nil {
		return err
	}
	statNodeStructHMAC, err := userlib.HMACEval(shareStructsValue.HMACKeyNode, statNodeStruct.SerializedUUIDPair)
	if err != nil {
		return err
	}
	ok = userlib.HMACEqual(statNodeStructHMAC, statNodeStruct.SerializedUUIDPairHMAC)
	if !ok {
		return errors.New("HMAC verification failed")
	}

	userlib.DatastoreDelete(shareData.FileUUID)

	newFileUUID := uuid.New()

	userlib.DatastoreSet(newFileUUID, startNodeStructBytes)

	err = updateShareStructTree(shareStructsValue, shareData, newFileUUID, shareStructsValue.ShareStructPairUUID)
	if err != nil {
		return err
	}

	fileMetadataNS := userdata.Namespace[filename]
	fileMetadataNS.UUIDStart = newFileUUID
	userdata.Namespace[filename] = fileMetadataNS

	shareStructsValueOld := userdata.ShareStructs[filename]
	shareStructsValueOld.FileUUID = newFileUUID
	userdata.ShareStructs[filename] = shareStructsValueOld

	usernameBytes, err := json.Marshal(userdata.Username)
	if err != nil {
		return err
	}
	usernameHash := userlib.Hash(usernameBytes)
	usernameUUID, err := uuid.FromBytes(usernameHash[:16])
	if err != nil {
		return err
	}

	serializedUser, err := json.Marshal(userdata)
	if err != nil {
		return err
	}

	encryptedUser := userlib.SymEnc(userdata.PasswordHash, userlib.RandomBytes(16), serializedUser)

	signedEncryptedUser, err := userlib.DSSign(userdata.PrivateSignKey, encryptedUser)
	if err != nil {
		return err
	}

	hashedSerializedUser := userlib.Argon2Key(serializedUser, []byte("fixedSaltForPasswordVerification"), 16)

	userdataToStore := StoredUserData{
		EncryptedUser:        encryptedUser,
		SignedEncryptedUser:  signedEncryptedUser,
		Username:             userdata.Username,
		HashedSerializedUser: hashedSerializedUser,
	}

	serializedUserdataToStore, err := json.Marshal(userdataToStore)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(usernameUUID, serializedUserdataToStore)

	return nil
}

func loadShareStruct(shareStructPairUUID uuid.UUID, shareStructsValue ShareStructsValue) (*Share, error) {
	storedShareDataBytes, ok := userlib.DatastoreGet(shareStructPairUUID)
	if !ok {
		return nil, errors.New("User doesn't have share data")
	}

	var storedShareData StoredShareData
	err := json.Unmarshal(storedShareDataBytes, &storedShareData)
	if err != nil {
		return nil, err
	}

	expectedShareHMAC, err := userlib.HMACEval(shareStructsValue.HMACKey, storedShareData.EncryptedShareStruct)
	if err != nil {
		return nil, err
	}
	if !userlib.HMACEqual(expectedShareHMAC, storedShareData.EncryptedShareStructHMAC) {
		return nil, errors.New("HMAC verification failed for the share struct")
	}

	shareDataBytes := userlib.SymDec(shareStructsValue.SymKey, storedShareData.EncryptedShareStruct)
	var shareData Share
	err = json.Unmarshal(shareDataBytes, &shareData)
	if err != nil {
		return nil, err
	}

	return &shareData, nil
}

func storeShareStruct(shareStructsValue ShareStructsValue, shareData Share, storeUUID uuid.UUID) error {
	newShareDataBytes, err := json.Marshal(shareData)
	if err != nil {
		return err
	}

	encryptedNewShareData := userlib.SymEnc(shareStructsValue.SymKey, userlib.RandomBytes(16), newShareDataBytes)

	encryptedNewShareHMACValue, err := userlib.HMACEval(shareStructsValue.HMACKey, encryptedNewShareData)
	if err != nil {
		return err
	}

	newShareDataToStore := StoredShareData{
		EncryptedShareStruct:     encryptedNewShareData,
		EncryptedShareStructHMAC: encryptedNewShareHMACValue,
	}
	newShareDataToStoreBytes, err := json.Marshal(newShareDataToStore)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(storeUUID, newShareDataToStoreBytes)

	return nil
}

func updateShareStructTree(shareStructsValue ShareStructsValue, shareData Share,
	newFileUUID uuid.UUID, shareDataUUID uuid.UUID) error {

	shareData.FileUUID = newFileUUID
	storeShareStruct(shareStructsValue, shareData, shareDataUUID)

	shareStructSetPtr, err := getShareStructSet(shareStructsValue, shareData)
	if err != nil {
		return err
	}
	shareStructSet := *shareStructSetPtr

	for _, childShareStructSetValue := range shareStructSet.ShareStructSet {
		childShareDataPtr, err := loadShareStruct(childShareStructSetValue.ChildUUID, shareStructsValue)
		if err != nil {
			return err
		}
		err = updateShareStructTree(shareStructsValue, *childShareDataPtr, newFileUUID, childShareStructSetValue.ChildUUID)
		if err != nil {
			return err
		}
	}

	return nil
}

func getShareStructSet(shareStructsValue ShareStructsValue, shareData Share) (*ShareStructSet, error) {
	shareStructsSetUUIDBytes, ok := userlib.DatastoreGet(shareData.ShareStructsSet)
	if !ok {
		return nil, errors.New("shareStructsSetUUID doesn't exist in the Datastore")
	}
	var shareStructsSetUUID ShareStructsSetUUID
	json.Unmarshal(shareStructsSetUUIDBytes, &shareStructsSetUUID)

	shareStructsSetUUIDHMAC, err := userlib.HMACEval(shareStructsValue.HMACKey, shareStructsSetUUID.EncryptedShareStructsSet)
	if err != nil {
		return nil, errors.New("HMACEval errored")
	}

	ok = userlib.HMACEqual(shareStructsSetUUIDHMAC, shareStructsSetUUID.EncryptedShareStructsSetHMAC)
	if !ok {
		return nil, errors.New("HMAC verification failed on shareStructsSetUUID")
	}

	shareStructsSetBytes := userlib.SymDec(shareStructsValue.SymKey, shareStructsSetUUID.EncryptedShareStructsSet)
	var shareStructsSet ShareStructSet
	err = json.Unmarshal(shareStructsSetBytes, &shareStructsSet)
	if err != nil {
		return nil, errors.New("shareStructsSetBytes unmarshaling failed")
	}

	return &shareStructsSet, nil
}

func storeShareStructSet(shareStructsValue ShareStructsValue, storeUUID uuid.UUID, shareStructsSet ShareStructSet) error {
	newShareStructsSetBytes, err := json.Marshal(shareStructsSet)
	if err != nil {
		return errors.New("shareStructsSetBytes unmarshaling failed")
	}

	encryptedNewShareStructsSet := userlib.SymEnc(shareStructsValue.SymKey, userlib.RandomBytes(16), newShareStructsSetBytes)
	encryptedNewShareStructsSetHMAC, err := userlib.HMACEval(shareStructsValue.HMACKey, encryptedNewShareStructsSet)
	if err != nil {
		return errors.New("HMACEval errored")
	}

	newShareStructsSetUUID := ShareStructsSetUUID{
		EncryptedShareStructsSet:     encryptedNewShareStructsSet,
		EncryptedShareStructsSetHMAC: encryptedNewShareStructsSetHMAC,
	}

	newShareStructsSetUUIDBytes, err := json.Marshal(newShareStructsSetUUID)
	if err != nil {
		return errors.New("newShareStructsSetUUIDBytes unmarshaling failed")
	}

	userlib.DatastoreSet(storeUUID, newShareStructsSetUUIDBytes)

	return nil
}

func GetUserUUID(userdata *User, username string) (uuid.UUID, error) {
	usernameBytes, err := json.Marshal(userdata.Username)
	if err != nil {
		return uuid.Nil, err
	}
	usernameHash := userlib.Hash(usernameBytes)
	usernameUUID, err := uuid.FromBytes(usernameHash[:16])
	if err != nil {
		return uuid.Nil, err
	}

	return usernameUUID, nil
}
