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
	PasswordHash          []byte
	PublicKey             userlib.PKEEncKey
	PrivateKey            userlib.PKEDecKey
	PublicVerificationKey userlib.DSVerifyKey
	PrivateSignKey        userlib.DSSignKey
	Namespace             map[string]FileMetadataNS
	ShareStructs          map[string][]interface{}
}

type StoredUserData struct {
	EncryptedUser        []byte
	SignedEncryptedUser  []byte
	Username             string
	HashedSerializedUser []byte
}

type FileMetadataNS struct {
	UUIDStart    userlib.UUID
	SymKey       []byte
	HMACKeyFiles []byte
	HMACKeyNodes []byte
}

type File struct {
	Filename string
	Content  []byte
	Owner    userlib.UUID
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
	FileUUID     userlib.UUID
	NextNodeUUID *userlib.UUID
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	if username == "" {
		return nil, errors.New("username is empty")
	}
	var userdata User
	userdata.Username = username

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

	shareStructs := make(map[string][]interface{})
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

	usernameBytes, err := json.Marshal(userdata.Username)
	if err != nil {
		return err
	}
	usernameHash := userlib.Hash(usernameBytes)
	usernameUUID, err := uuid.FromBytes(usernameHash[:16])
	if err != nil {
		return err
	}

	fileData := File{
		Filename: filename,
		Content:  content,
		Owner:    usernameUUID,
	}

	fileDataBytes, err := json.Marshal(fileData)
	if err != nil {
		return err
	}

	fileEncKey := userlib.RandomBytes(16)
	fileIV := userlib.RandomBytes(16)
	encryptedFileData := userlib.SymEnc(fileEncKey, fileIV, fileDataBytes)

	fileHMACKey := userlib.RandomBytes(16)
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
		NextNodeUUID: nil,
	}
	nodeUUIDPairBytes, err := json.Marshal(nodeUUIDPair)
	if err != nil {
		return err
	}

	nodeHMACKey := userlib.RandomBytes(16)
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

	fileMetadata, exists := userdata.Namespace[filename]
	if !exists {
		nodeUUID := uuid.New()
		userlib.DatastoreSet(nodeUUID, nodeBytes)

		fileMetadata := FileMetadataNS{
			UUIDStart:    nodeUUID,
			SymKey:       fileEncKey,
			HMACKeyFiles: fileHMACKey,
			HMACKeyNodes: nodeHMACKey,
		}
		userdata.Namespace[filename] = fileMetadata
	} else {
		userlib.DatastoreSet(fileMetadata.UUIDStart, nodeBytes)
		fileMetadata.SymKey = fileEncKey
		fileMetadata.HMACKeyFiles = fileHMACKey
		fileMetadata.HMACKeyNodes = nodeHMACKey
	}

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

	return nil
}

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

	fileMetadata, ok := userdata.Namespace[filename]
	if !ok {
		return errors.New("filename does not exist in user's namespace")
	}

	newFileChunk := File{
		Filename: filename,
		Content:  content,
		Owner:    usernameUUID,
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
		NextNodeUUID: &newUUIDForCurrNode,
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

	fileMetadata, exists := userdata.Namespace[filename]
	if !exists {
		return nil, errors.New("filename doesn't exist in the user's namespace")
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

		if nodeUUIDPair.NextNodeUUID == nil {
			break
		}
		currentUUID = *nodeUUIDPair.NextNodeUUID
	}

	return content, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
