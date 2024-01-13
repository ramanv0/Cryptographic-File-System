package client

import (
	"encoding/json"

	"errors"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	_ "strconv"
)

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

func generateUsernameUUID(usernameBytes []byte) (uuid.UUID, error) {
	usernameHash := userlib.Hash(usernameBytes)
	return uuid.FromBytes(usernameHash[:16])
}

func generatePasswordHash(password string, usernameBytes []byte) ([]byte, error) {
	passwordBytes, err := json.Marshal(password)
	if err != nil {
		return nil, err
	}
	return userlib.Argon2Key(passwordBytes, usernameBytes, 16), nil
}

func storeUserData(userdata *User, usernameUUID uuid.UUID, password string) error {
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

func InitUser(username string, password string) (userdataptr *User, err error) {
	if username == "" {
		return nil, errors.New("username is empty")
	}

	userdata := User{Username: username, Password: password}

	usernameBytes, err := json.Marshal(username)
	if err != nil {
		return nil, err
	}
	usernameUUID, err := generateUsernameUUID(usernameBytes)
	if err != nil {
		return nil, err
	}

	_, exists := userlib.DatastoreGet(usernameUUID)
	if exists {
		return nil, errors.New("user already exists")
	}

	userdata.PasswordHash, err = generatePasswordHash(password, usernameBytes)
	if err != nil {
		return nil, err
	}

	if userdata.PublicKey, userdata.PrivateKey, err = userlib.PKEKeyGen(); err != nil {
		return nil, err
	}

	if userdata.PrivateSignKey, userdata.PublicVerificationKey, err = userlib.DSKeyGen(); err != nil {
		return nil, err
	}

	userdata.Namespace = make(map[string]FileMetadataNS)
	userdata.ShareStructs = make(map[string]ShareStructsValue)

	if err = storeUserData(&userdata, usernameUUID, password); err != nil {
		return nil, err
	}

	err = userlib.KeystoreSet(username+"PK", userdata.PublicKey)
	if err != nil {
		return nil, err
	}

	err = userlib.KeystoreSet(username+"DS", userdata.PublicVerificationKey)
	if err != nil {
		return nil, err
	}

	return &userdata, nil
}

func decryptAndVerifyUser(passwordHash []byte, storedUserData *StoredUserData) ([]byte, []byte, error) {
	decryptedUser := userlib.SymDec(passwordHash, storedUserData.EncryptedUser)
	hashedSerializedUser := userlib.Argon2Key(decryptedUser, []byte("fixedSaltForPasswordVerification"), 16)
	return decryptedUser, hashedSerializedUser, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	usernameBytes, err := json.Marshal(username)
	if err != nil {
		return nil, err
	}
	usernameUUID, err := generateUsernameUUID(usernameBytes)
	if err != nil {
		return nil, err
	}

	storedUserdataBytes, exists := userlib.DatastoreGet(usernameUUID)
	if !exists {
		return nil, errors.New("user doesn't exist")
	}

	var storedUserData StoredUserData
	if err = json.Unmarshal(storedUserdataBytes, &storedUserData); err != nil {
		return nil, err
	}

	publicVerificationKey, exists := userlib.KeystoreGet(username + "DS")
	if !exists {
		return nil, errors.New("verification key not found")
	}

	if err = userlib.DSVerify(publicVerificationKey, storedUserData.EncryptedUser, storedUserData.SignedEncryptedUser); err != nil {
		return nil, errors.New("encryption of the serialized user struct has been tampered with")
	}

	passwordHash, err := generatePasswordHash(password, usernameBytes)
	if err != nil {
		return nil, err
	}

	decryptedUser, hashedSerializedUser, err := decryptAndVerifyUser(passwordHash, &storedUserData)
	if err != nil {
		return nil, err
	}

	var userdata User
	if err = json.Unmarshal(decryptedUser, &userdata); err != nil {
		return nil, err
	}

	if !userlib.HMACEqual(hashedSerializedUser, storedUserData.HashedSerializedUser) {
		return nil, errors.New("incorrect password")
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

func encryptAndStoreFileData(fileData File, fileEncKey []byte, fileHMACKey []byte) (uuid.UUID, error) {
	fileDataBytes, err := json.Marshal(fileData)
	if err != nil {
		return uuid.Nil, err
	}

	fileIV := userlib.RandomBytes(16)
	encryptedFileData := userlib.SymEnc(fileEncKey, fileIV, fileDataBytes)

	encryptedFileHMACValue, err := userlib.HMACEval(fileHMACKey, encryptedFileData)
	if err != nil {
		return uuid.Nil, err
	}

	fileDataToStore := StoredFileData{
		EncryptedFile:     encryptedFileData,
		EncryptedFileHMAC: encryptedFileHMACValue,
	}
	fileDataToStoreBytes, err := json.Marshal(fileDataToStore)
	if err != nil {
		return uuid.Nil, err
	}

	fileUUID := uuid.New()
	userlib.DatastoreSet(fileUUID, fileDataToStoreBytes)
	return fileUUID, nil
}

func createLinkedListNode(nodeUUIDPair NodeUUIDPair, nodeHMACKey []byte) ([]byte, error) {
	nodeUUIDPairBytes, err := json.Marshal(nodeUUIDPair)
	if err != nil {
		return nil, err
	}

	nodeUUIDPairHMAC, err := userlib.HMACEval(nodeHMACKey, nodeUUIDPairBytes)
	if err != nil {
		return nil, err
	}

	node := LinkedListNode{
		SerializedUUIDPair:     nodeUUIDPairBytes,
		SerializedUUIDPairHMAC: nodeUUIDPairHMAC,
	}
	nodeBytes, err := json.Marshal(node)
	if err != nil {
		return nil, err
	}

	return nodeBytes, nil
}

func updateOrCreateFileMetadata(userdata *User, usernameUUID uuid.UUID, filename string, fileEncKey []byte, fileHMACKey []byte, nodeHMACKey []byte, nodeBytes []byte) (FileMetadataNS, error) {
	nodeUUID := uuid.New()
	userlib.DatastoreSet(nodeUUID, nodeBytes)

	fileMetadata := FileMetadataNS{
		UUIDStart:    nodeUUID,
		SymKey:       fileEncKey,
		HMACKeyFiles: fileHMACKey,
		HMACKeyNodes: nodeHMACKey,
	}
	userdata.Namespace[filename] = fileMetadata

	return fileMetadata, storeUserData(userdata, usernameUUID, userdata.Password)
}

func getFileKeys(userdata *User, filename string) (fileEncKey []byte, fileHMACKey []byte, nodeHMACKey []byte, err error) {
	if fileMetadata, exists := userdata.Namespace[filename]; exists {
		return fileMetadata.SymKey, fileMetadata.HMACKeyFiles, fileMetadata.HMACKeyNodes, nil
	} else if shareStructsValue, exists := userdata.ShareStructs[filename]; exists {
		return shareStructsValue.FileSymKey, shareStructsValue.HMACKeyFiles, shareStructsValue.HMACKeyNode, nil
	} else {
		return userlib.RandomBytes(16), userlib.RandomBytes(16), userlib.RandomBytes(16), nil
	}
}

func hybridEncrypt(data []byte, publicKey userlib.PKEEncKey) ([]byte, []byte, error) {
	hybridKey := userlib.RandomBytes(16)
	encryptedData := userlib.SymEnc(hybridKey, userlib.RandomBytes(16), data)

	encryptedHybridKey, err := userlib.PKEEnc(publicKey, hybridKey)
	if err != nil {
		return nil, nil, err
	}

	return encryptedData, encryptedHybridKey, nil
}

func generateDatastoreKey(username, namespace, filename string) (uuid.UUID, error) {
	keyBytes, err := json.Marshal(username + namespace + filename)
	if err != nil {
		return uuid.Nil, err
	}
	keyHash := userlib.Hash(keyBytes)
	return uuid.FromBytes(keyHash[:16])
}

func storeNewFileMetadata(userdata *User, filename string, fileMetadata FileMetadataNS) error {
	fileMetadataBytes, err := json.Marshal(fileMetadata)
	if err != nil {
		return err
	}

	encryptedFileMetadata, encryptedHybridKey, err := hybridEncrypt(fileMetadataBytes, userdata.PublicKey)
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
	if err != nil {
		return err
	}

	flattenedNamespaceEntry := FlattenedNamespaceEntry{
		EncryptedFileMetadataNS:       flattenedNamespaceHybridPairBytes,
		SignedEncryptedFileMetadataNS: signedEncryptedFileMetadata,
	}

	flattenedNamespaceEntryBytes, err := json.Marshal(flattenedNamespaceEntry)
	if err != nil {
		return err
	}

	datastoreKey, err := generateDatastoreKey(userdata.Username, "ns", filename)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(datastoreKey, flattenedNamespaceEntryBytes)
	return nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
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
	usernameUUID, err := generateUsernameUUID(usernameBytes)
	if err != nil {
		return err
	}

	fileEncKey, fileHMACKey, nodeHMACKey, err := getFileKeys(userdata, filename)
	if err != nil {
		return err
	}

	fileData := File{Content: content, Owner: usernameUUID}
	fileUUID, err := encryptAndStoreFileData(fileData, fileEncKey, fileHMACKey)
	if err != nil {
		return err
	}

	nodeUUIDPair := NodeUUIDPair{
		FileUUID:     fileUUID,
		NextNodeUUID: uuid.Nil,
	}
	nodeBytes, err := createLinkedListNode(nodeUUIDPair, nodeHMACKey)
	if err != nil {
		return err
	}

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
		fileMetadata, err = updateOrCreateFileMetadata(userdata, usernameUUID, filename, fileEncKey, fileHMACKey, nodeHMACKey, nodeBytes)
		if err != nil {
			return err
		}

		err = storeNewFileMetadata(userdata, filename, fileMetadata)
		if err != nil {
			return err
		}
	}

	return nil
}

func getFlattenedFileMetadata(userdata *User, filename string) (FileMetadataNS, error) {
	fileMetadataNSPtr, flattenedFileMetadataExists, err := getFlattenedNSEntry(userdata, filename)
	if err != nil {
		return FileMetadataNS{}, err
	}

	if flattenedFileMetadataExists {
		return *fileMetadataNSPtr, nil
	}

	shareStructsValuePtr, flattenedShareStructsValueExists, err := getFlattenedShareStructsEntry(userdata, filename)
	if err != nil {
		return FileMetadataNS{}, err
	}

	if flattenedShareStructsValueExists {
		shareStructsValue := *shareStructsValuePtr
		shareDataPtr, err := loadShareStruct(shareStructsValue.ShareStructPairUUID, shareStructsValue)
		if err != nil {
			return FileMetadataNS{}, err
		}
		return createFileMetadataFromShareData(*shareDataPtr, shareStructsValue), nil
	} else if _, ok := userdata.Namespace[filename]; ok {
		return userdata.Namespace[filename], nil
	} else if shareStructsValue, ok := userdata.ShareStructs[filename]; ok {
		shareDataPtr, err := loadShareStruct(shareStructsValue.ShareStructPairUUID, shareStructsValue)
		if err != nil {
			return FileMetadataNS{}, err
		}
		return createFileMetadataFromShareData(*shareDataPtr, shareStructsValue), nil
	} else {
		return FileMetadataNS{}, errors.New("filename does not exist in user's namespace")
	}
}

func createFileMetadataFromShareData(shareData Share, shareStructsValue ShareStructsValue) FileMetadataNS {
	return FileMetadataNS{
		UUIDStart:    shareData.FileUUID,
		SymKey:       shareStructsValue.FileSymKey,
		HMACKeyFiles: shareStructsValue.HMACKeyFiles,
		HMACKeyNodes: shareStructsValue.HMACKeyNode,
	}
}

func encryptAndStoreFileChunk(content []byte, fileMetadata FileMetadataNS, ownerUUID uuid.UUID) (uuid.UUID, error) {
	newFileChunk := File{Content: content, Owner: ownerUUID}
	serializedFileChunk, err := json.Marshal(newFileChunk)
	if err != nil {
		return uuid.Nil, err
	}

	encryptedFileChunk := userlib.SymEnc(fileMetadata.SymKey, userlib.RandomBytes(16), serializedFileChunk)

	encryptedFileChunkHMACValue, err := userlib.HMACEval(fileMetadata.HMACKeyFiles, encryptedFileChunk)
	if err != nil {
		return uuid.Nil, err
	}

	fileChunkDataToStore := StoredFileData{
		EncryptedFile:     encryptedFileChunk,
		EncryptedFileHMAC: encryptedFileChunkHMACValue,
	}
	fileChunkDataToStoreBytes, err := json.Marshal(fileChunkDataToStore)
	if err != nil {
		return uuid.Nil, err
	}
	fileUUID := uuid.New()
	userlib.DatastoreSet(fileUUID, fileChunkDataToStoreBytes)

	return fileUUID, nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	usernameBytes, err := json.Marshal(userdata.Username)
	if err != nil {
		return err
	}
	usernameUUID, err := generateUsernameUUID(usernameBytes)
	if err != nil {
		return err
	}

	fileMetadata, err := getFlattenedFileMetadata(userdata, filename)
	if err != nil {
		return err
	}

	fileUUID, err := encryptAndStoreFileChunk(content, fileMetadata, usernameUUID)
	if err != nil {
		return err
	}

	storedNodeDataBytes, ok := userlib.DatastoreGet(fileMetadata.UUIDStart)
	if !ok {
		return errors.New("node not found in datastore")
	}

	var currNode LinkedListNode
	err = json.Unmarshal(storedNodeDataBytes, &currNode)
	if err != nil {
		return err
	}

	expectedNodeHMAC, err := userlib.HMACEval(fileMetadata.HMACKeyNodes, currNode.SerializedUUIDPair)
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(expectedNodeHMAC, currNode.SerializedUUIDPairHMAC) {
		return errors.New("HMAC verification failed for the node")
	}

	newUUIDForCurrNode := uuid.New()
	userlib.DatastoreSet(newUUIDForCurrNode, storedNodeDataBytes)

	nodeUUIDPair := NodeUUIDPair{FileUUID: fileUUID, NextNodeUUID: newUUIDForCurrNode}
	newNodeBytes, err := createLinkedListNode(nodeUUIDPair, fileMetadata.HMACKeyNodes)
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

func retrieveAndVerifyNode(currentUUID uuid.UUID, hmacKey []byte) (NodeUUIDPair, error) {
	storedNodeDataBytes, ok := userlib.DatastoreGet(currentUUID)
	if !ok {
		return NodeUUIDPair{}, errors.New("node not found in datastore")
	}

	var node LinkedListNode
	err := json.Unmarshal(storedNodeDataBytes, &node)
	if err != nil {
		return NodeUUIDPair{}, err
	}

	expectedNodeHMAC, err := userlib.HMACEval(hmacKey, node.SerializedUUIDPair)
	if err != nil {
		return NodeUUIDPair{}, err
	}
	if !userlib.HMACEqual(expectedNodeHMAC, node.SerializedUUIDPairHMAC) {
		return NodeUUIDPair{}, errors.New("HMAC verification failed for the node")
	}

	var nodeUUIDPair NodeUUIDPair
	err = json.Unmarshal(node.SerializedUUIDPair, &nodeUUIDPair)
	if err != nil {
		return NodeUUIDPair{}, err
	}

	return nodeUUIDPair, nil
}

func retrieveDecryptVerifyFileData(fileUUID uuid.UUID, fileMetadata FileMetadataNS) (File, error) {
	storedFileDataBytes, ok := userlib.DatastoreGet(fileUUID)
	if !ok {
		return File{}, errors.New("file data not found in datastore")
	}

	var storedFileData StoredFileData
	err := json.Unmarshal(storedFileDataBytes, &storedFileData)
	if err != nil {
		return File{}, err
	}

	expectedFileHMAC, err := userlib.HMACEval(fileMetadata.HMACKeyFiles, storedFileData.EncryptedFile)
	if err != nil {
		return File{}, err
	}
	if !userlib.HMACEqual(expectedFileHMAC, storedFileData.EncryptedFileHMAC) {
		return File{}, errors.New("HMAC verification failed for the file")
	}

	fileDataBytes := userlib.SymDec(fileMetadata.SymKey, storedFileData.EncryptedFile)
	var fileData File
	err = json.Unmarshal(fileDataBytes, &fileData)
	if err != nil {
		return File{}, err
	}

	return fileData, nil
}

func getFileMetadata(userdata *User, filename string) (FileMetadataNS, error) {
	if _, ok := userdata.Namespace[filename]; ok {
		return userdata.Namespace[filename], nil
	} else if shareStructsValue, ok := userdata.ShareStructs[filename]; ok {
		shareDataPtr, err := loadShareStruct(shareStructsValue.ShareStructPairUUID, shareStructsValue)
		if err != nil {
			return FileMetadataNS{}, err
		}
		return createFileMetadataFromShareData(*shareDataPtr, shareStructsValue), nil
	} else {
		return FileMetadataNS{}, errors.New("filename doesn't exist for the user")
	}
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	mostRecentUserdata, err := GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return nil, err
	}

	userdata.Namespace = mostRecentUserdata.Namespace
	userdata.ShareStructs = mostRecentUserdata.ShareStructs

	fileMetadata, err := getFileMetadata(userdata, filename)
	if err != nil {
		return nil, err
	}

	currentUUID := fileMetadata.UUIDStart
	for {
		nodeUUIDPair, err := retrieveAndVerifyNode(currentUUID, fileMetadata.HMACKeyNodes)
		if err != nil {
			return nil, err
		}

		fileData, err := retrieveDecryptVerifyFileData(nodeUUIDPair.FileUUID, fileMetadata)
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

func checkFileOwnership(userdata *User, filename string) (bool, bool) {
	isOwner := false
	isShared := false
	if _, exists := userdata.Namespace[filename]; exists {
		isOwner = true
	}
	if _, exists := userdata.ShareStructs[filename]; exists {
		isShared = true
	}
	return isOwner, isShared
}

func retrieveAndVerifyShareData(userdata *User, filename string) (Share, uuid.UUID, ShareStructsValue, error) {
	shareStructsValue := userdata.ShareStructs[filename]
	shareUUID := shareStructsValue.ShareStructPairUUID

	storedShareDataBytes, ok := userlib.DatastoreGet(shareUUID)
	if !ok {
		return Share{}, uuid.Nil, ShareStructsValue{}, errors.New("User doesn't have share data")
	}

	var storedShareData StoredShareData
	err := json.Unmarshal(storedShareDataBytes, &storedShareData)
	if err != nil {
		return Share{}, uuid.Nil, ShareStructsValue{}, err
	}

	expectedShareHMAC, err := userlib.HMACEval(shareStructsValue.HMACKey, storedShareData.EncryptedShareStruct)
	if err != nil {
		return Share{}, uuid.Nil, ShareStructsValue{}, err
	}
	if !userlib.HMACEqual(expectedShareHMAC, storedShareData.EncryptedShareStructHMAC) {
		return Share{}, uuid.Nil, ShareStructsValue{}, errors.New("HMAC verification failed for the share struct")
	}

	shareDataBytes := userlib.SymDec(shareStructsValue.SymKey, storedShareData.EncryptedShareStruct)
	var shareData Share
	err = json.Unmarshal(shareDataBytes, &shareData)
	if err != nil {
		return Share{}, uuid.Nil, ShareStructsValue{}, err
	}

	return shareData, shareUUID, shareStructsValue, nil
}

func initializeNewShareData(userdata *User, filename string) (Share, []byte, []byte, uuid.UUID, error) {
	shareStructSet := ShareStructSet{
		ShareStructSet: make(map[string]ShareStructSetValue),
	}

	shareStructSetBytes, err := json.Marshal(shareStructSet)
	if err != nil {
		return Share{}, nil, nil, uuid.Nil, err
	}

	shareEncKey := userlib.RandomBytes(16)
	shareHMACKey := userlib.RandomBytes(16)

	encryptedShareStructSet := userlib.SymEnc(shareEncKey, userlib.RandomBytes(16), shareStructSetBytes)
	encryptedShareStructSetHMAC, err := userlib.HMACEval(shareHMACKey, encryptedShareStructSet)
	if err != nil {
		return Share{}, nil, nil, uuid.Nil, err
	}

	shareStructsSetUUID := ShareStructsSetUUID{
		EncryptedShareStructsSet:     encryptedShareStructSet,
		EncryptedShareStructsSetHMAC: encryptedShareStructSetHMAC,
	}

	shareStructsSetUUIDBytes, err := json.Marshal(shareStructsSetUUID)
	if err != nil {
		return Share{}, nil, nil, uuid.Nil, err
	}

	shareStructsSetStoreUUID := uuid.New()
	userlib.DatastoreSet(shareStructsSetStoreUUID, shareStructsSetUUIDBytes)

	fileMetadata := userdata.Namespace[filename]
	shareData := Share{
		FileUUID:        fileMetadata.UUIDStart,
		SymKey:          fileMetadata.SymKey,
		HMACKeyFiles:    fileMetadata.HMACKeyFiles,
		HMACKeyNode:     fileMetadata.HMACKeyNodes,
		ParentUUID:      uuid.Nil,
		ShareStructsSet: shareStructsSetStoreUUID,
	}

	shareDataBytes, err := json.Marshal(shareData)
	if err != nil {
		return Share{}, nil, nil, uuid.Nil, err
	}

	encryptedShareData := userlib.SymEnc(shareEncKey, userlib.RandomBytes(16), shareDataBytes)
	encryptedShareHMACValue, err := userlib.HMACEval(shareHMACKey, encryptedShareData)
	if err != nil {
		return Share{}, nil, nil, uuid.Nil, err
	}

	shareDataToStore := StoredShareData{
		EncryptedShareStruct:     encryptedShareData,
		EncryptedShareStructHMAC: encryptedShareHMACValue,
	}
	shareDataToStoreBytes, err := json.Marshal(shareDataToStore)
	if err != nil {
		return Share{}, nil, nil, uuid.Nil, err
	}

	shareUUID := uuid.New()
	userlib.DatastoreSet(shareUUID, shareDataToStoreBytes)

	return shareData, shareEncKey, shareHMACKey, shareUUID, nil
}

func createChildShareStructSet(symKey, hmacKey []byte) (uuid.UUID, error) {
	childShareStructSet := ShareStructSet{ShareStructSet: make(map[string]ShareStructSetValue)}
	childShareStructSetBytes, err := json.Marshal(childShareStructSet)
	if err != nil {
		return uuid.Nil, err
	}

	encryptedShareStructSet := userlib.SymEnc(symKey, userlib.RandomBytes(16), childShareStructSetBytes)
	encryptedShareStructSetHMAC, err := userlib.HMACEval(hmacKey, encryptedShareStructSet)
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

	storeUUID := uuid.New()
	userlib.DatastoreSet(storeUUID, shareStructsSetUUIDBytes)
	return storeUUID, nil
}

func createShareDataForInvitation(shareData Share, shareStructsValue ShareStructsValue, shareUUID,
	shareStructsSetStoreUUID uuid.UUID) (uuid.UUID, error) {

	shareDataForInvite := Share{
		FileUUID:        shareData.FileUUID,
		SymKey:          shareStructsValue.FileSymKey,
		HMACKeyFiles:    shareStructsValue.HMACKeyFiles,
		HMACKeyNode:     shareStructsValue.HMACKeyNode,
		ParentUUID:      shareUUID,
		ShareStructsSet: shareStructsSetStoreUUID,
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

	return newShareDataUUID, nil
}

func updateShareStructSet(recipientUsername string, newShareDataUUID uuid.UUID, shareStructsValue ShareStructsValue, shareData Share) error {
	shareStructSetValue := ShareStructSetValue{
		Username:  recipientUsername,
		ChildUUID: newShareDataUUID,
	}

	shareStructsSetPtr, err := getShareStructSet(shareStructsValue, shareData)
	if err != nil {
		return err
	}
	shareStructsSet := *shareStructsSetPtr

	shareStructsSet.ShareStructSet[recipientUsername] = shareStructSetValue

	err = storeShareStructSet(shareStructsValue, shareData.ShareStructsSet, shareStructsSet)
	if err != nil {
		return err
	}

	return nil
}

func storeInvitation(userdata *User, invite Invitation, recipientPK userlib.PKEEncKey) (uuid.UUID, error) {
	inviteBytes, err := json.Marshal(invite)
	if err != nil {
		return uuid.Nil, err
	}

	encryptedInviteBytes, encryptedInvitationSymKey, err := hybridEncrypt(inviteBytes, recipientPK)
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
	usernameUUID, err := generateUsernameUUID(usernameBytes)
	if err != nil {
		return uuid.Nil, err
	}

	recipientPK, ok := userlib.KeystoreGet(recipientUsername + "PK")
	if !ok {
		return uuid.Nil, errors.New("recipientUsername doesn't exist")
	}

	isOwner, isShared := checkFileOwnership(userdata, filename)
	if !(isOwner || isShared) {
		return uuid.Nil, errors.New("user does not have file with filename")
	}

	var shareData Share
	var shareUUID uuid.UUID
	var shareStructsValue ShareStructsValue

	if isShared {
		shareData, shareUUID, shareStructsValue, err = retrieveAndVerifyShareData(userdata, filename)
		if err != nil {
			return uuid.Nil, err
		}
	} else {
		var shareEncKey []byte
		var shareHMACKey []byte
		shareData, shareEncKey, shareHMACKey, shareUUID, err = initializeNewShareData(userdata, filename)
		if err != nil {
			return uuid.Nil, err
		}

		fileMetadata := userdata.Namespace[filename]
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

		err = storeUserData(userdata, usernameUUID, userdata.Password)
		if err != nil {
			return uuid.Nil, err
		}
	}

	childShareStructsSetStoreUUID, err := createChildShareStructSet(shareStructsValue.SymKey, shareStructsValue.HMACKey)
	if err != nil {
		return uuid.Nil, err
	}

	newShareDataUUID, err := createShareDataForInvitation(shareData, shareStructsValue, shareUUID, childShareStructsSetStoreUUID)
	if err != nil {
		return uuid.Nil, err
	}

	err = updateShareStructSet(recipientUsername, newShareDataUUID, shareStructsValue, shareData)
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

	return storeInvitation(userdata, invite, recipientPK)
}

func decryptInvitation(invitationData []byte, privateKey userlib.PKEDecKey) (Invitation, error) {
	var invitationHybridPair InvitationHybridPair
	err := json.Unmarshal(invitationData, &invitationHybridPair)
	if err != nil {
		return Invitation{}, err
	}

	symKey, err := userlib.PKEDec(privateKey, invitationHybridPair.EncryptedSymKey)
	if err != nil {
		return Invitation{}, err
	}

	inviteBytes := userlib.SymDec(symKey, invitationHybridPair.EncryptedInvitation)

	var invite Invitation
	err = json.Unmarshal(inviteBytes, &invite)
	if err != nil {
		return Invitation{}, err
	}

	return invite, nil
}

func verifyInvitation(userdata *User, invitationPtr uuid.UUID, senderUsername string) (Invitation, error) {
	storedInviteBytes, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return Invitation{}, errors.New("Invite doesn't exist")
	}

	var storedInvitationData StoredInvitationData
	err := json.Unmarshal(storedInviteBytes, &storedInvitationData)
	if err != nil {
		return Invitation{}, err
	}

	senderVerifyKey, ok := userlib.KeystoreGet(senderUsername + "DS")
	if !ok {
		return Invitation{}, errors.New("Sender doesn't have verify key in Keystore")
	}

	err = userlib.DSVerify(senderVerifyKey, storedInvitationData.InvitationHybridPair, storedInvitationData.SignedInvitationHybridPair)
	if err != nil {
		return Invitation{}, err
	}

	return decryptInvitation(storedInvitationData.InvitationHybridPair, userdata.PrivateKey)
}

func decryptAndVerifyInvitationShareData(invite Invitation) (Share, error) {
	storedShareDataBytes, ok := userlib.DatastoreGet(invite.ShareStructPairUUID)
	if !ok {
		return Share{}, errors.New("Share data not in datastore")
	}

	var storedShareData StoredShareData
	err := json.Unmarshal(storedShareDataBytes, &storedShareData)
	if err != nil {
		return Share{}, err
	}

	storedShareDataHMAC, err := userlib.HMACEval(invite.ShareStructsHMACKey, storedShareData.EncryptedShareStruct)
	if err != nil {
		return Share{}, err
	}
	if !userlib.HMACEqual(storedShareDataHMAC, storedShareData.EncryptedShareStructHMAC) {
		return Share{}, errors.New("HMAC verification failed for the store share data")
	}

	shareBytes := userlib.SymDec(invite.ShareStructsSymKey, storedShareData.EncryptedShareStruct)
	var share Share
	err = json.Unmarshal(shareBytes, &share)
	if err != nil {
		return Share{}, err
	}

	return share, nil
}

func storeFlattenedShareStructsEntry(userdata *User, filename string, flattenedShareStructsEntry FlattenedShareStructsEntry) error {
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

func storeFlattenedShareStructsValue(userdata *User, filename string, shareStructsValue ShareStructsValue) error {
	shareStructsValueBytes, err := json.Marshal(shareStructsValue)
	if err != nil {
		return err
	}

	encryptedShareStructsValue, encryptedHybridKey, err := hybridEncrypt(shareStructsValueBytes, userdata.PublicKey)
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
	if err != nil {
		return err
	}

	flattenedShareStructsEntry := FlattenedShareStructsEntry{
		EncryptedShareStructsValue:       flattenedShareStructsHybridPairBytes,
		SignedEncryptedShareStructsValue: signedEncryptedShareStructsValue,
	}

	return storeFlattenedShareStructsEntry(userdata, filename, flattenedShareStructsEntry)
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

	invite, err := verifyInvitation(userdata, invitationPtr, senderUsername)
	if err != nil {
		return err
	}
	if invite.Revoked {
		return errors.New("Invite has been revoked")
	}

	share, err := decryptAndVerifyInvitationShareData(invite)
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
	usernameUUID, err := generateUsernameUUID(usernameBytes)

	err = storeUserData(userdata, usernameUUID, userdata.Password)
	if err != nil {
		return err
	}

	err = storeFlattenedShareStructsValue(userdata, filename, shareStructsValue)
	if err != nil {
		return err
	}

	return nil
}

func removeRecipientFromShareStructSet(shareStructsValue ShareStructsValue, recipientUsername string, shareData *Share) error {
	shareStructSet, err := getShareStructSet(shareStructsValue, *shareData)
	if err != nil {
		return err
	}

	if _, exists := shareStructSet.ShareStructSet[recipientUsername]; !exists {
		return errors.New("recipientUsername doesn't exist in the SharedStructsSet")
	}

	recipientShareUUID := shareStructSet.ShareStructSet[recipientUsername].ChildUUID
	userlib.DatastoreDelete(recipientShareUUID)
	delete(shareStructSet.ShareStructSet, recipientUsername)

	newShareStructsSetUUID := uuid.New()
	if err := storeShareStructSet(shareStructsValue, newShareStructsSetUUID, *shareStructSet); err != nil {
		return err
	}

	shareData.ShareStructsSet = newShareStructsSetUUID
	return nil
}

func updateChildShareData(shareStructsValue ShareStructsValue, shareData Share, shareStructSet ShareStructSet, newOwnerShareUUID uuid.UUID) error {
	for _, childShareStructSetValue := range shareStructSet.ShareStructSet {
		childShareData, err := loadShareStruct(childShareStructSetValue.ChildUUID, shareStructsValue)
		if err != nil {
			return err
		}
		childShareData.ParentUUID = newOwnerShareUUID
		if err := storeShareStruct(shareStructsValue, *childShareData, childShareStructSetValue.ChildUUID); err != nil {
			return err
		}
	}
	return nil
}

func updateStartNodeAndFileMetadata(userdata *User, filename string, shareData *Share, shareStructsValue ShareStructsValue) error {
	startNodeStructBytes, ok := userlib.DatastoreGet(shareData.FileUUID)
	if !ok {
		return errors.New("Start node doesn't exist in Datastore")
	}

	var startNodeStruct LinkedListNode
	if err := json.Unmarshal(startNodeStructBytes, &startNodeStruct); err != nil {
		return err
	}
	statNodeStructHMAC, err := userlib.HMACEval(shareStructsValue.HMACKeyNode, startNodeStruct.SerializedUUIDPair)
	if err != nil {
		return err
	}
	ok = userlib.HMACEqual(statNodeStructHMAC, startNodeStruct.SerializedUUIDPairHMAC)
	if !ok {
		return errors.New("HMAC verification failed")
	}
	userlib.DatastoreDelete(shareData.FileUUID)

	newFileUUID := uuid.New()
	userlib.DatastoreSet(newFileUUID, startNodeStructBytes)

	err = updateShareStructTree(shareStructsValue, *shareData, newFileUUID, shareStructsValue.ShareStructPairUUID)
	if err != nil {
		return err
	}

	fileMetadata := userdata.Namespace[filename]
	fileMetadata.UUIDStart = newFileUUID
	userdata.Namespace[filename] = fileMetadata

	shareStructsValue.FileUUID = newFileUUID
	userdata.ShareStructs[filename] = shareStructsValue

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
	shareData, err := loadShareStruct(shareStructsValue.ShareStructPairUUID, shareStructsValue)
	if err != nil {
		return errors.New("Could not load share struct")
	}

	err = removeRecipientFromShareStructSet(shareStructsValue, recipientUsername, shareData)
	if err != nil {
		return err
	}

	userlib.DatastoreDelete(shareStructsValue.ShareStructPairUUID)
	newOwnerShareUUID := uuid.New()
	shareStructsValue.ShareStructPairUUID = newOwnerShareUUID
	userdata.ShareStructs[filename] = shareStructsValue
	if err = storeShareStruct(shareStructsValue, *shareData, newOwnerShareUUID); err != nil {
		return err
	}

	shareStructSet, err := getShareStructSet(shareStructsValue, *shareData)
	if err != nil {
		return err
	}
	if err = updateChildShareData(shareStructsValue, *shareData, *shareStructSet, newOwnerShareUUID); err != nil {
		return err
	}

	if err = updateStartNodeAndFileMetadata(userdata, filename, shareData, shareStructsValue); err != nil {
		return err
	}

	usernameBytes, err := json.Marshal(userdata.Username)
	if err != nil {
		return err
	}
	usernameUUID, err := generateUsernameUUID(usernameBytes)
	if err = storeUserData(userdata, usernameUUID, userdata.Password); err != nil {
		return err
	}

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
