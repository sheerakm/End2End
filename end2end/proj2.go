package proj2

// CS 161 Project 2 Spring 2020
// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder. We will be very upset.

import (
	// You neet to add with
	// go get github.com/cs161-staff/userlib
	"github.com/cs161-staff/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging, etc...
	"encoding/hex"

	// UUIDs are generated right based on the cryptographic PRNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	"strconv"

	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes: 
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
        var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// The structure definition for a user record
type User struct {
	Username string
	// SymKey []byte
	MACKey []byte

	// filename maps to enced hash of File structs in datastore
	MyFiles map[string][]byte

	// files that are shared with me, maps my filename to the encrypted
	// hash that maps to uuid hash
	MySharedFiles map[string][]byte

	// My keys that User need to open a file
	// Maps filename to keys
	// First key for is the shared key for the actual file struct
	// Second key is for opening up encrypted uuid for the real uuid of the file
	MyKeys map[string][][]byte

	// Filename maps to MAC of encrypted file that i stored
	//MyMacs map[string][]byte
	
	Password string
	Salt []byte

	PDecKey userlib.PKEDecKey
	SignKey userlib.DSSignKey
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type File struct {
	Owner string
	// array of hashes for data pages
	//each new append just add a page and store it in datastore
	Pages [][]byte

	//symkey to decrypt of the data pages stored in the datastore
	SymKey []byte

	//MacKey []byte

	//Tree of accesses where the top node is the owner
	SharingTree *Tree
}
type Tree struct {
	Username string
	// UUID that shared users use to map to UUID of the file struct
	ID []byte
	Children []*Tree
}

type SharedStruct struct {
	// marshaled sharedStuff struct
	Stuff []byte
	// Mac of stuff
	MACofStuff []byte
	// Signature of stuff
	Signature []byte
}

type SharedStuff struct {
	Hash []byte // uuid of encrypted uuid of file
	Key []byte // Key for the uuid
	FileKey []byte // key for the actual file
}


func GetHash(str string) ([]byte) {
	hash := userlib.Hash([]byte(str))
	return hash[:16]
}
func Pmsg(str string) {
	userlib.DebugMsg(str)
}
func RemoveAccess(node *Tree) {
	//userlib.DebugMsg(string(node.ID))
	id, _ := uuid.FromBytes(node.ID)
	userlib.DatastoreDelete(id)
	for i := 0; i < len(node.Children); i++ {
		RemoveAccess(node.Children[i])
	}
}
func FindUser(node *Tree, username string) *Tree {
	if node.Username == username {
		return node
	}
	var cur *Tree
	for i := 0; i < len(node.Children); i++ {
		cur = FindUser(node.Children[i], username)
		if cur != nil {
			return cur
		} 
	}
	return nil
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the password has strong entropy, EXCEPT
// the attackers may possess a precomputed tables containing 
// hashes of common passwords downloaded from the internet.
func InitUser(username string, password string) (userdataptr *User, err error) {
	errMsg := "Error in InitUser, "
	var userdata User
	userdataptr = &userdata

	if password == "" || username == "" {
		return nil, errors.New(errMsg+"password or username is empty")
	}
	// Convert username into []byte hash
	hash := GetHash(username)
	
	// Convert into UUID from the hash of username
	id, _ := uuid.FromBytes(hash[:16])


	// Check if username exists, if it does error
	_, exists := userlib.DatastoreGet(id)
	if exists {
		return nil, errors.New(errMsg +"username already exists")
	}


	// Generate random salt and store
	salt := userlib.RandomBytes(16)
	userlib.DatastoreSet(id, salt)

	userdata.Username = username
	userdata.MACKey = userlib.RandomBytes(16)
	userdata.MyFiles = make(map[string][]byte)
	userdata.MySharedFiles = make(map[string][]byte)
	userdata.MyKeys = make(map[string][][]byte)
	userdata.Password = password
	userdata.Salt = salt

	passwordKey := userlib.Argon2Key([]byte(password), salt, 16)

	PEncKey, PDecKey, err := userlib.PKEKeyGen()
	userdata.PDecKey = PDecKey
	userlib.KeystoreSet(username + "/publickey", PEncKey)

	signKey, verifyKey, err := userlib.DSKeyGen()
	userdata.SignKey = signKey
	userlib.KeystoreSet(username + "/publicverify", verifyKey)

	marshal, _ := json.Marshal(userdata)
	structHash := GetHash(username + "/struct")
	structID, _ := uuid.FromBytes(structHash[:16])
	encMarshal := userlib.SymEnc(passwordKey, userlib.RandomBytes(16), marshal)
	userlib.DatastoreSet(structID, encMarshal)

	maccedStruct, _ := userlib.HMACEval(userdataptr.MACKey, encMarshal)
	macAddr := username + "/maccedStruct"
	macHash := userlib.Hash([]byte(macAddr))
	macID, _ := uuid.FromBytes(macHash[:16])
	userlib.DatastoreSet(macID, maccedStruct)

	return &userdata, nil
}

func (userdata *User) UpdateUserInfo() {


	passwordKey := userlib.Argon2Key([]byte(userdata.Password), userdata.Salt, 16)

	marshal, _ := json.Marshal(userdata)

	structHash := GetHash(userdata.Username + "/struct")
	structID, _ := uuid.FromBytes(structHash[:16])
	encMarshal := userlib.SymEnc(passwordKey, userlib.RandomBytes(16), marshal)
	userlib.DatastoreSet(structID, encMarshal)

	maccedStruct, _ := userlib.HMACEval(userdata.MACKey, encMarshal)
	macAddr := userdata.Username + "/maccedStruct"
	macHash := userlib.Hash([]byte(macAddr))
	macID, _ := uuid.FromBytes(macHash[:16])
	userlib.DatastoreSet(macID, maccedStruct)

}
// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	errMsg := "Error in GetUser, "
	var userdata User
	userdataptr = &userdata


	hash := GetHash(username)
	id, _ := uuid.FromBytes(hash[:16])
	salt, exists := userlib.DatastoreGet(id)
	// If user doesnt exist return error
	if !exists {
		return nil, errors.New("Error in GetUser, user doesnt exist")
	}

	passwordKey := userlib.Argon2Key([]byte(password), salt, 16)
	
	structHash := GetHash(username + "/struct")
	structID, _ := uuid.FromBytes(structHash[:16])
	encMarshaledData, flag := userlib.DatastoreGet(structID)
	if !flag {
		return nil, errors.New("Error in GetUser, User struct doesn't exist")
	}
	// how to get a nil value of this?!
	if encMarshaledData == nil || len(encMarshaledData) < 16{
		return nil, errors.New("Error in GetUser, encMarshaledData is NIL")
	}
	decMarshaledData := userlib.SymDec(passwordKey, encMarshaledData)

	err = json.Unmarshal(decMarshaledData, &userdata)
	if err != nil {
		return nil, errors.New(errMsg+"decryption error")
	}

	if userdata.Username != username {
		return nil, errors.New("Error in GetUser, Wrong password")
	}
	
	maccedStruct, _ := userlib.HMACEval(userdataptr.MACKey, encMarshaledData)
	macHash := GetHash(username + "/maccedStruct")
	macID, _ := uuid.FromBytes(macHash[:16])

	//check macs if not equal integrity has been broken
	macCheck, flag := userlib.DatastoreGet(macID)
	if !flag {
		return nil, errors.New("Error in GetUser, macID does not exist")
	}
	if !userlib.HMACEqual(maccedStruct, macCheck) {
		return nil, errors.New("Error in Get User, mac not equal or datastore MAC has been modified")
	}
	userdata.Password = password
	userdata.Salt = salt
	return &userdata, nil

}

// This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename 
// should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	
	var fileID uuid.UUID
	var encFile []byte

	if fileHash, ok := userdata.MyFiles[filename]; ok {
		// File is owned by user
		fileID, _ = uuid.FromBytes(fileHash[:16])
		file, flag := userlib.DatastoreGet(fileID)
		encFile = file
		if !flag { 
			Pmsg("error in store file Error happened fileid didnt exist")
			return
		}
	} else if fileHash, ok := userdata.MySharedFiles[filename]; ok {
		// File is a shared file
		fileHashID, _ := uuid.FromBytes(fileHash[:16])
		encHash, flag := userlib.DatastoreGet(fileHashID)
		if !flag {
			Pmsg("error in store fileError happened fileid didnt exist")
			return
		}
		fileHash = userlib.SymDec(userdata.MyKeys[filename][1], encHash)
		fileID, _ = uuid.FromBytes(fileHash[:16])
		file, flag := userlib.DatastoreGet(fileID)
		encFile = file
		if !flag { 
			Pmsg("error in store fileError happened fileid didnt exist")
			return
		}
	} else { // New File
		filenameHash := GetHash(userdata.Username + filename)
		userdata.MyFiles[filename] = filenameHash[:16]
		fileID, _ := uuid.FromBytes(filenameHash[:16])
		newTree := &Tree{
			userdata.Username,
			filenameHash[:16],
			make([]*Tree, 0),
		}
		currentFile := &File{
			userdata.Username,
			make([][]byte, 0),
			userlib.RandomBytes(16),
			newTree,
		}
		curPageHash := userlib.RandomBytes(16)
		currentFile.Pages = append(currentFile.Pages, curPageHash[:16])
		curPageID, _ := uuid.FromBytes(curPageHash[:16])
		encPage := userlib.SymEnc(currentFile.SymKey, userlib.RandomBytes(16), data)
		userlib.DatastoreSet(curPageID, encPage)
		marshaledData, err := json.Marshal(currentFile)
		if err != nil {

		}
		userdata.MyKeys[filename] = append(userdata.MyKeys[filename], userlib.RandomBytes(16))
		encMarshaledData := userlib.SymEnc(userdata.MyKeys[filename][0], userlib.RandomBytes(16), marshaledData)
		userlib.DatastoreSet(fileID, encMarshaledData)
		userdata.UpdateUserInfo()
		return
	}
	decFile := userlib.SymDec(userdata.MyKeys[filename][0], encFile)
	var oldFile File
	json.Unmarshal(decFile, &oldFile)
	currentFile := &File {
		oldFile.Owner,
		make([][]byte, 0),
		oldFile.SymKey,
		oldFile.SharingTree,
	}

	curPageHash := userlib.RandomBytes(16)
	
	currentFile.Pages = append(make([][]byte, 0), curPageHash)
	curPageID, _ := uuid.FromBytes(curPageHash[:16])
	encPage := userlib.SymEnc(currentFile.SymKey, userlib.RandomBytes(16), data)
	userlib.DatastoreSet(curPageID, encPage)
	
	marshaledData, err := json.Marshal(currentFile)
	if err != nil {
		Pmsg("MARSHAL ERROR IN STORE")
		return
	}
	encMarshaledData := userlib.SymEnc(userdata.MyKeys[filename][0], userlib.RandomBytes(16), marshaledData)
	userlib.DatastoreSet(fileID, encMarshaledData)
	userdata.UpdateUserInfo()


	return
}



// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	var currentFile File
	var fileHash []byte
	if val, ok := userdata.MyFiles[filename]; ok {
		fileHash = val
	} else if val, ok := userdata.MySharedFiles[filename]; ok {
		fileHash = val
		hashID, _ := uuid.FromBytes(fileHash[:16])
		encHash, flag := userlib.DatastoreGet(hashID)
		if !flag {
			return errors.New("Error AppendFile, getting encrypted hash in shared map")
		}
		if encHash == nil || len(encHash) < 16 {
			return errors.New("Error AppendFile, getting uuid from datastore")
		}
		decHash := userlib.SymDec(userdata.MyKeys[filename][1], encHash)
		fileHash = decHash
	} else {
		return errors.New("Error AppendFile, File didnt exist")
	}
	
	fileID, _ := uuid.FromBytes(fileHash[:16])
	encMarshaledData, flag := userlib.DatastoreGet(fileID)
	if !flag {
		err = errors.New("Error AppendFile, fileID does not exist")
		return err
	}

	if encMarshaledData == nil || len(encMarshaledData) < 16 {
		return errors.New("Error AppendFile, corrupted data")
	}
	decMarshaledData := userlib.SymDec(userdata.MyKeys[filename][0], encMarshaledData)
	
	err = json.Unmarshal(decMarshaledData, &currentFile)
	if err != nil {
		return errors.New("Error AppendFile, corruptd data")
	}
	if currentFile.SharingTree == nil {
		return errors.New("Error AppendFile, corruptd data")
	}
	// Need to be able to access datastore from tests
	curPageHash := userlib.RandomBytes(16)
	curPageID, _ := uuid.FromBytes(curPageHash[:16])
	currentFile.Pages = append(currentFile.Pages, curPageHash)
	_ = strconv.Itoa(52)
	encData := userlib.SymEnc(currentFile.SymKey, userlib.RandomBytes(16), data)
	userlib.DatastoreSet(curPageID, encData)


	marshaledFile, err := json.Marshal(currentFile)
	if err != nil {
		return err
	}

	encMarshaledFile := userlib.SymEnc(userdata.MyKeys[filename][0], userlib.RandomBytes(16), marshaledFile)
	userlib.DatastoreSet(fileID, encMarshaledFile)
	return nil
}


// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	updatedUser, err := GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return nil, errors.New("error updating user before load")
	}
	userdata.MyFiles = updatedUser.MyFiles
	userdata.MySharedFiles = updatedUser.MySharedFiles
	userdata.MyKeys = updatedUser.MyKeys

	errMsg := "LoadFile error, "
	var currentFile File
	if filenameHash, ok := userdata.MyFiles[filename]; ok {
		
		fileID, _ := uuid.FromBytes(filenameHash)
		encMarshaledData, flag := userlib.DatastoreGet(fileID)
		if !flag {
			return nil, errors.New("LoadFile error, File doesn't exist anymore")
		}
		if len(encMarshaledData) < 16  || encMarshaledData == nil{
			return nil, errors.New(errMsg+"encrypter data in datatstore has been set to nil")
		}
		decMarshaledData := userlib.SymDec(userdata.MyKeys[filename][0], encMarshaledData)
		err = json.Unmarshal(decMarshaledData, &currentFile)
		if err != nil {
			return nil, errors.New(errMsg+"datastore was modified")
		}
		data = make([]byte, 0)
		for i := 0; i < len(currentFile.Pages); i++ {
			filePageHash := currentFile.Pages[i]
			filePageID, _ := uuid.FromBytes(filePageHash)

			encDataPage, flag := userlib.DatastoreGet(filePageID)
			if !flag {
				return nil, errors.New("LoadFile error, datastoreget with a shared file")
			}
			if encDataPage == nil {
				return nil, errors.New("LoadFile error, encDataPage is NIL")
			}
			decDataPage := userlib.SymDec(currentFile.SymKey, encDataPage)
			data = append(data, decDataPage...)
			
		}
		//userlib.DebugMsg("fking sheerak sucks1")
		
	} else if filenameHash, ok := userdata.MySharedFiles[filename]; ok {
		hashID, _ := uuid.FromBytes(filenameHash[:16])

		encHash, flag := userlib.DatastoreGet(hashID)
		if !flag {
			return nil, errors.New("Error in LoadFile, getting hashid")
		}
		if encHash == nil {
			return nil, errors.New("Error in LoadFile, encrypted hash is nil")
		}
		decHash := userlib.SymDec(userdata.MyKeys[filename][1], encHash)
		fileID, _ := uuid.FromBytes(decHash[:16])
		encMarshaledFile, flag := userlib.DatastoreGet(fileID)

		if !flag {
			err = errors.New("File does not exist")
			return nil, err
		}
		if encMarshaledFile == nil {
			return nil, errors.New(errMsg + "encmarshaledfile is nil")
		}
		decMarshaledData := userlib.SymDec(userdata.MyKeys[filename][0], encMarshaledFile)
		json.Unmarshal(decMarshaledData, &currentFile)
		data = make([]byte, 0)
		for i := 0; i < len(currentFile.Pages); i++ {
	
			filedataPageHash := currentFile.Pages[i]
			filedataPageID, _ := uuid.FromBytes(filedataPageHash[:16])

			encDataPage, flag := userlib.DatastoreGet(filedataPageID)
			if !flag {
				return nil, errors.New("Error LoadFile, filepageID dne")
			}
			if encDataPage == nil {
				return nil, errors.New(errMsg +"got nil page")
			}
			decDataPage := userlib.SymDec(currentFile.SymKey, encDataPage)
			data = append(data, decDataPage...)
		}
		//userlib.DebugMsg("fking sheerak sucks2")
	} else {
		//userlib.DebugMsg("fking sheerak sucks")

		return nil, errors.New("Error LoadFile, file does not exist")
	}

	return data, nil
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {

	errMsg := "Error in ShareFile, "
	err = errors.New(errMsg)
	// This block is to get owner to check if the owner is sharing or smeone else
	var file File
	var hash []byte
	if val, ok := userdata.MyFiles[filename]; ok {
		hash = val
	} else if val, ok := userdata.MySharedFiles[filename]; ok {
		hash = val
		id, _ := uuid.FromBytes(hash[:16])
		encryptedHash, flag := userlib.DatastoreGet(id)
		if !flag {
			return "", errors.New(errMsg + "id does not exist")
		}
		hash = userlib.SymDec(userdata.MyKeys[filename][1], encryptedHash)
	} else {
		return "", errors.New(errMsg +"Trying to share a file that doesnt exist")
	}
	id, _ := uuid.FromBytes(hash[:16])
	encFile, flag := userlib.DatastoreGet(id)
	if !flag {
		return "", errors.New(errMsg+ "file id doesnt exist")
	}
	if encFile == nil || len(encFile) < 16 {
		return "", errors.New(errMsg+"corrupted data")
	}
	decFile := userlib.SymDec(userdata.MyKeys[filename][0], encFile)
	json.Unmarshal(decFile, &file)
	owner := file.Owner




	publicKey, flag := userlib.KeystoreGet(recipient+"/publickey")
	if !flag {
		err = errors.New("Error in ShareFile, public key does not exist")
		return "", err
	}

	// sharing the hash uuid for the hash uuid of the file struct
	recipientKey := userlib.RandomBytes(16)
	recipientHashKey := userlib.RandomBytes(16)
	recHashKeyID, _ := uuid.FromBytes(recipientHashKey)
	var encHashOfHashFile []byte
	if userdata.Username == owner {
		encHashOfHashFile = userlib.SymEnc(recipientKey, userlib.RandomBytes(16), userdata.MyFiles[filename])
	} else {
		id, _ := uuid.FromBytes(userdata.MySharedFiles[filename])
		getHash, flag := userlib.DatastoreGet(id)
		if !flag {
			return "", errors.New(errMsg+"uuid of uuid of file doesnt exist")
		}
		decHash := userlib.SymDec(userdata.MyKeys[filename][1], getHash)
		encHashOfHashFile = userlib.SymEnc(recipientKey, userlib.RandomBytes(16), decHash)
	}
	userlib.DatastoreSet(recHashKeyID, encHashOfHashFile)

	stuff := &SharedStuff {
		recipientHashKey, // sharing hash uuid for hash uuid of file
		recipientKey, // key to decrypt hash
		userdata.MyKeys[filename][0],
	}
	marshaledStuff, err := json.Marshal(stuff)

	macKey := userlib.RandomBytes(16)
	macStuff, err := userlib.HMACEval(macKey, marshaledStuff)
	signature, err := userlib.DSSign(userdata.SignKey, marshaledStuff)


	sharedStruct := &SharedStruct{
		marshaledStuff,
		macStuff,
		signature,
	}
	marshaledStruct, err := json.Marshal(sharedStruct)
	marshaledSymKey := userlib.RandomBytes(16)
	encStruct := userlib.SymEnc(marshaledSymKey, userlib.RandomBytes(16), marshaledStruct)
	if err != nil {

	}
	structIDKey := userlib.RandomBytes(16)
	structID, _ := uuid.FromBytes(structIDKey)
	userlib.DatastoreSet(structID, encStruct)

	encData, err := userlib.PKEEnc(publicKey, append(append(macKey, structIDKey...), marshaledSymKey...))
	if err != nil {
		return "", errors.New("sheerak sucks")
	}

	// Adding to sharing tree
	curUser := FindUser(file.SharingTree, userdata.Username)
	var sharedUser *Tree
	sharedUser = new(Tree)
	sharedUser.Username = recipient
	sharedUser.ID = recipientHashKey
	sharedUser.Children = make([]*Tree, 0)
	curUser.Children = append(curUser.Children, sharedUser)
	
	marshaledFile, err := json.Marshal(file)
	encFile = userlib.SymEnc(userdata.MyKeys[filename][0], userlib.RandomBytes(16), marshaledFile)


	if owner == userdata.Username {
		hashid := userdata.MyFiles[filename]
		id, _ = uuid.FromBytes(hashid)
		userlib.DatastoreSet(id, encFile)
	} else {
		hashid := userdata.MySharedFiles[filename]
		id, _ := uuid.FromBytes(hashid)
		hashID, flag := userlib.DatastoreGet(id)
		if !flag {

		}
		hashid = userlib.SymDec(userdata.MyKeys[filename][1], hashID)
		id, _ = uuid.FromBytes(hashid)
		userlib.DatastoreSet(id, encFile)
	}


	magic_string = string(encData)

	return magic_string, nil
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.


func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	userdata.UpdateUserInfo()
	errMsg := "Error in ReceiveFile, "
	var sharedStruct SharedStruct

	magic_byte := []byte(magic_string)
	decString, err := userlib.PKEDec(userdata.PDecKey, magic_byte)
	if err != nil {
		return errors.New(errMsg+"decrypting with private key error")
	}
	macKey := decString[:16]
	structIDKey := decString[16:32]
	marshaledSymKey := decString[32:48]
	
	structID, _ := uuid.FromBytes(structIDKey)
	encData, flag := userlib.DatastoreGet(structID)
	if !flag {
		return errors.New(errMsg+ "structID doesnt exist")
	}
	if encData == nil || len(encData) < 16 {
		return errors.New(errMsg+"corrupted data")
	}
	decData := userlib.SymDec(marshaledSymKey, encData)
	json.Unmarshal(decData, &sharedStruct)

	//check mac
	mac, err := userlib.HMACEval(macKey, sharedStruct.Stuff)
	if err != nil {
		return errors.New("Error ReceiveFile, hmaceval error")
	}
	equal := userlib.HMACEqual(sharedStruct.MACofStuff, mac)
	if !equal {
		return errors.New("Error ReceiveFile, MAC not equal")
	}
	
	//check signature
	signatureKey, flag := userlib.KeystoreGet(sender + "/publicverify")
	if !flag {
		return errors.New("Error ReceiveFile, getting public verify key")
	}
	err = userlib.DSVerify(signatureKey, sharedStruct.Stuff, sharedStruct.Signature)
	if err != nil {
		return errors.New("Error ReceiveFile, signature doesn't match")
	}

	var sharedStuff SharedStuff
	json.Unmarshal(sharedStruct.Stuff, &sharedStuff)

	if val, ok := userdata.MySharedFiles[filename]; ok {
		_ = val
		return errors.New("Error ReceiveFile, file already exists")
	} else if val, ok := userdata.MyFiles[filename]; ok { 
		_ = val
		return errors.New("Error ReceiveFile, file already exists")
	}
	userdata.MySharedFiles[filename] = sharedStuff.Hash
	userdata.MyKeys[filename] = make([][]byte, 2)
	userdata.MyKeys[filename][0] = sharedStuff.FileKey
	userdata.MyKeys[filename][1]= sharedStuff.Key

	userdata.UpdateUserInfo()
	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {

	errorMsg := "Error in RevokeFile, "
	var curFile File
	fileHashID := userdata.MyFiles[filename]
	fileID, _ := uuid.FromBytes(fileHashID)
	encFile, flag := userlib.DatastoreGet(fileID)
	if !flag {
		return errors.New(errorMsg + "datastoreget error, wrong hashid")
	}
	if encFile == nil || len(encFile) < 16 {
		return errors.New(errorMsg+"file corrupted")
	}
	decFile := userlib.SymDec(userdata.MyKeys[filename][0], encFile)
	json.Unmarshal(decFile, &curFile)
	if curFile.Owner != userdata.Username {
		return errors.New(errorMsg + "not owner")
	}
	found := false
	for i := 0; i < len(curFile.SharingTree.Children); i++ {
		if curFile.SharingTree.Children[i] != nil && curFile.SharingTree.Children[i].Username == target_username {
			RemoveAccess(curFile.SharingTree.Children[i])
			if len(curFile.SharingTree.Children) == 1 {
				curFile.SharingTree.Children = make([]*Tree, 0)
			} else {
				curFile.SharingTree.Children[i] = nil
				curFile.SharingTree.Children[i] = curFile.SharingTree.Children[len(curFile.SharingTree.Children)-1]
				curFile.SharingTree.Children = curFile.SharingTree.Children[:len(curFile.SharingTree.Children)-1]   
	
			}
			found = true
			Pmsg(strconv.Itoa(len(curFile.SharingTree.Children)))
			break
		}
	}
	if !found {
		return errors.New(errorMsg+"No direct target child")
	}
	marshaledData, err := json.Marshal(curFile)
	if err != nil {
		return errors.New("marshaling err")
	}
	encFile = userlib.SymEnc(userdata.MyKeys[filename][0], userlib.RandomBytes(16), marshaledData)
	userlib.DatastoreSet(fileID, encFile)
	return nil
}
