package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	"testing"
	"reflect"
	"github.com/cs161-staff/userlib"
	_ "encoding/json"
	_ "encoding/hex"
	"github.com/google/uuid"
	 "strings"
	_ "errors"
	_ "strconv"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}



func TestPlease(t *testing.T) {
	clear()

	
	userlib.SetDebugStatus(true)


	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("failed init", err)
		return
	}
	data := userlib.DatastoreGetMap()

	u.StoreFile("file1", []byte("damnit"))


	for k, v := range data {
		_ = v
		userlib.DatastoreDelete(k)
	}
	_, err = u.LoadFile("file1")
	if err == nil {
		t.Error("should errored", err)
	}
}


func TestMoreModifying(t *testing.T) {
	clear()
	userlib.SetDebugStatus(true)
	

	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	u2, err := InitUser("bob", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	apd := []byte("This is a testThis is a test")
	str, err := u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("error in sharing")
	}
	_ = apd
	err = u2.ReceiveFile("file1", "alice", str)
	if err != nil {
		t.Error("failed to receive", err)
	}


	

	




	data := userlib.DatastoreGetMap()
	_ = data

	for k, v := range data {
		_ = v
		userlib.DatastoreSet(k, []byte("DFDFSDFSDF"))
	}

	magic_string, err := u.ShareFile("file1", "stupid")
	if err == nil {
		t.Error("should have errored stupid DNE", err)
	}

	_ = magic_string
	err = u2.ReceiveFile("file1", "alice", str)
	if err == nil {
		t.Error("failed to receive", err)
	}

	err = u.AppendFile("nonexisting", v)
	if err == nil {
		t.Error("should erred", err)
		return
	}
	v2, err2 := u.LoadFile("file1")
	if err2 == nil {
		t.Error("should have errored", err)
		return
	}
	_ = v2

	v2, err = u2.LoadFile("file1")
	if err == nil {
		t.Error("Should have errored", err)
		return
	}
	u, err = GetUser("alice", "fubar")
	if err == nil {
		t.Error("should have been corrupted", err)
		return
	}




}
func TestInit(t *testing.T) {
	clear()
	
	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	
	u, err = InitUser("", "sdsd")
	if err == nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	u, err = InitUser("alisce", "")
	if err == nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}


	_ = u
	_, _ = uuid.FromBytes([]byte("let compile"))
	// t.Log() only produces output if you run with "go test -v"
	//t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}

func TestAttempts(t *testing.T) {
	clear()

	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	u2, err := InitUser("bob", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v = []byte("this is a test")
	u2.StoreFile("file1", v)
	magic_string, err := u.ShareFile("file2", "bob")
	if err == nil {
		t.Error("Should have failed")
		return
	}
	_ = magic_string

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("failed sharing")
		return
	}
	//magic_string = "changedmagic"
	err = u2.ReceiveFile("file1", "alice", magic_string)

	if err == nil {
		t.Error("error same filename", err)
	}

	err = u2.ReceiveFile("file2", "steve", magic_string)

	if err == nil {
		t.Error("wrong sender", err)
	}


	
}
func TestGet(t *testing.T) {
	clear()
	//t.Log("Get test")

	userlib.SetDebugStatus(true)

	u, err := InitUser("sheerak", "sucks")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	//t.Log("initialized user", u)

	u1, err := InitUser("sheerak", "sucks")
	if err == nil {
		// t.Error says the test fails
		t.Error("should have errored", err)
		return
	}
	u1, err = GetUser("sheerak", "sucks")
	if err != nil {
		// t.Error says the test fails
		t.Error("couldnt get", err)
		return
	}

	//t.Log("Got user", u1)
	
	if strings.Compare(u1.Username, u.Username) != 0 {
		t.Error("Failed to get username correctly", err)
		t.Log("u is ", u)
		t.Log("u1 is ", u1)
		return
	}


	u2, err := GetUser("sheerak", "rocks")
	if err == nil {
		t.Error("Logged in but password is wrong", err)
		return
	}
	_ = u2


	



	

	//t.Log("Got user", u2)



}

func TestGetWrongUser(t *testing.T) {
	clear()
	//t.Log("Get test")

	userlib.SetDebugStatus(true)


	u1, err := GetUser("sheerak", "sucks")
	if err == nil {
		t.Error("Failed to get user", err)
		return
	}
	//t.Log("Got user", u1)
	_ = u1
	//t.Log("Got user", u2)
}
func TestStorage(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
	hash := userlib.Hash([]byte("alice" + "file1"))
	uid, _ := uuid.FromBytes(hash[:16])
	userlib.DatastoreDelete(uid)
	userlib.DatastoreSet(uid, []byte("hello"))
	v2, err2 = u.LoadFile("file1")
	if err2 == nil {
		t.Error("Failed to detect change", err2)
		return
	}
	if reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file should be different", v, v2)
		return
	}


}

func TestInvalidFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
}

func TestAppend(t *testing.T) {
	clear()
	u, err := InitUser("jonah", "password")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err := GetUser("jonah", "password")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u3, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	
	str1 := "Really Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long string" +
	 "Really Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long string" +
	"Really Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long string " +
	"Really Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long stringReally Long string"
	str2 := "I hope it works"
	str3 := "sheerak sucks"
	appendedData := []byte(str1+str2+str3)

	u.StoreFile("file", []byte(str1))

	magic_string, err := u.ShareFile("file", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u3.ReceiveFile("file", "jonah", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	
	
	err = u.AppendFile("file", []byte(str2))
	if err != nil {
		t.Error("append str2 error", err)
	}
	err = u.AppendFile("file", []byte(str3))
	if err != nil {
		t.Error("append str3 error", err)
	}

	loadedFile, err := u.LoadFile("file")
	if err != nil {
		t.Error("load error", err)
	}
	loadedFile2, err := u2.LoadFile("file")
	if err != nil {
		t.Error("load error", err)
	}
	v2, err := u3.LoadFile("file")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}

	if !reflect.DeepEqual(loadedFile2, loadedFile) {
		t.Error("Downloaded file is not the same", loadedFile2, loadedFile)
		return
	}
	if !reflect.DeepEqual(appendedData, loadedFile) {
		t.Error("Downloaded file is not the same", appendedData, loadedFile)
		return
	}

	if !reflect.DeepEqual(v2, loadedFile) {
		t.Error("Downloaded file is not the same", appendedData, loadedFile)
		return
	}

	appendedData = []byte(str1+str2+str3 + str3)

	err = u3.AppendFile("file", []byte(str3))
	if err != nil {
		t.Error("append str3 error", err)
	}
	loadedFile, err = u.LoadFile("file")
	if err != nil {
		t.Error("load error", err)
	}

	if !reflect.DeepEqual(appendedData, loadedFile) {
		t.Error("Downloaded file is not the same", appendedData, loadedFile)
		return
	}

	

}
func TestShareThenAppend(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)
	
	var v2 []byte
	var magic_string string

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}
	shouldBe := []byte("This is a test" + "appending")
	appendData := []byte("appending")
	u2.AppendFile("file2", appendData)

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("LoadFile file2 error")
		return
	}
	v, err = u.LoadFile("file1")
	if err != nil {
		t. Error("loadfile file 1 error")
		return
	}

	if !reflect.DeepEqual(v, shouldBe) {
		t.Error("Shared appended file v not equal to should be")
		return
	}

	if !reflect.DeepEqual(v2, shouldBe) {
		t.Error("Shared appended file v2 not equal to should be")
		return
	}

	//t.Error("", v, v2)
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared appended file not equal", v, v2)
		return
	}

	_ = shouldBe

}
func TestShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	u3, err2 := InitUser("sheerak", "sucks")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}
	
	v := []byte("This is a test")
	u.StoreFile("file1", v)
	
	var v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "stupid")
	if err == nil {
		t.Error("should have errored stupid DNE", err)
	}
	magic_string, err = u.ShareFile("stupid", "stupid")
	if err == nil {
		t.Error("should have errored stupid DNE", err)
	}
	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "stupid", magic_string)
	if err == nil {
		t.Error("wrong sender")
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err == nil {
		t.Error("cant receive same filename", err)
		return
	}

	magic_string, err = u2.ShareFile("file2", "sheerak")
	if err != nil {
		t.Error("failed sharing", err)
	}

	err = u3.ReceiveFile("file3", "bob", magic_string)

	testbyte := []byte("helllooooooo")
	u.StoreFile("file1", testbyte)
	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	v3, err := u3.LoadFile("file3")
	if !reflect.DeepEqual(testbyte, v2) {
		t.Error("Shared file is not the same", testbyte, v2)
		return
	}
	if !reflect.DeepEqual(testbyte, v3) {
		t.Error("Shared file is not the same", testbyte, v3)
		return
	}

}

func TestRevoke(t *testing.T) {
	clear()
	u, err := InitUser("sheerak", "sucks")
	if err != nil {
		t.Error("Failed to initialize sheerak", err)
		return
	}
	u2, err2 := InitUser("jonah", "isawesome")
	if err2 != nil {
		t.Error("Failed to initialize jonah", err2)
		return
	}
	
	u3, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)
	
	var v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from sheerak", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "jonah")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "sheerak", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	magic_string, err = u2.ShareFile("file2", "alice")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u3.ReceiveFile("file3", "jonah", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}
	err = u.RevokeFile("file1", "jonah")
	if err != nil {
		t.Error("Revoking caused error", err)
		return
	}
	err = u.RevokeFile("file1", "jonah")
	if err == nil {
		t.Error("should have errored", err)
		return
	}
	err = u2.RevokeFile("file1", "jonah")
	if err == nil {
		t.Error("not owner", err)
		return
	}
	
	err = u.RevokeFile("file1", "alice")
	if err == nil {
		t.Error("not direct child", err)
		return
	}
	v2, err = u2.LoadFile("file2")
	if err == nil {
		t.Error("File should have been revoked")
		return
	}

	v2, err = u3.LoadFile("file3")
	if err == nil {
		t.Error("file should have been revoked")
		return
	}
	str, err := u3.ShareFile("file3", "jonah")
	if err == nil {
		t.Error("shouldnt have been able to share", err)
		return
	}

	str, err = u2.ShareFile("file2", "alice")
	if err == nil {
		t.Error("shouldnt have been able to share", err)
		return
	}
	_ = str

	err = u.RevokeFile("file1", "stupid")
	if err == nil {
		t.Error("doesnt have access", err)
		return
	}

	err = u2.AppendFile("file2", []byte("PLEEASE"))
	if err == nil {
		t.Error("shouldnt have been able to append")
		return
	}

}
