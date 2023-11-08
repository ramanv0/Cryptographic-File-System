package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"

	"strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	var doris *client.User
	var eve *client.User
	var frank *client.User
	var grace *client.User
	var horace *client.User
	var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User
	var bobPhone *client.User
	var bobLaptop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	dorisFile := "dorisFile.txt"
	eveFile := "eveFile.txt"
	frankFile := "frankFile.txt"
	graceFile := "graceFile.txt"
	horaceFile := "horaceFile.txt"
	iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		Specify("My Test: Testing Store then Append", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			err := aliceLaptop.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
		})

		Specify("My Test: Testing Accept then Append", func() {
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			bob.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())

			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			invite, err := bob.CreateInvitation(bobFile, "alice")
			Expect(err).To(BeNil())

			err = alice.AcceptInvitation("bob", invite, aliceFile)
			Expect(err).To(BeNil())

			err = aliceLaptop.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))
		})

		Specify("My Test: RevokeAccess", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			alice.StoreFile(aliceFile, []byte(contentOne))

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			eve, err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())

			grace, err = client.InitUser("grace", defaultPassword)
			Expect(err).To(BeNil())

			frank, err = client.InitUser("frank", defaultPassword)
			Expect(err).To(BeNil())

			inviteAB, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", inviteAB, bobFile)
			Expect(err).To(BeNil())

			inviteAC, err := alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("alice", inviteAC, charlesFile)
			Expect(err).To(BeNil())

			inviteBD, err := bob.CreateInvitation(bobFile, "doris")
			Expect(err).To(BeNil())

			err = doris.AcceptInvitation("bob", inviteBD, dorisFile)
			Expect(err).To(BeNil())

			inviteBE, err := bob.CreateInvitation(bobFile, "eve")
			Expect(err).To(BeNil())

			err = eve.AcceptInvitation("bob", inviteBE, eveFile)
			Expect(err).To(BeNil())

			inviteDF, err := doris.CreateInvitation(dorisFile, "frank")
			Expect(err).To(BeNil())

			err = frank.AcceptInvitation("doris", inviteDF, frankFile)
			Expect(err).To(BeNil())

			inviteCG, err := charles.CreateInvitation(charlesFile, "grace")
			Expect(err).To(BeNil())

			err = grace.AcceptInvitation("charles", inviteCG, graceFile)
			Expect(err).To(BeNil())

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			data, err := bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
			Expect(data).To(BeNil())

			data, err = doris.LoadFile(dorisFile)
			Expect(err).ToNot(BeNil())
			Expect(data).To(BeNil())

			data, err = eve.LoadFile(eveFile)
			Expect(err).ToNot(BeNil())
			Expect(data).To(BeNil())

			data, err = frank.LoadFile(frankFile)
			Expect(err).ToNot(BeNil())
			Expect(data).To(BeNil())

			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = doris.AppendToFile(dorisFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = eve.AppendToFile(eveFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = frank.AppendToFile(frankFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		Specify("My Test: Tampering (Store then Load/Append/CreateInvitation)", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			alice.StoreFile(aliceFile, []byte(contentOne))

			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			datastoreMap := userlib.DatastoreGetMap()
			for uuidKey, _ := range datastoreMap {
				userlib.DatastoreSet(uuidKey, []byte("Overwritten with garbage bytes!!!"))
			}

			_, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			err = aliceLaptop.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			_, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("My Test: Filename doesn't exist in namespace (Load, Append, CreateInvitation)", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			_, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("My Test: recipientUsername does not exist", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			alice.StoreFile(aliceFile, []byte(contentOne))

			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("My Test: Revoke before accepting", func() {
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			bob.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())

			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			invite, err := bob.CreateInvitation(bobFile, "alice")
			Expect(err).To(BeNil())

			bob.RevokeAccess(bobFile, "alice")

			err = alice.AcceptInvitation("bob", invite, aliceFile)
			Expect(err).ToNot(BeNil())

			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("My Test: Test append bandwidth", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			alice.StoreFile(aliceFile, []byte(contentOne))

			garbageStr := ""
			for i := 0; i < 100; i++ {
				garbageStr += "A"
			}

			before := userlib.DatastoreGetBandwidth()
			alice.AppendToFile(aliceFile, []byte(garbageStr))
			after := userlib.DatastoreGetBandwidth()

			Expect(after).To(BeNumerically("~", before+(len(garbageStr)+2907), 500))
		})

		Specify("My Test: Append shouldn't scale with total file size", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			garbageStr := ""
			for i := 0; i < 100; i++ {
				garbageStr += "A"
			}

			largeContent := ""
			for i := 0; i < 10000; i++ {
				largeContent += "AAAAA"
			}

			alice.StoreFile(aliceFile, []byte(largeContent))

			before := userlib.DatastoreGetBandwidth()
			alice.AppendToFile(aliceFile, []byte(garbageStr))
			after := userlib.DatastoreGetBandwidth()

			Expect(after).To(BeNumerically("~", before+(len(garbageStr)+2907), 500))
		})

		Specify("My Test: Append shouldn't scale with number of files", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			garbageStr := ""
			for i := 0; i < 100; i++ {
				garbageStr += "A"
			}

			for i := 0; i < 100; i++ {
				alice.StoreFile(aliceFile+strconv.Itoa(i), []byte("A"))
			}

			before := userlib.DatastoreGetBandwidth()
			alice.AppendToFile(aliceFile+"0", []byte(garbageStr))
			after := userlib.DatastoreGetBandwidth()

			Expect(after).To(BeNumerically("~", before+(len(garbageStr)+2907), 500))
		})

		Specify("My Test: Append shouldn't scale with length of the filename", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			garbageStr := ""
			for i := 0; i < 100; i++ {
				garbageStr += "A"
			}

			longFilename := "" // 10000 bytes
			for i := 0; i < 1000; i++ {
				longFilename += "AAAAAAAAAA"
			}

			alice.StoreFile(longFilename, []byte(contentOne))

			before := userlib.DatastoreGetBandwidth()
			alice.AppendToFile(longFilename, []byte(garbageStr))
			after := userlib.DatastoreGetBandwidth()

			Expect(after).To(BeNumerically("~", before+(len(garbageStr)+2907), 500))
		})

		Specify("My Test: Append shouldn't scale with the size of the previous apped", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			alice.StoreFile(aliceFile, []byte(contentOne))

			garbageStr := ""
			for i := 0; i < 100; i++ {
				garbageStr += "A"
			}

			largePrevAppend := "" // 10000 bytes
			for i := 0; i < 1000; i++ {
				largePrevAppend += "AAAAAAAAAA"
			}

			alice.AppendToFile(aliceFile, []byte(largePrevAppend))

			before := userlib.DatastoreGetBandwidth()
			alice.AppendToFile(aliceFile, []byte(garbageStr))
			after := userlib.DatastoreGetBandwidth()

			Expect(after).To(BeNumerically("~", before+(len(garbageStr)+2907), 500))
		})

		Specify("My Test: Append shouldn't scale with length of the username", func() {
			longUsername := "" // 10000 bytes
			for i := 0; i < 1000; i++ {
				longUsername += "AAAAAAAAAA"
			}

			alice, err = client.InitUser(longUsername, defaultPassword)
			Expect(err).To(BeNil())

			garbageStr := ""
			for i := 0; i < 100; i++ {
				garbageStr += "A"
			}

			alice.StoreFile(aliceFile, []byte(contentOne))

			before := userlib.DatastoreGetBandwidth()
			alice.AppendToFile(aliceFile, []byte(garbageStr))
			after := userlib.DatastoreGetBandwidth()

			Expect(after).To(BeNumerically("~", before+(len(garbageStr)+2907), 500))
		})

		Specify("My Test: Append shouldn't scale with length of the password", func() {
			longPassword := "" // 10000 bytes
			for i := 0; i < 1000; i++ {
				longPassword += "AAAAAAAAAA"
			}

			alice, err = client.InitUser("alice", longPassword)
			Expect(err).To(BeNil())

			garbageStr := ""
			for i := 0; i < 100; i++ {
				garbageStr += "A"
			}

			alice.StoreFile(aliceFile, []byte(contentOne))

			before := userlib.DatastoreGetBandwidth()
			alice.AppendToFile(aliceFile, []byte(garbageStr))
			after := userlib.DatastoreGetBandwidth()

			Expect(after).To(BeNumerically("~", before+(len(garbageStr)+2907), 500))
		})

		Specify("My Test: Append shouldn't scale with the number of users the file is shared with", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			alice.StoreFile(aliceFile, []byte(contentOne))

			garbageStr := ""
			for i := 0; i < 100; i++ {
				garbageStr += "A"
			}

			for i := 0; i < 100; i++ {
				newUser, err := client.InitUser("user"+strconv.Itoa(i), defaultPassword)
				Expect(err).To(BeNil())
				invite, err := alice.CreateInvitation(aliceFile, "user"+strconv.Itoa(i))
				Expect(err).To(BeNil())
				newUser.AcceptInvitation("alice", invite, "file"+strconv.Itoa(i))
			}

			before := userlib.DatastoreGetBandwidth()
			alice.AppendToFile(aliceFile, []byte(garbageStr))
			after := userlib.DatastoreGetBandwidth()

			Expect(after).To(BeNumerically("~", before+(len(garbageStr)+2907), 500))
		})

		Specify("My Test: InitUser when a user with the same username exists", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("My Test: InitUser when an empty username is provided", func() {
			alice, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("My Test: GetUser when there is no initialized user for the given username.", func() {
			_, err := client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("My Test: GetUser when the user credentials are invalid.", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			_, err := client.GetUser("alice", defaultPassword+"x")
			Expect(err).ToNot(BeNil())

			_, err = client.GetUser("alicex", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("My Test: GetUser when the User struct cannot be obtained due to malicious action.", func() {
			alice, err = client.InitUser("alice", defaultPassword)

			datastoreMap := userlib.DatastoreGetMap()
			for uuidKey, _ := range datastoreMap {
				userlib.DatastoreSet(uuidKey, []byte("Overwritten with garbage bytes!!!"))
			}

			_, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("My Test: Comprehensive", func() {
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			err = aliceLaptop.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			bobPhone, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bobPhone.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			bobLaptop, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = bobLaptop.AppendToFile(bobFile, []byte(contentThree))
			Expect(err).To(BeNil())

			data, err = bobLaptop.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			data, err = bobPhone.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			data, err = aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			err = bobLaptop.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())

			data, err = bobLaptop.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			data, err = bobPhone.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			data, err = aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			err = aliceLaptop.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			_, err = bobLaptop.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = bobPhone.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			newUUIDNS := aliceLaptop.Namespace[aliceFile].UUIDStart
			newUUIDSH := aliceLaptop.ShareStructs[aliceFile].FileUUID
			Expect(newUUIDNS == newUUIDSH).To(BeTrue())

			oldUUIDSH := bobLaptop.ShareStructs[bobFile].FileUUID
			Expect(newUUIDNS == oldUUIDSH).To(BeFalse())

			_, ok := userlib.DatastoreGet(oldUUIDSH)
			Expect(ok).To(BeFalse())
		})

		Specify("My Test: Share-Revoke", func() {
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			bobPhone, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			invite, err := aliceDesktop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bobPhone.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			data, err := bobPhone.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			err = aliceDesktop.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			_, err = bobPhone.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			err = bobPhone.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			data, err = aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})

		Specify("My Test: Recipient should not be able to access the file until they call AcceptInvitation", func() {
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			bobPhone, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			invite, err := aliceDesktop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			_, err = bobPhone.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			err = bobPhone.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			_, err = bobPhone.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			err = bobPhone.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			data, err := bobPhone.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			err = bobPhone.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			data, err = bobPhone.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			err = aliceDesktop.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			_, err = bobPhone.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			err = bobPhone.AppendToFile(bobFile, []byte(contentThree))
			Expect(err).ToNot(BeNil())

			data, err = aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))
		})

		Specify("My Test: Big share tree", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			frank, err = client.InitUser("frank", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			eve, err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			bobPhone, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			grace, err = client.InitUser("grace", defaultPassword)
			Expect(err).To(BeNil())

			horace, err = client.InitUser("horace", defaultPassword)
			Expect(err).To(BeNil())

			invite, err := alice.CreateInvitation(aliceFile, "frank")
			Expect(err).To(BeNil())

			err = frank.AcceptInvitation("alice", invite, frankFile)
			Expect(err).To(BeNil())

			invite, err = alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("alice", invite, charlesFile)
			Expect(err).To(BeNil())

			invite, err = alice.CreateInvitation(aliceFile, "doris")
			Expect(err).To(BeNil())

			err = doris.AcceptInvitation("alice", invite, dorisFile)
			Expect(err).To(BeNil())

			invite, err = alice.CreateInvitation(aliceFile, "eve")
			Expect(err).To(BeNil())

			err = eve.AcceptInvitation("alice", invite, eveFile)
			Expect(err).To(BeNil())

			invite, err = frank.CreateInvitation(frankFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("frank", invite, bobFile)
			Expect(err).To(BeNil())

			invite, err = frank.CreateInvitation(frankFile, "grace")
			Expect(err).To(BeNil())

			err = grace.AcceptInvitation("frank", invite, graceFile)
			Expect(err).To(BeNil())

			invite, err = eve.CreateInvitation(eveFile, "horace")
			Expect(err).To(BeNil())

			err = horace.AcceptInvitation("eve", invite, horaceFile)
			Expect(err).To(BeNil())

			err = alice.RevokeAccess(aliceFile, "frank")
			Expect(err).To(BeNil())

			_, err = frank.LoadFile(frankFile)
			Expect(err).ToNot(BeNil())

			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = bobPhone.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = grace.LoadFile(graceFile)
			Expect(err).ToNot(BeNil())

			data, err := charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			data, err = eve.LoadFile(eveFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			data, err = horace.LoadFile(horaceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			err = horace.AppendToFile(horaceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			ira, err = client.InitUser("ira", defaultPassword)
			Expect(err).To(BeNil())

			invite, err = horace.CreateInvitation(horaceFile, "ira")
			Expect(err).To(BeNil())

			err = ira.AcceptInvitation("horace", invite, iraFile)
			Expect(err).To(BeNil())
			err = ira.AppendToFile(iraFile, []byte(contentThree))
			Expect(err).To(BeNil())

			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			err = alice.RevokeAccess(aliceFile, "eve")
			Expect(err).To(BeNil())

			_, err = eve.LoadFile(eveFile)
			Expect(err).ToNot(BeNil())

			_, err = horace.LoadFile(horaceFile)
			Expect(err).ToNot(BeNil())

			_, err = ira.LoadFile(iraFile)
			Expect(err).ToNot(BeNil())

			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})
	})
})
