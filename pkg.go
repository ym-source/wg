package wg

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"wg/config"
	"wg/core"

	"golang.org/x/crypto/curve25519"
)

// ------------------- 数据结构 -------------------
type User struct {
	Username     string
	PrivateKey   string
	PublicKey    string
	PresharedKey string
	IP           string
}

var (
	mu           sync.Mutex
	users        []*User
	serverPubKey string // 服务端公钥（可动态生成或固定）
)

type Device struct {
	wgServer *core.WireGuardServer
}

func New(nodeId, serverPriv string, listenPort int) *Device {
	wgServer, err := config.BuildOptions("wg"+nodeId, serverPriv, listenPort)
	if err != nil {
		fmt.Println("Error initializing WireGuard server:", err)
		return nil
	}
	return &Device{wgServer: wgServer}
}
func (d *Device) Stop() {
	defer d.wgServer.Close()
	fmt.Println("Stopping device:")
}

// ------------------- Key 生成 -------------------
func GenerateKeyPair() (priv, pub string, err error) {
	var privKey [32]byte
	_, err = rand.Read(privKey[:])
	if err != nil {
		return "", "", err
	}
	priv = base64.StdEncoding.EncodeToString(privKey[:])

	var pubKey [32]byte
	// curve25519 生成公钥
	curve25519.ScalarBaseMult(&pubKey, &privKey)
	pub = base64.StdEncoding.EncodeToString(pubKey[:])
	return
}

func GeneratePsk() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// ------------------- IP 分配 -------------------
func AllocateIP(index int) string {
	return fmt.Sprintf("15.0.0.%d", index+2) // .2 开始
}

// ------------------- 添加/删除用户 -------------------
func (d *Device) AddUser(username string) (*User, error) {
	mu.Lock()
	defer mu.Unlock()

	priv, pub, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	psk, err := GeneratePsk()
	if err != nil {
		return nil, err
	}

	ip := AllocateIP(len(users))
	user := &User{
		Username:     username,
		PrivateKey:   priv,
		PublicKey:    pub,
		PresharedKey: psk,
		IP:           ip,
	}

	users = append(users, user)

	// 写入 WG Peer
	config.AddPeer(pub, psk, ip+"/32")
	return user, nil
}

func (d *Device) RemoveUser(publicKey string) {
	config.RemovePeer(publicKey)
}
