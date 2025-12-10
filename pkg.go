package wg

import (
	"fmt"
	"sync"
	"wg/config"
	"wg/core"
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
	mu    sync.Mutex
	users []*User
)

type Device struct {
	wgServer *core.WireGuardServer
}

func New(serverPriv string, listenPort, nodeId int) (*Device, error) {
	wgServer, err := config.BuildOptions("wg"+nodeId, serverPriv, listenPort, nodeId)
	if err != nil {
		return nil, err
	}
	return &Device{wgServer: wgServer}, nil
}
func (d *Device) Stop() {
	defer d.wgServer.Close()
	fmt.Println("Stopping device:")
}

// ------------------- 添加/删除用户 -------------------
func (d *Device) AddUser(username, priv, pub, psk string) (*User, error) {
	mu.Lock()
	defer mu.Unlock()
	user := &User{
		Username:     username,
		PrivateKey:   priv,
		PublicKey:    pub,
		PresharedKey: psk,
	}

	users = append(users, user)

	// 写入 WG Peer
	config.AddPeer(pub, psk, "0.0.0.0/0")
	return user, nil
}

func (d *Device) RemoveUser(publicKey string) {
	config.RemovePeer(publicKey)
	condition := func(user *User) bool { return user.PublicKey == publicKey }
	users = filterUsers(users, condition)

}
func filterUsers(users []*User, condition func(*User) bool) []*User {
	var result []*User
	for _, user := range users {
		if !condition(user) {
			result = append(result, user)
		}
	}
	return result
}
