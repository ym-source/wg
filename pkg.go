package wg

import (
	"fmt"

	"github.com/ym-source/wg/config"
	"github.com/ym-source/wg/core"
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
	users []*User
)

type Device struct {
	wgServer *core.WireGuardServer
}

func New(serverPriv string, listenPort, nodeId int) (*Device, error) {
	wgServer, err := config.BuildOptions("wg"+fmt.Sprint(nodeId), serverPriv, listenPort, nodeId)
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
func (d *Device) AddUser(username, priv, pub, psk string) error {
	// 写入 WG Peer
	err := config.AddPeer(pub, psk, "0.0.0.0/0")
	return err
}

func (d *Device) RemoveUser(publicKey string) error {
	err := config.RemovePeer(publicKey)
	return err
}
