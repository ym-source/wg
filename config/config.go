package config

import (
	"fmt"
	"net"
	"sync"

	"github.com/ym-source/wg/core"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// 用于同步访问配置
var mu sync.Mutex

// 存储当前用户的配置信息
var wgServer *core.WireGuardServer

// BuildOptions 构建 SingBox 配置
func BuildOptions(interfaceName, serverPriv string, listenPort, nodeId int) (*core.WireGuardServer, error) {
	wgServer1, err := core.NewWireGuardServer(interfaceName, serverPriv, listenPort, nodeId)
	if err != nil {
		return nil, fmt.Errorf("failed to create WireGuard server: %v", err)
	} else {
		wgServer = wgServer1
	}
	return wgServer1, err
}

// 添加新的 Peer 配置
func AddPeer(publicKey, psk, allowedIP string) error {
	mu.Lock()
	defer mu.Unlock()
	// 添加客户端
	cidrs := []string{allowedIP}
	var ips []net.IPNet
	// 解析每个 CIDR
	for _, cidr := range cidrs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("Error parsing CIDR:", err)
		}
		// 将 IPNet 加入切片
		ips = append(ips, *ipnet) // 这里使用 *ipnet 来解引用 ipnet，避免类型不匹配
	}
	// 解析公钥并检查错误
	clientPublicKey, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return fmt.Errorf("Failed to parse public key: %v", err)
	} // 替换为客户端公钥
	presharedKey, err := wgtypes.ParseKey(psk)
	if err != nil {
		return fmt.Errorf("Failed to parse public key: %v", err)
	} // 替换为客户端公钥
	// 创建 Peer
	peer := core.WGPeer{
		PublicKey: clientPublicKey,
		IPS:       ips, // 设置 Peer 的 IP
	}
	err = wgServer.AddPeer(peer, &presharedKey)
	if err != nil {
		return fmt.Errorf("failed to add client peer: %v", err)
	}

	// 获取状态
	_, err = wgServer.GetStatus()
	if err != nil {
		return fmt.Errorf("failed to get WireGuard status: %v", err)
	}
	return nil
}

// RemovePeer 动态删除 Peer
func RemovePeer(publicKey string) error {
	mu.Lock()
	defer mu.Unlock()
	// 解析公钥并检查错误
	clientPublicKey, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return fmt.Errorf("Failed to parse public key: %v", err)
	}
	err = wgServer.RemovePeer(clientPublicKey)
	if err != nil {
		return fmt.Errorf("failed to add client peer: %v", err)
	}

	// 获取状态
	_, err = wgServer.GetStatus()
	if err != nil {
		return fmt.Errorf("failed to get WireGuard status: %v", err)
	}
	return nil
}
