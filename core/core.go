package core

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WireGuardServer struct {
	client        *wgctrl.Client
	wk            string
	interfaceName string
	mutex         sync.Mutex
}
type WGPeer struct {
	PublicKey wgtypes.Key
	IPS       []net.IPNet
}

func NewWireGuardServer(interfaceName, serverPriv string, listenPort, nodeId int) (*WireGuardServer, error) {
	// Parse the private key
	privKey, err := wgtypes.ParseKey(serverPriv)
	if err != nil {
		log.Fatalf("failed to parse private key: %v", err)
	}
	// 创建 WireGuard 配置文件
	err = createWireGuardConfigFile(interfaceName, privKey, listenPort, nodeId)
	if err != nil {
		log.Fatalf("failed to create config file: %v", err)
	}
	// Create a wgctrl client
	client, err := wgctrl.New()
	if err != nil {
		log.Fatalf("failed to create wgctrl client: %v", err)
	}

	// Check if the device exists (wg0 in this case)
	devices, err := client.Devices()
	if err != nil {
		log.Fatalf("failed to list WireGuard devices: %v", err)
	}

	var found bool
	for _, device := range devices {
		if device.Name == interfaceName {
			found = true
			break
		}
	}

	wk, err := getRouteInfo()
	if err != nil {
		log.Fatalf("failed to list WireGuard devices: %v", err)
	}
	if !found {
		// 创建一个虚拟的 WireGuard 设备
		cmd := exec.Command("ip", "link", "add", "dev", interfaceName, "type", "wireguard")
		err := cmd.Run()
		if err != nil {
			return nil, fmt.Errorf("failed to create WireGuard device: %v", err)
		}

		// 设置设备为 UP
		cmd = exec.Command("ip", "link", "set", interfaceName, "up")
		err = cmd.Run()
		if err != nil {
			return nil, fmt.Errorf("failed to bring up WireGuard device: %v", err)
		}

		// 配置 IP 地址等
		cmd = exec.Command("ip", "addr", "add", "15.0.0."+string(nodeId)+"/24", "dev", interfaceName)
		err = cmd.Run()
		if err != nil {
			return nil, fmt.Errorf("failed to assign IP to WireGuard device: %v", err)
		}
	}

	// Define WireGuard configuration
	interfaceConfig := wgtypes.Config{
		PrivateKey: &privKey,
		ListenPort: &listenPort,
	}

	// Configure the WireGuard device using wgctrl
	err = client.ConfigureDevice(interfaceName, interfaceConfig)
	if err != nil {
		log.Fatalf("failed to configure WireGuard device: %v", err)
	}
	// Apply the PostUp iptables rules
	if err := execIptablesPostUp(interfaceName, wk); err != nil {
		log.Fatalf("failed to execute PostUp iptables rules: %v", err)
	}

	// Return the WireGuard server instance
	return &WireGuardServer{
		client:        client,
		wk:            wk,
		interfaceName: interfaceName,
	}, nil
}
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir() // 如果info是目录而非文件，也可以返回false
}

// 创建 WireGuard 配置文件
func createWireGuardConfigFile(interfaceName string, privateKey wgtypes.Key, listenPort, nodeId int) error {
	configContent := fmt.Sprintf(`
[Interface]
PrivateKey = %s
Address = 15.0.0.%d/24
ListenPort = %d

[Peer]
PublicKey = your_peer_public_key
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`, privateKey.String(), nodeId, listenPort)
	// 将配置写入文件
	filePath := fmt.Sprintf("/etc/wireguard/%s.conf", interfaceName)
	if fileExists(filePath) {
		return nil
	}
	err0 := os.MkdirAll("/etc/wireguard", 0755)
	if err0 != nil {
		return fmt.Errorf("Error creating directory: %v", err0)
	}
	err := os.WriteFile(filePath, []byte(configContent), 0600)
	if err != nil {
		return fmt.Errorf("failed to write WireGuard config file: %v", err)
	}

	fmt.Printf("WireGuard config file created at %s\n", filePath)
	return nil
}

func getRouteInfo() (string, error) {
	cmd := exec.Command("ip", "route", "show", "default")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", err
	}
	output := out.String()
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == "default" {
			return fields[4], nil // fields[4] 通常是网卡接口名
		}
	}
	return "", fmt.Errorf("default route not found")
}

// execIptablesPostUp 执行 PostUp 网络配置
func execIptablesPostUp(interfaceName, wk string) error {
	// 配置 iptables 规则，启动网络地址转换 (NAT)
	cmd := exec.Command("iptables", "-A", "FORWARD", "-i", interfaceName, "-j", "ACCEPT")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to execute iptables -A FORWARD: %v", err)
	}

	cmd = exec.Command("iptables", "-A", "FORWARD", "-o", interfaceName, "-j", "ACCEPT")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to execute iptables -A FORWARD: %v", err)
	}

	cmd = exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", wk, "-j", "MASQUERADE")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to execute iptables POSTROUTING: %v", err)
	}

	fmt.Println("PostUp rules applied.")
	return nil
}

// execIptablesPostDown 执行 PostDown 网络配置
func (wg *WireGuardServer) execIptablesPostDown() error {
	// Define iptables commands for cleanup
	cmds := [][]string{
		{"-t", "nat", "-D", "POSTROUTING", "-o", wg.wk, "-j", "MASQUERADE"},
		{"-D", "FORWARD", "-i", wg.interfaceName, "-j", "ACCEPT"},
		{"-D", "FORWARD", "-o", wg.interfaceName, "-j", "ACCEPT"},
	}

	// Loop through the commands to run them one by one
	for _, cmdArgs := range cmds {
		cmd := exec.Command("iptables", cmdArgs...)
		log.Printf("Running command: iptables %s", cmdArgs)
		cmd.Stderr = os.Stderr // Capture stderr to get any error messages
		err := cmd.Run()
		if err != nil {
			log.Printf("Failed to execute iptables command: iptables %s, error: %v", cmdArgs, err)
			return fmt.Errorf("failed to execute iptables command: %v", err)
		}
		log.Printf("Successfully executed: iptables %s", cmdArgs)
	}

	fmt.Println("PostDown rules applied.")
	return nil
}

// AddPeer 添加 Peer 配置
func (wg *WireGuardServer) AddPeer(p WGPeer, presharedKey *wgtypes.Key) error {
	wg.mutex.Lock()
	defer wg.mutex.Unlock()

	// 配置 Peer
	peerConfig := wgtypes.PeerConfig{
		PublicKey:  p.PublicKey,
		AllowedIPs: p.IPS,
	}

	// 添加 Peer 到 WireGuard 设备
	err := wg.client.ConfigureDevice(wg.interfaceName, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerConfig},
	})
	if err != nil {
		log.Printf("Failed to add peer: %v", err)
	} else {
		fmt.Println("Peer added successfully.")
	}

	return err
}

// GetStatus 获取设备状态
func (wg *WireGuardServer) GetStatus() (string, error) {
	device, err := wg.client.Device(wg.interfaceName)
	if err != nil {
		return "", err
	}

	status := fmt.Sprintf("Device: %s\nPublicKey: %s\n", wg.interfaceName, device.PublicKey.String())
	for _, peer := range device.Peers {
		status += fmt.Sprintf("Peer: %s\n", peer.PublicKey.String())
	}
	return status, nil
}

// RemovePeer 移除 Peer 配置
func (wg *WireGuardServer) RemovePeer(pub wgtypes.Key) error {
	wg.mutex.Lock()
	defer wg.mutex.Unlock()

	// 配置要删除的 Peer
	peerConfig := wgtypes.PeerConfig{
		PublicKey: pub,
	}

	// 更新配置以删除该 Peer
	err := wg.client.ConfigureDevice(wg.interfaceName, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerConfig},
	})
	if err != nil {
		log.Printf("Failed to remove peer: %v", err)
	} else {
		fmt.Println("Peer removed successfully.")
	}

	return err
}

// Close 清理资源
func (wg *WireGuardServer) Close() {
	// Wait for shutdown signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	<-c

	// 清理 WireGuard 设备
	if err := wg.client.Close(); err != nil {
		log.Printf("Error closing WireGuard client: %v", err)
	}

	// 执行 PostDown 配置
	if err := wg.execIptablesPostDown(); err != nil {
		log.Printf("Error executing PostDown iptables rules: %v", err)
	}

	// 删除 WireGuard 设备
	deleteCmd := exec.Command("ip", "link", "delete", wg.interfaceName)
	if err := deleteCmd.Run(); err != nil {
		log.Printf("Failed to delete WireGuard device: %v", err)
	} else {
		fmt.Println("WireGuard device deleted successfully.")
	}

	// Log and exit
	log.Println("Shutting down...")
	os.Exit(0)
}
