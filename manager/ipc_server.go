/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"github.com/1060279812/wireguard/windows/services"
	"io"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/1060279812/wireguard/windows/conf"
	"github.com/1060279812/wireguard/windows/driver"
	"github.com/1060279812/wireguard/windows/updater"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

var (
	managerServices     = make(map[*ManagerService]bool)
	managerServicesLock sync.RWMutex
	haveQuit            uint32
	quitManagersChan    = make(chan struct{}, 1)
)

type ManagerService struct {
	events        *os.File
	eventLock     sync.Mutex
	elevatedToken windows.Token
}

func (s *ManagerService) StoredConfig(tunnelName string) (*conf.Config, error) {
	conf, err := conf.LoadFromName(tunnelName)
	if err != nil {
		return nil, err
	}
	if s.elevatedToken == 0 {
		conf.Redact()
	}
	return conf, nil
}

// [Interface]
// PrivateKey = YBOWHj8CGt2jfYzxUw+LPISkoU7GBMC2P/ys0a1LB2k=
// Address = 10.1.7.3/24
// MTU = 1420

// [Peer]
// PublicKey = /3mh+V0WpIVNcECT9BB+Qz9VClT56WV5COLr2TsDZHs=
// AllowedIPs = 10.0.0.0/8
// Endpoint = 23.157.88.195:4001
// PersistentKeepalive = 25

//[Peer]
//PublicKey = bGXkGfgXvsu1DrPepV8efLA5WnbnEBvu9M34ninwozI=
//AllowedIPs = 10.1.7.5/32
//Endpoint = 192.168.18.1:33079
//PersistentKeepalive = 25

// [Interface]
// PrivateKey = YBOWHj8CGt2jfYzxUw+LPISkoU7GBMC2P/ys0a1LB2k=
// Address = 10.1.7.3/24
// MTU = 1420

// [Peer]
// PublicKey = /3mh+V0WpIVNcECT9BB+Qz9VClT56WV5COLr2TsDZHs=
// AllowedIPs = 0.0.0.0/0, ::/0
// Endpoint = 23.157.88.195:4001
// PersistentKeepalive = 25

//[Peer]
//PublicKey = rM4FM2NaSQCHthVe8hA25fbgwJA2hkUGlHd1rp7E6kI=
//AllowedIPs = 0.0.0.0/1,128.0.0.0/1
//Endpoint = 192.168.8.1:33079
//PersistentKeepalive = 25

// [Interface]
// PrivateKey = YBOWHj8CGt2jfYzxUw+LPISkoU7GBMC2P/ys0a1LB2k=
// Address = 10.1.7.3/24
// MTU = 1420

// [Peer]
// PublicKey = eBDtNoqMs19HtTVC0ojbicpzVFMXMwfGd7pfin5zrXU=
// AllowedIPs = 1.25.25.28/0, ::/0
// Endpoint = 192.168.117.114:51820
// PersistentKeepalive = 25

// [Peer]
// PublicKey = fBDtNoqMs19HtTVC0ojbicpzVFMXMwfGd7pfin5zrXU=
// AllowedIPs = 0.0.0.0/1, 128.0.0.0/1
// Endpoint = 192.168.117.111:51820
// PersistentKeepalive = 25

//[Peer]
//PublicKey = gBDtNoqMs19HtTVC0ojbicpzVFMXMwfGd7pfin5zrXU=
//AllowedIPs = 1.25.25.28/0, ::/0
//Endpoint = 192.168.117.222:51820
//PersistentKeepalive = 25

//[Peer]
//PublicKey = hBDtNoqMs19HtTVC0ojbicpzVFMXMwfGd7pfin5zrXU=
//AllowedIPs = 1.25.25.28/0, ::/0
//Endpoint = 192.168.117.333:51820
//PersistentKeepalive = 25

//func (s *ManagerService) RuntimeConfig(tunnelName string) (*conf.Config, error) {
//	storedConfig, err := conf.LoadFromName(tunnelName)
//	if err != nil {
//		return nil, err
//	}
//	driverAdapter, err := findDriverAdapter(tunnelName)
//	if err != nil {
//		return nil, err
//	}
//	runtimeConfig, err := driverAdapter.Configuration()
//	if err != nil {
//		driverAdapter.Unlock()
//		releaseDriverAdapter(tunnelName)
//		return nil, err
//	}
//
//	conf := conf.FromDriverConfiguration(runtimeConfig, storedConfig)
//	driverAdapter.Unlock()
//	if s.elevatedToken == 0 {
//		conf.Redact()
//	}
//
//	//// 立即将配置同步到 wireguard-nt
//	//if err := driverAdapter.SetConfiguration(conf.ToDriverConfiguration()); err != nil {
//	//	return nil, err
//	//}
//
//	// log.Printf("RuntimeConfig() runtimeConfig peer size=%d\n", runtimeConfig.PeerCount)
//	// log.Printf("RuntimeConfig() storedConfig peer size=%d\n", len(storedConfig.Peers))
//	// log.Printf("RuntimeConfig() conf peer size=%d\n", len(conf.Peers))
//
//	return storedConfig, nil
//}

//func logPeerAction(action string, peer *driver.Peer) {
//	// 使用 Base64 编码 PublicKey
//	publicKeyEncoded := base64.StdEncoding.EncodeToString(peer.PublicKey[:])
//	log.Printf("%s Peer: PublicKey=%s, Endpoint=%v, AllowedIPs=%v\n", action, publicKeyEncoded, peer.Endpoint, peer.Endpoint.Family)
//}

func (s *ManagerService) RuntimeConfig(tunnelName string) (*conf.Config, error) {
	storedConfig, err := conf.LoadFromName(tunnelName)
	if err != nil {
		return nil, err
	}
	driverAdapter, err := findDriverAdapter(tunnelName)
	if err != nil {
		return nil, err
	}
	runtimeConfig, err := driverAdapter.Configuration()
	if err != nil {
		driverAdapter.Unlock()
		releaseDriverAdapter(tunnelName)
		return nil, err
	}
	conf := conf.FromDriverConfiguration(runtimeConfig, storedConfig)
	driverAdapter.Unlock()
	if s.elevatedToken == 0 {
		conf.Redact()
	}
	//// 立即将配置同步到 wireguard-nt
	if err := driverAdapter.SetConfiguration(conf.ToDriverConfiguration()); err != nil {
		return nil, err
	}
	err = driverAdapter.SetAdapterState(driver.AdapterStateUp)
	if err != nil {
		log.Println(fmt.Errorf("%v: %w", services.ErrorDeviceBringUp, err))
	}
	log.Printf("RuntimeConfig() runtimeConfig peer size=%d\n", runtimeConfig.PeerCount)
	log.Printf("RuntimeConfig() storedConfig peer size=%d\n", len(storedConfig.Peers))
	log.Printf("RuntimeConfig() conf peer size=%d\n", len(conf.Peers))
	//log.Printf("RuntimeConfig() driverAdapter luid=%d\n", driverAdapter.LUID())

	//if int(runtimeConfig.PeerCount) != len(conf.Peers) {
	//time.Sleep(5 * time.Second)
	//sendMessageForPipe("set route")
	//}
	return conf, nil
}

func (s *ManagerService) UpdateConfig(tunnelName string, storedConfig *conf.Config) (*conf.Config, error) {
	// 查找与指定 tunnel 关联的驱动适配器
	driverAdapter, err := findDriverAdapter(tunnelName)
	if err != nil {
		return nil, err
	}
	// 获取驱动适配器的运行时配置
	//runtimeConfig, err := driverAdapter.Configuration()
	//if err != nil {
	//	driverAdapter.Unlock()
	//	releaseDriverAdapter(tunnelName)
	//	return nil, err
	//}

	err = driverAdapter.SetConfiguration(storedConfig.ToDriverConfiguration())
	if err != nil {
		log.Println("UpdateConfig() err")
		driverAdapter.Unlock()
		releaseDriverAdapter(tunnelName)
		return nil, err
	}
	driverAdapter.Unlock()

	log.Printf("UpdateConfig() storedConfig peer size=%d\n", len(storedConfig.Peers))
	log.Printf("UpdateConfig() conf=%s\n", storedConfig.ToWgQuick())

	// 如果没有提升权限，则对配置进行脱敏处理
	if s.elevatedToken == 0 {
		storedConfig.Redact()
	}
	log.Println("UpdateConfig() end()")
	return storedConfig, nil
}

func (s *ManagerService) Start(tunnelName string) error {
	c, err := conf.LoadFromName(tunnelName)
	if err != nil {
		return err
	}

	// Figure out which tunnels have intersecting addresses/routes and stop those.
	trackedTunnelsLock.Lock()
	tt := make([]string, 0, len(trackedTunnels))
	var inTransition string
	for t, state := range trackedTunnels {
		c2, err := conf.LoadFromName(t)
		if err != nil || !c.IntersectsWith(c2) {
			// If we can't get the config, assume it doesn't intersect.
			continue
		}
		tt = append(tt, t)
		if len(t) > 0 && (state == TunnelStarting || state == TunnelUnknown) {
			inTransition = t
			break
		}
	}
	trackedTunnelsLock.Unlock()
	if len(inTransition) != 0 {
		return fmt.Errorf("Please allow the tunnel ‘%s’ to finish activating", inTransition)
	}

	// Stop those intersecting tunnels asynchronously.
	go func() {
		for _, t := range tt {
			s.Stop(t)
		}
		for _, t := range tt {
			state, err := s.State(t)
			if err == nil && (state == TunnelStarted || state == TunnelStarting) {
				log.Printf("[%s] Trying again to stop zombie tunnel", t)
				s.Stop(t)
				time.Sleep(time.Millisecond * 100)
			}
		}
	}()
	// After the stop process has begun, but before it's finished, we install the new one.
	path, err := c.Path()
	if err != nil {
		return err
	}
	return InstallTunnel(path)
}

func (s *ManagerService) Stop(tunnelName string) error {
	err := UninstallTunnel(tunnelName)
	if err == windows.ERROR_SERVICE_DOES_NOT_EXIST {
		_, notExistsError := conf.LoadFromName(tunnelName)
		if notExistsError == nil {
			return nil
		}
	}
	return err
}

func (s *ManagerService) WaitForStop(tunnelName string) error {
	serviceName, err := conf.ServiceNameOfTunnel(tunnelName)
	if err != nil {
		return err
	}
	m, err := serviceManager()
	if err != nil {
		return err
	}
	for {
		service, err := m.OpenService(serviceName)
		if err == nil || err == windows.ERROR_SERVICE_MARKED_FOR_DELETE {
			service.Close()
			time.Sleep(time.Second / 3)
		} else {
			return nil
		}
	}
}

func (s *ManagerService) Delete(tunnelName string) error {
	if s.elevatedToken == 0 {
		return windows.ERROR_ACCESS_DENIED
	}
	err := s.Stop(tunnelName)
	if err != nil {
		return err
	}
	return conf.DeleteName(tunnelName)
}

func (s *ManagerService) State(tunnelName string) (TunnelState, error) {
	serviceName, err := conf.ServiceNameOfTunnel(tunnelName)
	if err != nil {
		return 0, err
	}
	m, err := serviceManager()
	if err != nil {
		return 0, err
	}
	service, err := m.OpenService(serviceName)
	if err != nil {
		return TunnelStopped, nil
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return TunnelUnknown, nil
	}
	switch status.State {
	case svc.Stopped:
		return TunnelStopped, nil
	case svc.StopPending:
		return TunnelStopping, nil
	case svc.Running:
		return TunnelStarted, nil
	case svc.StartPending:
		return TunnelStarting, nil
	default:
		return TunnelUnknown, nil
	}
}

func (s *ManagerService) GlobalState() TunnelState {
	return trackedTunnelsGlobalState()
}

func (s *ManagerService) Create(tunnelConfig *conf.Config) (*Tunnel, error) {
	if s.elevatedToken == 0 {
		return nil, windows.ERROR_ACCESS_DENIED
	}
	err := tunnelConfig.Save(true)
	if err != nil {
		return nil, err
	}
	return &Tunnel{tunnelConfig.Name}, nil
	// TODO: handle already existing situation
	// TODO: handle already running and existing situation
}

func (s *ManagerService) Tunnels() ([]Tunnel, error) {
	names, err := conf.ListConfigNames()
	if err != nil {
		return nil, err
	}
	tunnels := make([]Tunnel, len(names))
	for i := 0; i < len(tunnels); i++ {
		tunnels[i].Name = names[i]
	}
	return tunnels, nil
	// TODO: account for running ones that aren't in the configuration store somehow
}

func (s *ManagerService) Quit(stopTunnelsOnQuit bool) (alreadyQuit bool, err error) {
	if s.elevatedToken == 0 {
		return false, windows.ERROR_ACCESS_DENIED
	}
	if !atomic.CompareAndSwapUint32(&haveQuit, 0, 1) {
		return true, nil
	}

	// Work around potential race condition of delivering messages to the wrong process by removing from notifications.
	managerServicesLock.Lock()
	s.eventLock.Lock()
	s.events = nil
	s.eventLock.Unlock()
	delete(managerServices, s)
	managerServicesLock.Unlock()

	if stopTunnelsOnQuit {
		names, err := conf.ListConfigNames()
		if err != nil {
			return false, err
		}
		for _, name := range names {
			UninstallTunnel(name)
		}
	}

	quitManagersChan <- struct{}{}
	return false, nil
}

func (s *ManagerService) UpdateState() UpdateState {
	return updateState
}

func (s *ManagerService) Update() {
	if s.elevatedToken == 0 {
		return
	}
	progress := updater.DownloadVerifyAndExecute(uintptr(s.elevatedToken))
	go func() {
		for {
			dp := <-progress
			IPCServerNotifyUpdateProgress(dp)
			if dp.Complete || dp.Error != nil {
				return
			}
		}
	}()
}

func (s *ManagerService) ServeConn(reader io.Reader, writer io.Writer) {
	decoder := gob.NewDecoder(reader)
	encoder := gob.NewEncoder(writer)
	for {
		var methodType MethodType
		err := decoder.Decode(&methodType)
		if err != nil {
			return
		}
		switch methodType {
		case StoredConfigMethodType:
			var tunnelName string
			err := decoder.Decode(&tunnelName)
			if err != nil {
				return
			}
			config, retErr := s.StoredConfig(tunnelName)
			if config == nil {
				config = &conf.Config{}
			}
			err = encoder.Encode(*config)
			if err != nil {
				return
			}
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case RuntimeConfigMethodType:
			var tunnelName string
			err := decoder.Decode(&tunnelName)
			if err != nil {
				return
			}
			config, retErr := s.RuntimeConfig(tunnelName)
			if config == nil {
				config = &conf.Config{}
			}
			err = encoder.Encode(*config)
			if err != nil {
				return
			}
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case UpdateConfigMethodType:
			var tunnelName string
			err := decoder.Decode(&tunnelName)
			if err != nil {
				return
			}
			var config2 *conf.Config
			err = decoder.Decode(&config2)
			if err != nil {
				return
			}
			config, retErr := s.UpdateConfig(tunnelName, config2)
			if config == nil {
				config = &conf.Config{}
			}
			err = encoder.Encode(*config)
			if err != nil {
				return
			}
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case StartMethodType:
			var tunnelName string
			err := decoder.Decode(&tunnelName)
			if err != nil {
				return
			}
			retErr := s.Start(tunnelName)
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case StopMethodType:
			var tunnelName string
			err := decoder.Decode(&tunnelName)
			if err != nil {
				return
			}
			retErr := s.Stop(tunnelName)
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case WaitForStopMethodType:
			var tunnelName string
			err := decoder.Decode(&tunnelName)
			if err != nil {
				return
			}
			retErr := s.WaitForStop(tunnelName)
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case DeleteMethodType:
			var tunnelName string
			err := decoder.Decode(&tunnelName)
			if err != nil {
				return
			}
			retErr := s.Delete(tunnelName)
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case StateMethodType:
			var tunnelName string
			err := decoder.Decode(&tunnelName)
			if err != nil {
				return
			}
			state, retErr := s.State(tunnelName)
			err = encoder.Encode(state)
			if err != nil {
				return
			}
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case GlobalStateMethodType:
			state := s.GlobalState()
			err = encoder.Encode(state)
			if err != nil {
				return
			}
		case CreateMethodType:
			var config conf.Config
			err := decoder.Decode(&config)
			if err != nil {
				return
			}
			tunnel, retErr := s.Create(&config)
			if tunnel == nil {
				tunnel = &Tunnel{}
			}
			err = encoder.Encode(tunnel)
			if err != nil {
				return
			}
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case TunnelsMethodType:
			tunnels, retErr := s.Tunnels()
			err = encoder.Encode(tunnels)
			if err != nil {
				return
			}
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case QuitMethodType:
			var stopTunnelsOnQuit bool
			err := decoder.Decode(&stopTunnelsOnQuit)
			if err != nil {
				return
			}
			alreadyQuit, retErr := s.Quit(stopTunnelsOnQuit)
			err = encoder.Encode(alreadyQuit)
			if err != nil {
				return
			}
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case UpdateStateMethodType:
			updateState := s.UpdateState()
			err = encoder.Encode(updateState)
			if err != nil {
				return
			}
		case UpdateMethodType:
			s.Update()
		default:
			return
		}
	}
}

func IPCServerListen(reader, writer, events *os.File, elevatedToken windows.Token) *ManagerService {
	service := &ManagerService{
		events:        events,
		elevatedToken: elevatedToken,
	}

	go func() {
		managerServicesLock.Lock()
		managerServices[service] = true
		managerServicesLock.Unlock()
		service.ServeConn(reader, writer)
		managerServicesLock.Lock()
		service.eventLock.Lock()
		service.events = nil
		service.eventLock.Unlock()
		delete(managerServices, service)
		managerServicesLock.Unlock()
	}()
	return service
}

func notifyAll(notificationType NotificationType, adminOnly bool, ifaces ...any) {
	if len(managerServices) == 0 {
		return
	}

	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(notificationType)
	if err != nil {
		return
	}
	for _, iface := range ifaces {
		err = encoder.Encode(iface)
		if err != nil {
			return
		}
	}

	managerServicesLock.RLock()
	for m := range managerServices {
		if m.elevatedToken == 0 && adminOnly {
			continue
		}
		go func(m *ManagerService) {
			m.eventLock.Lock()
			defer m.eventLock.Unlock()
			if m.events != nil {
				m.events.SetWriteDeadline(time.Now().Add(time.Second))
				m.events.Write(buf.Bytes())
			}
		}(m)
	}
	managerServicesLock.RUnlock()
}

func errToString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func IPCServerNotifyTunnelChange(name string, state TunnelState, err error) {
	notifyAll(TunnelChangeNotificationType, false, name, state, trackedTunnelsGlobalState(), errToString(err))
}

func IPCServerNotifyTunnelsChange() {
	notifyAll(TunnelsChangeNotificationType, false)
}

func IPCServerNotifyUpdateFound(state UpdateState) {
	notifyAll(UpdateFoundNotificationType, false, state)
}

func IPCServerNotifyUpdateProgress(dp updater.DownloadProgress) {
	notifyAll(UpdateProgressNotificationType, true, dp.Activity, dp.BytesDownloaded, dp.BytesTotal, errToString(dp.Error), dp.Complete)
}

func IPCServerNotifyManagerStopping() {
	notifyAll(ManagerStoppingNotificationType, false)
	time.Sleep(time.Millisecond * 200)
}
