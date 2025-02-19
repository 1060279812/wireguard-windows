/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/1060279812/wireguard/windows/conf"
	"github.com/1060279812/wireguard/windows/driver"
	"github.com/1060279812/wireguard/windows/elevate"
	"github.com/1060279812/wireguard/windows/ringlogger"
	"github.com/1060279812/wireguard/windows/services"
	"github.com/1060279812/wireguard/windows/tunnel/winipcfg"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type tunnelService struct {
	Path string
}

var (
	watcher    *InterfaceWatcher
	pipeHandle windows.Handle
)

const (
	pipeName     = `\\.\pipe\MyNamedPipe`
	maxInstances = 10 // 增加命名管道的最大实例数
)

func (service *tunnelService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	// 设置服务状态为启动中
	serviceState := svc.StartPending
	changes <- svc.Status{State: serviceState}

	//var watcher *InterfaceWatcher
	var adapter *driver.Adapter
	var luid winipcfg.LUID
	var config *conf.Config
	var err error
	serviceError := services.ErrorSuccess

	// 延迟执行的函数，用于处理服务停止时的清理工作
	defer func() {
		svcSpecificEC, exitCode = services.DetermineErrorCode(err, serviceError)
		logErr := services.CombineErrors(err, serviceError)
		if logErr != nil {
			log.Println(logErr)
		}
		serviceState = svc.StopPending
		changes <- svc.Status{State: serviceState}

		stopIt := make(chan bool, 1)
		go func() {
			t := time.NewTicker(time.Second * 30)
			for {
				select {
				case <-t.C:
					t.Stop()
					buf := make([]byte, 1024)
					for {
						n := runtime.Stack(buf, true)
						if n < len(buf) {
							buf = buf[:n]
							break
						}
						buf = make([]byte, 2*len(buf))
					}
					lines := bytes.Split(buf, []byte{'\n'})
					log.Println("Failed to shutdown after 30 seconds. Probably dead locked. Printing stack and killing.")
					for _, line := range lines {
						if len(bytes.TrimSpace(line)) > 0 {
							log.Println(string(line))
						}
					}
					os.Exit(777)
					return
				case <-stopIt:
					t.Stop()
					return
				}
			}
		}()

		if logErr == nil && adapter != nil && config != nil {
			logErr = runScriptCommand(config.Interface.PreDown, config.Name)
		}
		if watcher != nil {
			watcher.Destroy()
		}
		if adapter != nil {
			adapter.Close()
		}
		if logErr == nil && adapter != nil && config != nil {
			_ = runScriptCommand(config.Interface.PostDown, config.Name)
		}
		stopIt <- true
		log.Println("Shutting down")
	}()
	// 初始化日志文件
	var logFile string
	logFile, err = conf.LogFile(true)
	if err != nil {
		serviceError = services.ErrorRingloggerOpen
		return
	}
	err = ringlogger.InitGlobalLogger(logFile, "TUN")
	if err != nil {
		serviceError = services.ErrorRingloggerOpen
		return
	}
	// 加载配置文件
	config, err = conf.LoadFromPath(service.Path)
	if err != nil {
		serviceError = services.ErrorLoadConfiguration
		return
	}
	config.DeduplicateNetworkEntries()

	log.SetPrefix(fmt.Sprintf("[%s] ", config.Name))

	services.PrintStarting()

	// 如果是在系统启动时启动的服务，检查 SCM 锁定状态以防止死锁
	if services.StartedAtBoot() {
		if m, err := mgr.Connect(); err == nil {
			if lockStatus, err := m.LockStatus(); err == nil && lockStatus.IsLocked {
				/* If we don't do this, then the driver installation will block forever, because
				 * installing a network adapter starts the driver service too. Apparently at boot time,
				 * Windows 8.1 locks the SCM for each service start, creating a deadlock if we don't
				 * announce that we're running before starting additional services.
				 */
				/* 如果不这样做，那么驱动程序安装将永远阻塞，
				 * 因为安装网络适配器也会启动驱动程序服务。
				 * 显然在启动时，Windows 8.1 会锁定 SCM 以启动每个服务，
				 * 如果不在启动其他服务之前宣布我们正在运行，就会造成死锁。
				 */
				log.Printf("SCM locked for %v by %s, marking service as started", lockStatus.Age, lockStatus.Owner)
				serviceState = svc.Running
				changes <- svc.Status{State: serviceState}
			}
			m.Disconnect()
		}
	}
	// 评估静态陷阱
	evaluateStaticPitfalls()

	// 监视网络接口
	log.Println("Watching network interfaces")
	watcher, err = watchInterface()
	if err != nil {
		serviceError = services.ErrorSetNetConfig
		return
	}

	// 解析 DNS 名称
	log.Println("Resolving DNS names")
	err = config.ResolveEndpoints()
	if err != nil {
		serviceError = services.ErrorDNSLookup
		return
	}
	// 创建网络适配器
	log.Println("Creating network adapter")
	for i := 0; i < 15; i++ {
		if i > 0 {
			time.Sleep(time.Second)
			log.Printf("Retrying adapter creation after failure because system just booted (T+%v): %v", windows.DurationSinceBoot(), err)
		}
		adapter, err = driver.CreateAdapter(config.Name, "WireGuard", deterministicGUID(config))
		if err == nil || !services.StartedAtBoot() {
			break
		}
	}
	if err != nil {
		err = fmt.Errorf("Error creating adapter: %w", err)
		serviceError = services.ErrorCreateNetworkAdapter
		return
	}
	luid = adapter.LUID()
	driverVersion, err := driver.RunningVersion()
	if err != nil {
		log.Printf("Warning: unable to determine driver version: %v", err)
	} else {
		log.Printf("Using WireGuardNT/%d.%d", (driverVersion>>16)&0xffff, driverVersion&0xffff)
	}
	err = adapter.SetLogging(driver.AdapterLogOn)
	if err != nil {
		err = fmt.Errorf("Error enabling adapter logging: %w", err)
		serviceError = services.ErrorCreateNetworkAdapter
		return
	}
	// 运行 PreUp 脚本
	err = runScriptCommand(config.Interface.PreUp, config.Name)
	if err != nil {
		serviceError = services.ErrorRunScript
		return
	}
	// 启用防火墙
	err = enableFirewall(config, luid)
	if err != nil {
		serviceError = services.ErrorFirewall
		return
	}
	// 降低权限
	log.Println("Dropping privileges")
	err = elevate.DropAllPrivileges(true)
	if err != nil {
		serviceError = services.ErrorDropPrivileges
		return
	}
	// 设置接口配置
	log.Println("Setting interface configuration")
	err = adapter.SetConfiguration(config.ToDriverConfiguration())
	if err != nil {
		serviceError = services.ErrorDeviceSetConfig
		return
	}
	err = adapter.SetAdapterState(driver.AdapterStateUp)
	if err != nil {
		serviceError = services.ErrorDeviceBringUp
		return
	}
	watcher.Configure(adapter, config, luid)
	// 运行 PostUp 脚本
	err = runScriptCommand(config.Interface.PostUp, config.Name)
	if err != nil {
		serviceError = services.ErrorRunScript
		return
	}
	// 更新服务状态为运行中
	changes <- svc.Status{State: serviceState, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	// 启动日志监听器
	//go service.startLogListener(adapter, luid, watcher)

	//创建命名管道
	//go service.startPipeServer(adapter, luid, watcher)

	var started bool
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				log.Printf("------------------ tunnel service Stop.........................")
				//释放管道
				//if pipeHandle != 0 {
				//r, _, err := procDisconnectNamedPipe.Call(uintptr(handle))
				//if r == 0 {
				//	return err
				//}
				//err := windows.CloseHandle(pipeHandle)
				//if err != nil {
				//	return false, 0
				//}
				//}
				return
			case svc.Interrogate:
				changes <- c.CurrentStatus
			default:
				log.Printf("Unexpected service control request #%d\n", c)
			}
		case <-watcher.started:
			if !started {
				serviceState = svc.Running
				changes <- svc.Status{State: serviceState, Accepts: svc.AcceptStop | svc.AcceptShutdown}
				log.Println("Startup complete")
				started = true
			}
		case e := <-watcher.errors:
			serviceError, err = e.serviceError, e.err
			return
		}
	}
}

//func (service *tunnelService) startPipeServer(adapter *driver.Adapter, luid winipcfg.LUID, watcher *InterfaceWatcher) {
//	for {
//		handle, err := windows.CreateNamedPipe(
//			windows.StringToUTF16Ptr(pipeName),
//			windows.PIPE_ACCESS_DUPLEX,
//			windows.PIPE_TYPE_MESSAGE|windows.PIPE_READMODE_MESSAGE|windows.PIPE_WAIT,
//			maxInstances,
//			4096,
//			4096,
//			0,
//			nil)
//		if err != nil {
//			log.Fatalf("Failed to create pipe: %v", err)
//		}
//
//		pipeHandle = handle
//
//		defer windows.CloseHandle(handle)
//
//		log.Println("Waiting for client to connect to the pipe...")
//		err = windows.ConnectNamedPipe(handle, nil)
//		if err != nil {
//			log.Fatalf("Failed to connect to named pipe: %v", err)
//		}
//
//		log.Println("Client connected to the pipe.")
//		go handleClient(handle, service, adapter, luid, watcher)
//	}
//}

//func handleClient(pipe windows.Handle, service *tunnelService, adapter *driver.Adapter, luid winipcfg.LUID, watcher *InterfaceWatcher) {
//	defer windows.CloseHandle(pipe)
//	buffer := make([]byte, 4096)
//
//	for {
//		var bytesRead uint32
//		err := windows.ReadFile(pipe, buffer, &bytesRead, nil)
//		if err != nil {
//			log.Printf("Error reading from pipe: %v", err)
//			break
//		}
//		message := string(buffer[:bytesRead])
//		log.Printf("Service PipeReceived message: %s", message)
//
//		if "set route" == message {
//			var config *conf.Config
//			//var err error
//			// 加载配置文件
//			config, err = conf.LoadFromPath(service.Path)
//			if err != nil {
//				return
//			}
//			//log.Printf("------------------handleClient message----------watcher.luid:%d , adapter.LUID:%d", watcher.luid, luid)
//			//if watcher.luid == 0 {
//
//			peer := config.Peers[1]
//
//			logPeerAction("-----------------addRoute", peer)
//
//			estimatedRouteCount := 0
//			//for _, peer := range config.Peers {
//			estimatedRouteCount += len(peer.AllowedIPs)
//			//}
//			routes := make(map[winipcfg.RouteData]bool, estimatedRouteCount)
//
//			//foundDefault4 := false
//			//foundDefault6 := false
//			//for _, peer := range conf.Peers {
//			for _, allowedip := range peer.AllowedIPs {
//				route := winipcfg.RouteData{
//					Destination: allowedip.Masked(),
//					Metric:      0,
//				}
//				if allowedip.Addr().Is4() {
//					if allowedip.Bits() == 0 {
//						//foundDefault4 = true
//					}
//					route.NextHop = netip.IPv4Unspecified()
//				} else if allowedip.Addr().Is6() {
//					if allowedip.Bits() == 0 {
//						//foundDefault6 = true
//					}
//					route.NextHop = netip.IPv6Unspecified()
//				}
//				routes[route] = true
//			}
//			//}
//
//			deduplicatedRoutes := make([]*winipcfg.RouteData, 0, len(routes))
//			for route := range routes {
//				r := route
//				deduplicatedRoutes = append(deduplicatedRoutes, &r)
//			}
//
//			err := luid.SetRoutesForFamily(windows.AF_INET, deduplicatedRoutes)
//			if err != nil {
//				log.Printf("------------------handleClient message SetRoutesForFamily--------------err: %w", err)
//				return
//			}
//			err2 := luid.SetRoutesForFamily(windows.AF_INET6, deduplicatedRoutes)
//			if err2 != nil {
//				log.Printf("------------------handleClient message SetRoutesForFamily--------------err2: %w", err2)
//				return
//			}
//			log.Printf("------------------handleClient message----------end")
//
//			//watcher.storedEvents = append(watcher.storedEvents, interfaceWatcherEvent{adapter.LUID(), windows.AF_INET})
//			//watcher.storedEvents = append(watcher.storedEvents, interfaceWatcherEvent{adapter.LUID(), windows.AF_INET6})
//			//	return
//			//}
//			//watcher.Configure(adapter, config, adapter.LUID())
//
//			//// 检查 LUID 对应的网络接口是否有效
//			//if isInterfaceValid(adapter.LUID()) {
//			//	log.Println("handleClient()  LUID 对应的网络接口是有效的")
//			//} else {
//			//	log.Println("handleClient()  LUID 对应的网络接口无效")
//			//}
//		}
//
//		//response := fmt.Sprintf("Received: %s", message)
//		//var bytesWritten uint32
//		//err = windows.WriteFile(pipe, []byte(response), &bytesWritten, nil)
//		//if err != nil {
//		//	log.Printf("Error writing to pipe: %v", err)
//		//	break
//		//}
//	}
//}

// isInterfaceValid 检查 LUID 对应的网络接口是否有效
func isInterfaceValid(luid winipcfg.LUID) bool {
	iface, err := luid.Interface()
	if err != nil {
		log.Printf("Error retrieving interface for LUID: %v, Error: %v", luid, err)
		return false
	}

	// 检查接口状态
	if iface.OperStatus == winipcfg.IfOperStatusUp {
		log.Printf("Interface for LUID: %v, InterfaceGUID: %v, Interface: %+v", luid, iface.InterfaceGUID, iface)
		return true
	}

	log.Printf("Interface for LUID: %v is down, InterfaceGUID: %v", luid, iface.InterfaceGUID)
	return false
}

func (service *tunnelService) startLogListener(adapter *driver.Adapter, luid winipcfg.LUID, watcher *InterfaceWatcher) {
	ticker := time.NewTicker(time.Second)
	cursor := ringlogger.CursorAll

	for {
		select {
		case <-ticker.C:
			var items []ringlogger.FollowLine
			items, cursor = ringlogger.Global.FollowFromCursor(cursor)
			if len(items) == 0 {
				continue
			}

			for _, item := range items {
				logLine := item.Line
				if strings.Contains(logLine, "Sending handshake initiation to peer") ||
					strings.Contains(logLine, "Receiving handshake response from peer") ||
					strings.Contains(logLine, "Handshake for peer") {

					//service.handleLogMessage(adapter,watcher, logLine)
				}
				//if strings.Contains(logLine, "need update route") {
				//	service.handleLogMessage(adapter, luid, watcher, logLine)
				//}
				if logLine == "[MGR] need update route" {
					service.handleLogMessage(adapter, luid, watcher, logLine)
				}
			}
		}
	}
}

func (service *tunnelService) handleLogMessage(adapter *driver.Adapter, luid winipcfg.LUID, watcher *InterfaceWatcher, logLine string) {
	log.Printf("------------------Handling log message----------watcher.luid:%d , adapter.LUID:%d , %s", watcher.luid, luid, logLine)
	//var config *conf.Config
	//var err error
	//// 加载配置文件
	//config, err = conf.LoadFromPath(service.Path)
	//if err != nil {
	//	return
	//}
	////if watcher.luid == 0 {
	//watcher.storedEvents = append(watcher.storedEvents, interfaceWatcherEvent{luid, windows.AF_INET})
	////	return
	////}
	//watcher.Configure(adapter, config, luid)
	//for _, peer := range config.Peers {
	//	logPeerAction("-----------------apply", peer)
	//}
	// 这里可以添加处理逻辑，例如通知某个服务 存和取的不在同一个windows service下难怪掉不通
}

func logPeerAction(action string, peer conf.Peer) {
	// 使用 Base64 编码 PublicKey
	publicKeyEncoded := base64.StdEncoding.EncodeToString(peer.PublicKey[:])
	log.Printf("%s Peer: PublicKey=%s, Endpoint=%v, AllowedIPs=%v, Flags=%d\n", action, publicKeyEncoded, peer.Endpoint, peer.AllowedIPs, peer.Flags)
}

func Run(confPath string) error {
	name, err := conf.NameFromPath(confPath)
	if err != nil {
		return err
	}
	serviceName, err := conf.ServiceNameOfTunnel(name)
	if err != nil {
		return err
	}
	return svc.Run(serviceName, &tunnelService{Path: confPath}) //最终会调用Execute()
}
