/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"runtime"
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

func (service *tunnelService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	// 设置服务状态为启动中
	serviceState := svc.StartPending
	changes <- svc.Status{State: serviceState}

	var watcher *interfaceWatcher
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

	var started bool
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
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

func Run(confPath string) error {
	name, err := conf.NameFromPath(confPath)
	if err != nil {
		return err
	}
	serviceName, err := conf.ServiceNameOfTunnel(name)
	if err != nil {
		return err
	}
	return svc.Run(serviceName, &tunnelService{confPath})
}
