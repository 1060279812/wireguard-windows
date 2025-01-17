/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"C"
	"crypto/rand"
	"log"
	"path/filepath"
	"unsafe"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/tunnel"
)

/**
  启动 WireGuard 隧道服务。
*/

//export WireGuardTunnelService
func WireGuardTunnelService(confFile16 *uint16) bool {
	confFile := windows.UTF16PtrToString(confFile16)
	//将配置文件所在目录设置为 WireGuard 的根目录。
	conf.PresetRootDirectory(filepath.Dir(confFile))
	//强制使用固定的 GUID（全局唯一标识符），而不是基于配置文件内容的确定性 GUID。
	tunnel.UseFixedGUIDInsteadOfDeterministic = true
	//启动 WireGuard 隧道服务，并传入配置文件路径。
	err := tunnel.Run(confFile)
	if err != nil {
		log.Printf("Service run error: %v", err)
	}
	return err == nil
}

/**
  生成一对公私钥。
*/

//export WireGuardGenerateKeypair
func WireGuardGenerateKeypair(publicKey, privateKey *byte) {
	publicKeyArray := (*[32]byte)(unsafe.Pointer(publicKey))
	privateKeyArray := (*[32]byte)(unsafe.Pointer(privateKey))
	n, err := rand.Read(privateKeyArray[:])
	if err != nil || n != len(privateKeyArray) {
		panic("Unable to generate random bytes")
	}
	privateKeyArray[0] &= 248
	privateKeyArray[31] = (privateKeyArray[31] & 127) | 64

	curve25519.ScalarBaseMult(publicKeyArray, privateKeyArray)
}

func main() {}
