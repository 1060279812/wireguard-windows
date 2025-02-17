/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package winipcfg

import (
	"sync"

	"golang.org/x/sys/windows"
)

// InterfaceChangeCallback structure allows interface change callback handling.
type InterfaceChangeCallback struct {
	cb   func(notificationType MibNotificationType, iface *MibIPInterfaceRow)
	wait sync.WaitGroup
}

var (
	interfaceChangeAddRemoveMutex = sync.Mutex{}
	interfaceChangeMutex          = sync.Mutex{}
	interfaceChangeCallbacks      = make(map[*InterfaceChangeCallback]bool)
	interfaceChangeHandle         = windows.Handle(0)
)

// RegisterInterfaceChangeCallback registers a new InterfaceChangeCallback. If this particular callback is already
// registered, the function will silently return. Returned InterfaceChangeCallback.Unregister method should be used
// to unregister.
func RegisterInterfaceChangeCallback(callback func(notificationType MibNotificationType, iface *MibIPInterfaceRow)) (*InterfaceChangeCallback, error) {
	// 创建一个新的 InterfaceChangeCallback 结构体，保存回调函数
	s := &InterfaceChangeCallback{cb: callback}

	// 加锁，防止同时添加或删除回调函数
	interfaceChangeAddRemoveMutex.Lock()
	defer interfaceChangeAddRemoveMutex.Unlock()

	// 加锁，防止同时执行回调函数
	interfaceChangeMutex.Lock()
	defer interfaceChangeMutex.Unlock()

	// 将新的回调函数添加到回调函数列表中
	interfaceChangeCallbacks[s] = true

	// 如果回调句柄为空，则注册接口变化通知
	if interfaceChangeHandle == 0 {
		// 注册接口变化通知，将 interfaceChanged 函数作为回调
		err := notifyIPInterfaceChange(windows.AF_UNSPEC, windows.NewCallback(interfaceChanged), 0, false, &interfaceChangeHandle)
		if err != nil {
			// 如果注册失败，则删除刚刚添加的回调函数，并将句柄设为0
			delete(interfaceChangeCallbacks, s)
			interfaceChangeHandle = 0
			return nil, err
		}
	}

	// 返回新的回调结构体
	return s, nil
}

// Unregister unregisters the callback.
func (callback *InterfaceChangeCallback) Unregister() error {
	// 加锁，防止同时添加或删除回调函数
	interfaceChangeAddRemoveMutex.Lock()
	defer interfaceChangeAddRemoveMutex.Unlock()

	// 加锁，防止同时执行回调函数
	interfaceChangeMutex.Lock()
	// 从回调函数列表中删除该回调函数
	delete(interfaceChangeCallbacks, callback)
	// 检查是否需要移除接口变化通知
	removeIt := len(interfaceChangeCallbacks) == 0 && interfaceChangeHandle != 0
	interfaceChangeMutex.Unlock()

	// 等待所有回调函数执行完毕
	callback.wait.Wait()

	// 如果需要移除接口变化通知，则取消注册
	if removeIt {
		err := cancelMibChangeNotify2(interfaceChangeHandle)
		if err != nil {
			return err
		}
		interfaceChangeHandle = 0
	}

	return nil
}

func interfaceChanged(callerContext uintptr, row *MibIPInterfaceRow, notificationType MibNotificationType) uintptr {
	// 创建接口行的副本
	rowCopy := *row
	// 加锁，防止同时执行回调函数
	interfaceChangeMutex.Lock()
	// 遍历所有注册的回调函数，并异步执行它们
	for cb := range interfaceChangeCallbacks {
		cb.wait.Add(1)
		go func(cb *InterfaceChangeCallback) {
			cb.cb(notificationType, &rowCopy)
			cb.wait.Done()
		}(cb)
	}
	interfaceChangeMutex.Unlock()
	return 0
}
