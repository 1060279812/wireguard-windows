package grpc

import (
	"context"
	"encoding/json"
	"github.com/1060279812/wireguard/windows/conf"
	pb "github.com/1060279812/wireguard/windows/manager/grpc/proto" // 引入生成的 gRPC 代码
	"google.golang.org/grpc"
	"io"
	"log"
	"strings"
	"sync"
)

type MessageStruct struct {
	Type    string `json:"type"`
	Message int    `json:"message"`
}

var (
	conn    *grpc.ClientConn
	wg      sync.WaitGroup
	stopCh  = make(chan struct{})
	stopped = false
)

var tag = "grpc_server"
var interfaceName = "kvmWg"

// Callback 定义回调函数类型
type Callback func(config *conf.Config)

func StartGrpcClient(callback func(config *conf.Config)) {
	var err error
	conn, err = grpc.Dial("localhost:50085", grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatalf("无法连接服务器: %v", err)
	}

	client := pb.NewCommunicationServiceClient(conn)

	// 创建双向流
	stream, err := client.Chat(context.Background())
	if err != nil {
		log.Fatalf("无法创建流: %v", err)
	}

	wg.Add(1)
	// 启动接收消息的协程
	go receiveMessages(stream, callback)

	//for i := 0; i < 10000; i++ {
	//	// 发送消息
	//	sendMessage(stream, []map[string]string{
	//		{"type": "1", "message": "Hello from Golang client 1!"},
	//	})
	//	time.Sleep(time.Second * 5)
	//}
	// 等待接收消息的协程结束
	wg.Wait()

	// 主动断开连接
	Disconnect()
}

func sendMessage(stream pb.CommunicationService_ChatClient, messages []map[string]string) {
	for _, message := range messages {
		jsonMessage, _ := json.Marshal(message)
		req := &pb.MessageRequest{JsonMessage: string(jsonMessage)}
		if err := stream.Send(req); err != nil {
			log.Fatalf("发送消息失败: %v", err)
		}
		log.Printf("发送消息: %s", req.JsonMessage)
	}
}

func receiveMessages(stream pb.CommunicationService_ChatClient, callback func(config *conf.Config)) {
	defer wg.Done()
	for {
		select {
		case <-stopCh:
			log.Println("接收消息的协程停止")
			sendMessage(stream, []map[string]string{
				{"type": "400", "message": "...................接收消息的协程停止..............."},
			})
			return
		default:
			res, err := stream.Recv()
			if err == io.EOF {
				log.Println("流已关闭")
				sendMessage(stream, []map[string]string{
					{"type": "103", "message": "...................流已关闭..............."},
				})
			}
			if err != nil {
				log.Fatalf("接收消息失败: %v", err)
				sendMessage(stream, []map[string]string{
					{"type": "101", "message": "...................接收消息失败..............."},
				})
			}
			message := res.JsonMessage
			log.Printf("接收到的消息: %s", message)
			sendMessage(stream, []map[string]string{
				{"type": "200", "message": message},
			})
			if strings.Contains(message, "Peer") {
				cfg, err := conf.FromWgQuick(message, interfaceName)
				if err == nil {
					callback(cfg)
					log.Println("----------------已收到 peer消息 1111--------------------")
					sendMessage(stream, []map[string]string{
						{"type": "200", "message": "----------------已收到 peer消息--------------------"},
					})
				} else {
					sendMessage(stream, []map[string]string{
						{"type": "400", "message": "----------------已收到 peer消息--------------------"},
					})
					log.Fatalf("FromWgQuick err: %v", err)
				}
			}
		}
	}
}

func Disconnect() {
	if !stopped {
		close(stopCh)
		conn.Close()
		stopped = true
		log.Println("已主动断开连接")
	}
}
