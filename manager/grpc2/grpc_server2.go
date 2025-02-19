package grpc2

import (
	"encoding/json"
	"github.com/1060279812/wireguard/windows/conf"
	pb "github.com/1060279812/wireguard/windows/manager/grpc2/proto" // 引入生成的 gRPC 代码
	"google.golang.org/grpc"
	"io"
	"log"
	"net"
	"strings"
)

var tag = "grpc_server"
var interfaceName = "kvmWg"

type server struct {
	pb.UnimplementedChatServiceServer
	callback func(config *conf.Config)
}

type Message struct {
	Text string `json:"text"`
}

// Callback 定义回调函数类型
type Callback func(config *conf.Config)

func (s *server) Chat(stream pb.ChatService_ChatServer) error {
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		message := msg.Json
		log.Printf("Received message: %s", message)

		if strings.Contains(message, "Peer") {
			log.Println("----------------已收到 peer 消息11111--------------------")

			// 定义一个Message类型的变量
			var msg Message
			err := json.Unmarshal([]byte(message), &msg)
			if err != nil {
				log.Println("JSON解析错误:", err)
			}
			// 输出解析出的text内容
			log.Printf("Received message json content: %s", msg.Text)

			cfg, _ := conf.FromWgQuick(msg.Text, interfaceName)
			if err == nil {
				log.Println("----------------已收到 peer 消息22222--------------------")
				// 调用回调函数
				if s.callback != nil {
					s.callback(cfg)
				}
			}
		} else {
			log.Println("----------------已收到 other 消息--------------------")
		}
		//var receivedMessage Message
		//if err := json.Unmarshal([]byte(msg.Json), &receivedMessage); err != nil {
		//	return err
		//}
		//
		//responseMessage := Message{Text: "Echo: " + receivedMessage.Text}
		//responseJson, err := json.Marshal(responseMessage)
		//if err != nil {
		//	return err
		//}
		//
		//response := &pb.ChatMessage{Json: string(responseJson)}
		//if err := stream.Send(response); err != nil {
		//	return err
		//}
	}
}

func StartGrpcServer(callback func(config *conf.Config)) {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	// 创建 server 实例并传入回调函数
	serverInstance := &server{
		callback: callback,
	}
	pb.RegisterChatServiceServer(s, serverInstance)
	log.Println("Server is running on port 50051")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterChatServiceServer(s, &server{})
	log.Println("Server is running on port 50051")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
