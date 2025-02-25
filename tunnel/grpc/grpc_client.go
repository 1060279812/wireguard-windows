package grpc

import (
	"context"
	"encoding/json"
	"github.com/1060279812/wireguard/windows/conf"
	"log"
	"strings"
	"time"

	pb "github.com/1060279812/wireguard/windows/tunnel/grpc/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

// Callback 定义回调函数类型
//type Callback func(config *conf.Config)

const (
	address         = "localhost:50056"
	reconnectPeriod = 5 * time.Second
)

type Message struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

var (
	client *GrpcClient
)

const (
	MESSAGE_TYPE_WIREGUARD_CONFIG = "configuration"
	MESSAGE_TYPE_STOP_SERVER      = "stop_server"
	interfaceName                 = "kvmWg"
)

type GrpcClient struct {
	conn           *grpc.ClientConn
	client         pb.ChatServiceClient
	stream         pb.ChatService_ChatClient
	address        string
	isShuttingDown bool
}

func NewGrpcClient(address string) *GrpcClient {
	return &GrpcClient{address: address}
}

func (c *GrpcClient) Connect() error {
	var err error
	c.conn, err = grpc.Dial(c.address, grpc.WithInsecure(), grpc.WithBlock(), grpc.WithTimeout(5*time.Second))
	if err != nil {
		return err
	}
	c.client = pb.NewChatServiceClient(c.conn)
	c.stream, err = c.client.Chat(context.Background())
	return err
}

func (c *GrpcClient) monitorConnection() {
	for {
		if c.isShuttingDown {
			//log.Println("stop monitorConnection...")
			return
		}
		state := c.conn.GetState()
		if state == connectivity.TransientFailure || state == connectivity.Shutdown {
			//log.Println("Connection lost. Reconnecting...")
			for {
				if c.conn.GetState() == connectivity.Ready {
					//log.Println("Reconnected to server.")
					break
				}
				time.Sleep(reconnectPeriod)
				if err := c.Connect(); err == nil {
					break
				}
			}
		}
		time.Sleep(reconnectPeriod)
	}
}

func (c *GrpcClient) receiveMessages(callback func(config *conf.Config)) {
	for {
		in, err := c.stream.Recv()
		if err != nil {
			log.Fatalf("Failed to receive a message: %v", err)
		}
		var message Message
		if err := json.Unmarshal([]byte(in.Json), &message); err != nil {
			//log.Printf("Failed to unmarshal JSON: %v", err)
		} else {
			//log.Printf("Received message [%s]: %s", message.Type, message.Text)

			if strings.EqualFold(message.Type, MESSAGE_TYPE_WIREGUARD_CONFIG) {
				cfg, err := conf.FromWgQuick(message.Text, interfaceName)
				if err == nil {
					callback(cfg)
					c.SendMessage("response", "----------------已收到 peer消息 success--------------------")
				} else {
					c.SendMessage("response", "----------------已收到 peer消息 err--------------------")
					//log.Fatalf("FromWgQuick err: %v", err)
				}
			} else if strings.EqualFold(message.Type, MESSAGE_TYPE_STOP_SERVER) {
				c.SendMessage("response", "----------------已收到 stop server消息--------------------")
				time.Sleep(100 * time.Millisecond)
				StopGrpcClient()
			}
		}
	}
}

func (c *GrpcClient) SendMessage(messageType, text string) {
	message := Message{Type: messageType, Text: text}
	jsonMessage, err := json.Marshal(message)
	if err != nil {
		log.Fatalf("Failed to marshal JSON: %v", err)
	}
	err = c.stream.Send(&pb.ChatMessage{Json: string(jsonMessage), Type: messageType})
	if err != nil {
		log.Fatalf("Failed to send a message: %v", err)
	}
}

func StartGrpcClient(callback func(config *conf.Config)) *GrpcClient {
	client = NewGrpcClient(address)
	if err := client.Connect(); err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}

	go client.monitorConnection()
	go client.receiveMessages(callback)
	//
	//for {
	//	time.Sleep(5 * time.Second)
	//	client.SendMessage("regular", "定期消息: "+time.Now().String())
	//}

	return client
}

func StopGrpcClient() {
	if client != nil {
		client.isShuttingDown = true
		if client.conn.GetState() == connectivity.Connecting {
			//err := client.stream.CloseSend()
			//if err != nil {
			//	return
			//}
			err := client.conn.Close()
			if err != nil {
				return
			}
			log.Println("StopGrpcClient...")
		}
	}
}
