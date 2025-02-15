package main

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/nxsre/lightsocks"
	"github.com/nxsre/lightsocks/cmd"
	"github.com/nxsre/lightsocks/server"
	"github.com/phayes/freeport"
)

var version = "master"

func main() {
	log.SetFlags(log.Lshortfile)

	// 优先从环境变量中获取监听端口
	port, err := strconv.Atoi(os.Getenv("LIGHTSOCKS_SERVER_PORT"))
	// 服务端监听端口随机生成
	if err != nil {
		port, err = freeport.GetFreePort()
	}
	if err != nil {
		// 随机端口失败就采用 7448
		port = 7448
	}
	// 默认配置
	config := &cmd.Config{
		ListenAddr: fmt.Sprintf(":%d", port),
		// 密码随机生成
		Password: lightsocks.RandPassword(),
	}
	config.ReadConfig()
	config.SaveConfig()

	// 启动 server 端并监听
	lsServer, err := server.NewLsServer(config.Password, ":3333")
	if err != nil {
		log.Fatalln(err)
	}
	log.Fatalln(lsServer.Listen(func(listenAddr string) {
		log.Println(fmt.Sprintf(`
lightsocks-server:%s 启动成功，配置如下：
服务监听地址：
%s
密码：
%s`, version, listenAddr, config.Password))
	}))
}
