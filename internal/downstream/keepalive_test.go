package downstream

import (
	"net"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

func TestKeepAlive(t *testing.T) {
	for _, responds := range []bool{true, false} {
		name := "closes unresponsive peer"
		if responds {
			name = "accepts unsupported request replies"
		}
		t.Run(name, func(t *testing.T) {
			host := startPasswordServer(t).host
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			requests := make(chan string, 32)
			cfg := &gossh.ServerConfig{NoClientAuth: true}
			cfg.AddHostKey(host)
			go func() {
				raw, err := listener.Accept()
				if err != nil {
					return
				}
				defer raw.Close()
				conn, _, reqs, err := gossh.NewServerConn(raw, cfg)
				if err != nil {
					return
				}
				defer conn.Close()
				for req := range reqs {
					select {
					case requests <- req.Type:
					default:
					}
					if responds {
						_ = req.Reply(false, nil)
					}
				}
			}()
			client, err := gossh.Dial("tcp", listener.Addr().String(), &gossh.ClientConfig{User: "test", HostKeyCallback: gossh.InsecureIgnoreHostKey(), Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			done := make(chan struct{})
			go func() { keepAlive(client, 10*time.Millisecond, 100*time.Millisecond); close(done) }()
			select {
			case request := <-requests:
				if request != "keepalive@openssh.com" {
					t.Fatalf("request=%q", request)
				}
			case <-time.After(time.Second):
				t.Fatal("no keepalive sent")
			}
			if responds {
				select {
				case <-done:
					t.Fatal("unsupported-request reply closed a live connection")
				case <-time.After(200 * time.Millisecond):
				}
				_ = client.Close()
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("keepalive worker did not stop")
			}
		})
	}
}
