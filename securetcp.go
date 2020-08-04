package lightsocks

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/lucas-clemente/quic-go"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

const (
	bufSize = 1024
)

// 加密传输的 TCP Socket
type SecureTCPConn struct {
	io.ReadWriteCloser
	Cipher *Cipher
}

// 从输入流里读取加密过的数据，解密后把原数据放到bs里
func (secureSocket *SecureTCPConn) DecodeRead(bs []byte) (n int, err error) {
	n, err = secureSocket.Read(bs)
	if err != nil {
		return
	}
	secureSocket.Cipher.Decode(bs[:n])
	return
}

// 把放在bs里的数据加密后立即全部写入输出流
func (secureSocket *SecureTCPConn) EncodeWrite(bs []byte) (int, error) {
	secureSocket.Cipher.Encode(bs)
	return secureSocket.Write(bs)
}

// 从src中源源不断的读取原数据加密后写入到dst，直到src中没有数据可以再读取
func (secureSocket *SecureTCPConn) EncodeCopy(dst io.ReadWriteCloser) error {
	buf := make([]byte, bufSize)
	for {
		readCount, errRead := secureSocket.Read(buf)
		if errRead != nil {
			if errRead != io.EOF {
				return errRead
			} else {
				return nil
			}
		}
		if readCount > 0 {
			writeCount, errWrite := (&SecureTCPConn{
				ReadWriteCloser: dst,
				Cipher:          secureSocket.Cipher,
			}).EncodeWrite(buf[0:readCount])
			if errWrite != nil {
				return errWrite
			}
			if readCount != writeCount {
				return io.ErrShortWrite
			}
		}
	}
}

// 从src中源源不断的读取加密后的数据解密后写入到dst，直到src中没有数据可以再读取
func (secureSocket *SecureTCPConn) DecodeCopy(dst io.Writer) error {
	buf := make([]byte, bufSize)
	for {
		readCount, errRead := secureSocket.DecodeRead(buf)
		if errRead != nil {
			if errRead != io.EOF {
				return errRead
			} else {
				return nil
			}
		}
		if readCount > 0 {
			writeCount, errWrite := dst.Write(buf[0:readCount])
			if errWrite != nil {
				return errWrite
			}
			if readCount != writeCount {
				return io.ErrShortWrite
			}
		}
	}
}

// see net.DialTCP
func DialEncryptedQuic(raddr string, cipher *Cipher) (*SecureTCPConn, error) {
	session, err := quic.DialAddr("127.0.0.1:3333",&tls.Config{InsecureSkipVerify: true,NextProtos: []string{"2222"}}, nil)
	if err != nil {
		log.Fatalln(session, err)
		return nil, err
	}

	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		fmt.Println(err)
	}

	return &SecureTCPConn{
		ReadWriteCloser: stream,
		Cipher:          cipher,
	}, nil
}
func certsetup() (serverTLSConf *tls.Config, clientTLSConf *tls.Config, err error) {
	// set up our CA certificate
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"000094016"},
			Names: []pkix.AttributeTypeAndValue{pkix.AttributeTypeAndValue{
				Type:  []int{2, 5, 4, 42},
				Value: "Gopher CA",
			}},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// create our private and public key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	// create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	// pem encode
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})

	certpool := x509.NewCertPool()
	certpool.AppendCertsFromPEM(caPEM.Bytes())

	// set up our server certificate
	serverCert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"555594016"},
			Names: []pkix.AttributeTypeAndValue{pkix.AttributeTypeAndValue{
				Type:  []int{2, 5, 4, 42},
				Value: "Gopher Server",
			}},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	serverCertPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	// 使用CA证书创建并签名服务器证书
	serverCertBytes, err := x509.CreateCertificate(rand.Reader, serverCert, ca, &serverCertPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	serverCertPEM := new(bytes.Buffer)
	pem.Encode(serverCertPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverCertBytes,
	})

	serverCertPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(serverCertPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverCertPrivKey),
	})

	servCert, err := tls.X509KeyPair(serverCertPEM.Bytes(), serverCertPrivKeyPEM.Bytes())
	if err != nil {
		return nil, nil, err
	}

	// set up our client certificate
	clientCert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"CN"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"66694016"},
			ExtraNames: []pkix.AttributeTypeAndValue{{
				Type:  []int{2, 5, 4, 22},
				Value: "Gopher Client",
			}, {
				Type:  []int{2, 5, 4, 6}, // []int{2, 5, 4, 6} 等于 Country 属性，所以会使用 GG 覆盖掉 Country 的 CN
				Value: "GG",
			}},
		},
		EmailAddresses: []string{"smith@example.com"},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().AddDate(10, 0, 0),
		SubjectKeyId:   []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:       x509.KeyUsageDigitalSignature,
	}

	clientCertPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	clientCertBytes, err := x509.CreateCertificate(rand.Reader, clientCert, ca, &clientCertPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	clientCertPEM := new(bytes.Buffer)
	pem.Encode(clientCertPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: clientCertBytes,
	})

	clientCertPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(clientCertPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(clientCertPrivKey),
	})

	cliCert, err := tls.X509KeyPair(clientCertPEM.Bytes(), clientCertPrivKeyPEM.Bytes())
	if err != nil {
		return nil, nil, err
	}

	clientCertPool := x509.NewCertPool()
	clientCertPool.AppendCertsFromPEM(clientCertPEM.Bytes())
	clientTLSConf = &tls.Config{
		RootCAs:      certpool,                   // 客户端加载 rootca，用来验证服务器证书
		Certificates: []tls.Certificate{cliCert}, // 携带客户端证书
		//InsecureSkipVerify: true,
	}

	serverTLSConf = &tls.Config{
		Certificates: []tls.Certificate{servCert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    certpool, // 加载客户端证书的ca，用来验证客户端证书
		NextProtos: []string{"2222"},
	}

	ioutil.WriteFile("ca.pem", caPEM.Bytes(), os.ModePerm)
	ioutil.WriteFile("ca_key.pem", caPrivKeyPEM.Bytes(), os.ModePerm)
	ioutil.WriteFile("server.pem", serverCertPEM.Bytes(), os.ModePerm)
	ioutil.WriteFile("server_key.pem", serverCertPrivKeyPEM.Bytes(), os.ModePerm)
	ioutil.WriteFile("client.pem", clientCertPEM.Bytes(), os.ModePerm)
	ioutil.WriteFile("client_key.pem", clientCertPrivKeyPEM.Bytes(), os.ModePerm)
	return
}

func ListenEncryptedTCP(laddr string, cipher *Cipher, handleConn func(localConn *SecureTCPConn), didListen func(listenAddr string)) error {
	lTcpAddr, err := net.ResolveTCPAddr("tcp", laddr)
	listener, err := net.ListenTCP("tcp", lTcpAddr)
	if err != nil {
		return err
	}
	defer listener.Close()

	if didListen != nil {
		// didListen 可能有阻塞操作
		go didListen(laddr)
	}

	for {
		localConn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}

		go handleConn(&SecureTCPConn{
			ReadWriteCloser: localConn,
			Cipher:          cipher,
		})
	}
}

func ListenEncryptedQuic(laddr string, cipher *Cipher, handleConn func(localConn *SecureTCPConn), didListen func(listenAddr string)) error {
	//listener, err := net.ListenTCP("tcp", laddr)
	sconfig,_,_:=certsetup()
	listener, err := quic.ListenAddr(laddr, sconfig, nil)
	if err != nil {
		return err
	}
	defer listener.Close()

	//if didListen != nil {
	//	// didListen 可能有阻塞操作
	//	go didListen(listener.Addr().(*quic.))
	//}

	for {
		sess, err := listener.Accept(context.Background())
		if err != nil {
			log.Println(err)
			continue
		}
		localConn, err := sess.AcceptStream(context.Background())
		go handleConn(&SecureTCPConn{
			ReadWriteCloser: localConn,
			Cipher:          cipher,
		})
	}
}
