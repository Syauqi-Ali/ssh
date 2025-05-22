package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/creack/pty"
	"github.com/fatih/color"
	"github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

type Config struct {
	SSH struct {
		Port     string `yaml:"port"`
		User     string `yaml:"user"`
		Password string `yaml:"password"`
		Timeout  int    `yaml:"timeout"`
	} `yaml:"ssh"`
	SFTP struct {
		Enable bool `yaml:"enable"`
	} `yaml:"sftp"`
}

var (
	config     Config
	configPath = "/ssh_config.yml"
)

func setWinsize(f *os.File, w, h int) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
}

func createDefaultConfig() error {
	defaultConfig := Config{}
	defaultConfig.SSH.Port = "2222"
	defaultConfig.SSH.User = "root"
	defaultConfig.SSH.Password = "password"
	defaultConfig.SSH.Timeout = 300
	defaultConfig.SFTP.Enable = true

	yamlData, err := yaml.Marshal(&defaultConfig)
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, yamlData, 0644)
}

func loadConfig() error {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		color.Yellow("Configuration file not found. Creating default config at %s", configPath)
		if err := createDefaultConfig(); err != nil {
			color.Red("Error creating default config: %v", err)
			return err
		}
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		color.Red("Error reading config file: %v", err)
		return err
	}

	if err := yaml.Unmarshal(content, &config); err != nil {
		color.Red("Error parsing config: %v", err)
		return err
	}

	return nil
}

func sftpHandler(sess ssh.Session) {
	debugStream := io.Discard
	serverOptions := []sftp.ServerOption{
		sftp.WithDebug(debugStream),
	}
	server, err := sftp.NewServer(sess, serverOptions...)
	if err != nil {
		color.Red("SFTP server init error: %s", err)
		return
	}
	if err := server.Serve(); err == io.EOF {
		server.Close()
		color.Green("SFTP client exited session.")
	} else if err != nil {
		color.Red("SFTP server completed with error: %s", err)
	}
}

func logLoginAttempt(ip, user string, success bool, method string) {
	timestamp := time.Now().Format(time.RFC3339)
	logEntry := fmt.Sprintf("%s - IP: %s, User: %s, Method: %s, Success: %v", timestamp, ip, user, method, success)

	if success {
		color.Green(logEntry)
		cmd := exec.Command("source ~/.profile")
	} else {
		color.Red(logEntry)
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		color.Red("Error getting home directory: %v", err)
		return
	}

	logFile := filepath.Join(homeDir, "ssh.log")
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		color.Red("Error opening log file: %v", err)
		return
	}
	defer f.Close()

	if _, err := f.WriteString(logEntry + "\n"); err != nil {
		color.Red("Error writing to log file: %v", err)
	}
}

func handleSession(s ssh.Session) {
	cmd := exec.Command("sh")
	ptyReq, winCh, isPty := s.Pty()
	if isPty {
		cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
		f, err := pty.Start(cmd)
		if err != nil {
			color.Red("Error starting pty: %v", err)
			io.WriteString(s, fmt.Sprintf("Error starting pty: %v\n", err))
			s.Exit(1)
			return
		}
		go func() {
			for win := range winCh {
				setWinsize(f, win.Width, win.Height)
			}
		}()
		go func() {
			io.Copy(f, s)
		}()
		io.Copy(s, f)
		cmd.Wait()
	} else {
		io.WriteString(s, "No PTY requested.\n")
		s.Exit(1)
	}
}

func isBcryptHash(str string) bool {
	return strings.HasPrefix(str, "$2a$") || strings.HasPrefix(str, "$2b$") || strings.HasPrefix(str, "$2y$")
}

func checkPassword(storedPassword, inputPassword string) bool {
	if isBcryptHash(storedPassword) {
		err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(inputPassword))
		return err == nil
	}
	return storedPassword == inputPassword
}

func main() {
	if err := loadConfig(); err != nil {
		color.Red("Failed to load configuration: %v", err)
		os.Exit(1)
	}

	if config.SSH.Port == "" {
		config.SSH.Port = "2222"
	}

	var sshTimeout time.Duration
	if config.SSH.Timeout > 0 {
		sshTimeout = time.Duration(config.SSH.Timeout) * time.Second
	}

	isPasswordHashed := isBcryptHash(config.SSH.Password)

	server := &ssh.Server{
		Addr: ":" + config.SSH.Port,
		PasswordHandler: func(ctx ssh.Context, pass string) bool {
			success := config.SSH.User == ctx.User() && checkPassword(config.SSH.Password, pass)
			logLoginAttempt(ctx.RemoteAddr().String(), ctx.User(), success, "password")
			return success
		},
	}

	if config.SFTP.Enable {
		server.SubsystemHandlers = map[string]ssh.SubsystemHandler{
			"sftp": sftpHandler,
		}
	}

	if config.SSH.Password == "" {
		server.PasswordHandler = nil
	}

	server.Handle(handleSession)

	if sshTimeout > 0 {
		server.MaxTimeout = sshTimeout
		server.IdleTimeout = sshTimeout
		color.Yellow("SSH server configured with:")
		color.Yellow("  - Max connection duration: %s", sshTimeout)
		color.Yellow("  - Idle timeout: %s", sshTimeout)
	}

	color.Yellow("  - User: %s", config.SSH.User)
	if isPasswordHashed {
		color.Yellow("  - Password is hashed with bcrypt")
	}
	color.Yellow("  - SFTP enabled: %v", config.SFTP.Enable)
	color.Blue("Starting SSH server on port %s...", config.SSH.Port)
	color.Yellow("  - Type 'q' to exit.")

	go func() {
		log.Fatal(server.ListenAndServe())
	}()

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "q" {
			color.Yellow("Exit command detected. Stopping SSH server.")
			os.Exit(0)
		}
	}
}
