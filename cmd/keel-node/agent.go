package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// agentMain is the `agent` command: keel-node run as "agent" (install.sh
// links /usr/local/bin/agent to it) or as "keel-node agent". It reads the
// status.json the service writes and drives the service through systemd or
// OpenRC.
func agentMain(args []string) int {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	configPath := fs.String("c", "/etc/keel/node.json", "the service's config file; status.json is next to it")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `用法: agent [命令]

  (不带命令)   显示节点状态
  restart      重启节点服务
  start/stop   启动 / 停止节点服务
  logs [-f]    看最近的日志，-f 持续跟踪
  update       从主控下载最新的节点程序并重启
  version      显示版本
`)
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	statusPath := filepath.Join(filepath.Dir(*configPath), "status.json")
	cmd, rest := "status", fs.Args()
	if len(rest) > 0 {
		cmd, rest = rest[0], rest[1:]
	}
	switch cmd {
	case "restart", "start", "stop", "update":
		if os.Geteuid() != 0 {
			fmt.Fprintln(os.Stderr, "错误: 需要 root，请用 sudo agent "+cmd)
			return 1
		}
	}
	var err error
	switch cmd {
	case "status":
		err = agentStatus(statusPath)
	case "restart", "start", "stop":
		err = serviceCtl(cmd)
		if err == nil && cmd != "stop" {
			fmt.Println("已" + map[string]string{"restart": "重启", "start": "启动"}[cmd] + "，几秒后用 agent 查看状态")
		}
	case "logs", "log":
		err = agentLogs(rest)
	case "update":
		err = agentUpdate(statusPath)
	case "version", "-v", "--version":
		fmt.Println(version, buildTime())
	case "help", "-h", "--help":
		fs.Usage()
	default:
		fs.Usage()
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		return 1
	}
	return 0
}

type initSystem string

func detectInit() initSystem {
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		if _, err := exec.LookPath("systemctl"); err == nil {
			return "systemd"
		}
	}
	if _, err := exec.LookPath("rc-service"); err == nil {
		return "openrc"
	}
	return ""
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

func serviceCtl(action string) error {
	switch detectInit() {
	case "systemd":
		return run("systemctl", action, "keel-node")
	case "openrc":
		return run("rc-service", "keel-node", action)
	}
	return errors.New("没找到 systemd 或 OpenRC")
}

// serviceActive asks the init system whether keel-node is running.
func serviceActive() (bool, initSystem) {
	init := detectInit()
	var cmd *exec.Cmd
	switch init {
	case "systemd":
		cmd = exec.Command("systemctl", "is-active", "--quiet", "keel-node")
	case "openrc":
		cmd = exec.Command("rc-service", "keel-node", "status")
	default:
		return false, init
	}
	return cmd.Run() == nil, init
}

func agentLogs(args []string) error {
	follow := len(args) > 0 && (args[0] == "-f" || args[0] == "f")
	switch detectInit() {
	case "systemd":
		a := []string{"-u", "keel-node", "-n", "100", "--no-pager"}
		if follow {
			a = append(a, "-f")
		}
		return run("journalctl", a...)
	case "openrc":
		a := []string{"-n", "100"}
		if follow {
			a = append(a, "-f")
		}
		return run("tail", append(a, "/var/log/keel-node.log")...)
	}
	return errors.New("没找到 systemd 或 OpenRC")
}

func readStatus(path string) (*NodeStatus, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s NodeStatus
	if err = json.Unmarshal(content, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

var useColor = func() bool {
	info, err := os.Stdout.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0 && os.Getenv("NO_COLOR") == ""
}()

func color(code, text string) string {
	if !useColor {
		return text
	}
	return "\033[" + code + "m" + text + "\033[0m"
}

func green(s string) string { return color("32", s) }
func red(s string) string   { return color("31", s) }
func dim(s string) string   { return color("2", s) }
func bold(s string) string  { return color("1", s) }

func agentStatus(path string) error {
	active, init := serviceActive()
	s, err := readStatus(path)
	fresh := err == nil && time.Since(time.Unix(s.Updated, 0)) < 3*statusInterval && processAlive(s.PID)
	fmt.Printf("%s  %s %s\n", bold("keel-node"), version, dim(buildDate(buildTime())))
	if errors.Is(err, os.ErrPermission) {
		// /etc/keel is root-only because it holds the node's token.
		return errors.New("没有权限读 " + path + "，请用 sudo agent")
	}
	switch {
	case fresh:
		line := fmt.Sprintf("%s · 已运行 %s · 内存 %s", green("运行中"), humanDuration(time.Since(time.Unix(s.Started, 0))), humanBytes(s.RSS))
		if s.Version != version {
			line += " · " + red("在跑的是 "+s.Version+"，重启后换成 "+version)
		}
		fmt.Println(label("服务"), line)
	case active:
		fmt.Println(label("服务"), red("在启动，但还没写出状态"), dim("（等几秒再看，或 agent logs）"))
		return nil
	default:
		msg := "没有运行"
		if init == "" {
			msg += "（没找到 systemd 或 OpenRC）"
		}
		fmt.Println(label("服务"), red(msg), dim("（agent start 启动，agent logs 看原因）"))
		return nil
	}

	if m := s.Master; m != nil {
		if m.Connected {
			line := green("已连接") + " " + m.URL + fmt.Sprintf(" · 配置版本 %d", s.ConfigRev)
			if m.LastReport > 0 {
				line += " · 上次上报 " + humanDuration(time.Since(time.Unix(m.LastReport, 0))) + "前"
			}
			fmt.Println(label("主控"), line)
		} else {
			fmt.Println(label("主控"), red("未连接")+" "+m.URL+" · "+shortError(m.Error), dim(fmt.Sprintf("（用本地缓存的配置版本 %d 照常运行）", s.ConfigRev)))
		}
	} else {
		fmt.Println(label("主控"), dim("未使用，配置来自本地文件"))
	}

	fmt.Println(label("入站"), dim("编进程序的协议: "+s.Protocols))
	if len(s.Inbounds) == 0 {
		fmt.Println("  " + dim("没有入站"))
	}
	certs := map[string]CertStatus{}
	for _, c := range s.Certs {
		certs[c.Domain] = c
	}
	for _, in := range s.Inbounds {
		state := green("运行中")
		if !in.Running {
			state = red("没起来: " + in.Error)
		}
		detail := ""
		switch {
		case in.Type == "vless" && len(in.ServerNames) > 0:
			detail = "Reality SNI " + strings.Join(in.ServerNames, ", ")
		case in.Type == "anytls" && in.ServerName != "":
			detail = "域名 " + in.ServerName
		}
		if in.ACME {
			if c, ok := certs[in.ServerName]; ok {
				detail += " · " + certLine(c)
			}
		} else if in.Type == "anytls" {
			detail += dim(" · 证书非自动申请")
		}
		fmt.Printf("  %-7s %-22s %s  %s\n", in.Type, in.Listen, state, strings.TrimPrefix(detail, " · "))
	}

	if len(s.Outbounds) > 0 {
		fmt.Println(label("出口"))
		for _, o := range s.Outbounds {
			if o.Alive {
				latency := ""
				if o.CheckedAt > 0 {
					latency = fmt.Sprintf(" %.0f ms", o.LatencyMs)
				}
				fmt.Printf("  %-8s %s%s\n", o.Tag, green("正常"), latency)
			} else {
				fmt.Printf("  %-8s %s  %s\n", o.Tag, red("不通"), dim(o.Error))
			}
		}
	}

	users := fmt.Sprintf("%d 个 · 连接 %d", s.Users, s.Conns)
	if s.Blocked > 0 {
		users += " · " + red(fmt.Sprintf("%d 个超额或到期", s.Blocked))
	}
	fmt.Println(label("用户"), users)

	if len(s.Probes) > 0 {
		names := map[string]string{"ct": "电信", "cu": "联通", "cm": "移动"}
		var parts []string
		for _, p := range s.Probes {
			name := names[p.Name]
			if name == "" {
				name = p.Name
			}
			if p.LossPct >= 100 {
				parts = append(parts, name+" "+red("不通"))
				continue
			}
			part := fmt.Sprintf("%s %.0f ms", name, p.LatencyMs)
			if p.LossPct > 0 {
				part += red(fmt.Sprintf(" 丢包 %.0f%%", p.LossPct))
			}
			parts = append(parts, part)
		}
		fmt.Println(label("三网"), strings.Join(parts, "   "))
	}
	return nil
}

func label(s string) string { return bold(s) }

// shortError keeps the last part of a wrapped Go error ("dial tcp ...:
// connect: connection refused" -> "connection refused").
func shortError(s string) string {
	if i := strings.LastIndex(s, ": "); i >= 0 && i+2 < len(s) {
		return s[i+2:]
	}
	return s
}

func certLine(c CertStatus) string {
	if c.Issuer == "acme" {
		line := "证书 " + green("已签发")
		if c.NotAfter > 0 {
			line += "，" + time.Unix(c.NotAfter, 0).Format("2006-01-02") + " 到期（提前 30 天自动续）"
		}
		return line
	}
	if c.Error != "" {
		line := "证书 " + red("申请失败: "+c.Error)
		if c.NextTry > 0 {
			line += dim("，" + humanDuration(time.Until(time.Unix(c.NextTry, 0))) + "后重试")
		}
		return line
	}
	return "证书 申请中（先用自签证书）"
}

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func buildDate(t string) string {
	if parsed, err := time.Parse(time.RFC3339, t); err == nil {
		return "（" + parsed.Local().Format("2006-01-02 15:04") + " 提交）"
	}
	return ""
}

func humanDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d 秒", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d 分钟", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d 小时 %d 分钟", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%d 天 %d 小时", int(d.Hours())/24, int(d.Hours())%24)
}

func humanBytes(n uint64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	}
	return fmt.Sprintf("%d KB", n>>10)
}

// agentUpdate downloads keel-node from the master the service talks to,
// checks that it runs, swaps it in and restarts the service.
func agentUpdate(statusPath string) error {
	s, err := readStatus(statusPath)
	if err != nil || s.Master == nil || s.Master.URL == "" {
		return errors.New("不知道主控地址（服务要先跑起来并连着主控）")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	pin, err := parseFingerprint(s.Master.Fingerprint)
	if err != nil {
		return err
	}
	url := strings.TrimSuffix(s.Master.URL, "/") + "/dl/keel-node-linux-" + runtime.GOARCH
	fmt.Println("下载", url)
	client := &http.Client{Timeout: 5 * time.Minute, Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment, TLSClientConfig: (&masterClient{pin: pin}).tlsConfig(),
	}}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败: HTTP %d", resp.StatusCode)
	}
	tmp := self + ".new"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, resp.Body)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, tmp, "agent", "version").Output()
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("下载的程序跑不起来: %w", err)
	}
	newVersion := strings.Fields(string(out))
	if len(newVersion) > 0 && newVersion[0] == s.Version && !strings.Contains(s.Version, "dirty") {
		os.Remove(tmp)
		fmt.Println("已经是最新版本", s.Version)
		return nil
	}
	if err = os.Rename(tmp, self); err != nil {
		os.Remove(tmp)
		return err
	}
	fmt.Printf("%s → %s，重启服务\n", s.Version, strings.TrimSpace(string(out)))
	return serviceCtl("restart")
}
