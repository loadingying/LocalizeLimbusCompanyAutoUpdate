//go:build windows

package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows/registry"
)

// ===============================
// 内置 7za.exe（需放置 assets/7za.exe）
// ===============================

//go:embed assets/7za.exe
var embedded7za []byte

func extractEmbedded7za() (string, error) {
	tmpDir := filepath.Join(os.TempDir(), "limbus_7za")
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}
	zaPath := filepath.Join(tmpDir, "7za.exe")
	if st, err := os.Stat(zaPath); err == nil && int(st.Size()) == len(embedded7za) {
		return zaPath, nil
	}
	if err := os.WriteFile(zaPath, embedded7za, 0755); err != nil {
		return "", fmt.Errorf("write 7za.exe: %w", err)
	}
	return zaPath, nil
}

// ===============================
// 配置 & 常量
// ===============================

type Config struct {
	GamePath      string `json:"gamePath"`
	APIVersionURL string `json:"apiVersionUrl"`
	APIHashURL    string `json:"apiHashUrl"`
	SevenZipPath  string `json:"sevenZipPath"`
	DownloadURL   string `json:"downloadUrl,omitempty"`
}

type VersionInfo struct {
	Version int    `json:"version"`
	Notice  string `json:"notice"`
}

type HashInfo struct {
	FontHash string `json:"font_hash"`
	MainHash string `json:"main_hash"`
}

const (
	taskName          = "LimbusCompanyChineseUpdate"
	configFile        = "config.json"
	executable        = "LimbusCompany.exe"
	lockFile          = "updater.lock"
	logFile           = "updater.log"
	fontURLPrimary    = "https://raw.githubusercontent.com/LocalizeLimbusCompany/LocalizeLimbusCompany/refs/heads/main/Fonts/LLCCN-Font.7z"
	fontURLFallback   = "https://download.zeroasso.top/files/LLCCN-Font.7z"
	fontPath          = "LimbusCompany_Data/Lang/LLC_zh-CN/Font/Context/ChineseFont.ttf"
	mainURLPrimary    = "https://download.zeroasso.top/files/LimbusLocalize_%d.7z"                                                 // 模板1
	mainURLFallback   = "https://github.com/LocalizeLimbusCompany/LocalizeLimbusCompany/releases/download/%d/LimbusLocalize_%d.7z" // 模板2
	defaultVersionAPI = "https://api.zeroasso.top/v2/resource/get_version"
	defaultHashAPI    = "https://api.zeroasso.top/v2/hash/get_hash"
	appID             = "1973530" // Limbus Company
)

var (
	globalConfig Config
	showHelp     bool
	logWriter    *os.File
	logMutex     sync.Mutex
	updated      bool
)

// ===============================
// 入口
// ===============================

func main() {
	register := flag.Bool("register", false, "注册自动更新任务")
	unregister := flag.Bool("unregister", false, "注销自动更新任务")
	flag.BoolVar(&showHelp, "h", false, "显示帮助信息")
	flag.Parse()

	initLog()
	defer func() {
		if logWriter != nil {
			_ = logWriter.Close()
		}
	}()

	logf("== 程序启动 [%s] ==", time.Now().Format("2006-01-02 15:04:05"))

	if showHelp {
		printHelp()
		return
	}
	if !hasPowerShell() {
		logf("错误: 系统未找到 PowerShell")
		return
	}
	if err := loadConfig(); err != nil {
		logf("加载配置失败: %v", err)
		return
	}
	if err := ensure7zAvailable(); err != nil {
		logf("7za 初始化失败: %v", err)
		return
	}
	if err := validateGamePath(); err != nil {
		logf("游戏路径验证失败: %v", err)
		return
	}

	switch {
	case *unregister:
		logf("执行注销任务操作")
		unregisterTask()
	case *register:
		logf("执行注册任务操作")
		registerTask()
	default:
		logf("执行更新检查")
		runUpdate()
	}
}

// ===============================
// 日志 & 配置
// ===============================

func initLog() {
	if _, err := os.Stat(logFile); err == nil {
		_ = os.Remove(logFile + "_prev")
		_ = os.Rename(logFile, logFile+"_prev")
	}
	f, err := os.Create(logFile)
	if err != nil {
		fmt.Printf("创建日志文件失败: %v\n", err)
		return
	}
	logWriter = f
}

func logf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("[%s] %s", time.Now().Format("2006-01-02 15:04:05"), msg)
	logMutex.Lock()
	defer logMutex.Unlock()
	fmt.Println(line)
	if logWriter != nil {
		_, _ = fmt.Fprintln(logWriter, line)
	}
}

func loadConfig() error {
	data, err := os.ReadFile(configFile)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		logf("未找到配置文件，写入默认配置")
		globalConfig = Config{
			GamePath:      "",
			APIVersionURL: defaultVersionAPI,
			APIHashURL:    defaultHashAPI,
			SevenZipPath:  "",
			DownloadURL:   mainURLPrimary,
		}
		return os.WriteFile(configFile, []byte(marshalConfig(globalConfig)), 0644)
	}
	if err := json.Unmarshal(data, &globalConfig); err != nil {
		return err
	}
	if globalConfig.APIVersionURL == "" {
		globalConfig.APIVersionURL = defaultVersionAPI
	}
	if globalConfig.APIHashURL == "" {
		globalConfig.APIHashURL = defaultHashAPI
	}
	if globalConfig.DownloadURL == "" {
		globalConfig.DownloadURL = mainURLPrimary
	}
	return nil
}

func saveConfig() error {
	return os.WriteFile(configFile, []byte(marshalConfig(globalConfig)), 0644)
}

func marshalConfig(c Config) string {
	b, _ := json.MarshalIndent(c, "", "  ")
	return string(b)
}

// ===============================
// 7-Zip 初始化与执行（精简参数版）
// ===============================

func ensure7zAvailable() error {
	p, err := extractEmbedded7za()
	if err != nil {
		return fmt.Errorf("释放内置7za失败: %v", err)
	}
	if err := test7z(p); err != nil {
		return fmt.Errorf("内置7za自检失败: %v", err)
	}
	globalConfig.SevenZipPath = p
	logf("使用内置 7za: %s", p)
	_ = saveConfig()
	return nil
}

func test7z(za string) error {
	cmd := exec.Command(za, "i")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	_ = cmd.Run() // 某些环境可能非0，但只要输出包含 7-Zip 即通过
	if strings.Contains(strings.ToLower(out.String()), "7-zip") {
		return nil
	}
	return fmt.Errorf("7za i 输出异常: %s", out.String())
}

// 运行 7z 并把输出写日志；出现 0 文件或 “No files to process” 判失败
func runAndLogWithExtractCheck(cmd *exec.Cmd, title string) error {
	var buf bytes.Buffer
	mw := io.MultiWriter(os.Stdout, &buf)
	cmd.Stdout, cmd.Stderr = mw, mw

	logf("执行命令: %s", cmd.String())
	err := cmd.Run()
	out := buf.String()

	for _, line := range strings.Split(out, "\n") {
		if s := strings.TrimRight(line, "\r\n"); s != "" {
			logf("[7z] %s", s)
		}
	}

	low := strings.ToLower(out)
	if strings.Contains(low, "no files to process") {
		return fmt.Errorf("%s 失败：7-Zip 显示 No files to process（未匹配到任何待解文件）", title)
	}
	// 扫描统计行中是否出现 Files: 0
	if idx := strings.LastIndex(low, "files:"); idx != -1 {
		tail := strings.TrimSpace(low[idx+len("files:"):])
		// 取开头数字
		n := 0
		for i := 0; i < len(tail); i++ {
			if tail[i] < '0' || tail[i] > '9' {
				break
			}
			n = n*10 + int(tail[i]-'0')
		}
		if n == 0 {
			return fmt.Errorf("%s 失败：解压结果为 0 个文件", title)
		}
	}

	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("%s 失败: exitcode=%d", title, ee.ExitCode())
		}
		return fmt.Errorf("%s 失败: %v", title, err)
	}
	return nil
}

// 列目录（-slt）写入日志，便于定位包结构
func listArchive(za, archive string) {
	cmd := exec.Command(za, "l", "-slt", archive)
	_ = runAndLogWithExtractCheck(cmd, "列出压缩包内容")
}

// 统一的极简解压：x -y -aoa -o<dest> <archive>
func extractArchive(za, archive, dest string, title string) error {
	if err := os.MkdirAll(dest, 0755); err != nil {
		return fmt.Errorf("创建目标目录失败: %v", err)
	}
	cmd := exec.Command(
		za, "x",
		"-y", "-aoa",
		"-o"+dest, // -o 和路径之间不能有空格
		archive,
	)
	return runAndLogWithExtractCheck(cmd, title)
}

// ===============================
// Steam 路径发现（基础）
// ===============================

func FindLimbusCompanyPath() (string, error) {
	root, _ := regGetString(registry.CURRENT_USER, `Software\Valve\Steam`, "SteamPath")
	if root == "" {
		root, _ = regGetString(registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Valve\Steam`, "InstallPath")
	}
	if root == "" {
		return "", errors.New("未在注册表找到 Steam 安装路径")
	}
	root = filepath.Clean(strings.ReplaceAll(root, `/`, `\`))

	libs := []string{root}
	// 解析 libraryfolders.vdf
	vdf := filepath.Join(root, "steamapps", "libraryfolders.vdf")
	libs = append(libs, parseLibraryFolders(vdf)...)

	seen := map[string]bool{}
	for _, lib := range libs {
		lib = filepath.Clean(lib)
		if seen[lib] {
			continue
		}
		seen[lib] = true

		steamapps := filepath.Join(lib, "steamapps")
		// 优先从 manifest 读 installdir
		acf := filepath.Join(steamapps, "appmanifest_"+appID+".acf")
		if dir := parseInstalldir(acf); dir != "" {
			full := filepath.Join(steamapps, "common", dir)
			if existsDir(full) && existsFile(filepath.Join(full, executable)) {
				return full, nil
			}
		}
		// 回退到固定名称
		fallback := filepath.Join(steamapps, "common", "Limbus Company")
		if existsDir(fallback) && existsFile(filepath.Join(fallback, executable)) {
			return fallback, nil
		}
	}
	return "", errors.New("未在任何库中找到 Limbus Company")
}

func regGetString(root registry.Key, path, name string) (string, error) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer k.Close()
	s, _, err := k.GetStringValue(name)
	return s, err
}

func parseLibraryFolders(file string) []string {
	f, err := os.Open(file)
	if err != nil {
		return nil
	}
	defer f.Close()
	re := regexp.MustCompile(`(?i)"path"\s*"([^"]+)"`)
	var out []string
	b, _ := io.ReadAll(f)
	for _, m := range re.FindAllStringSubmatch(string(b), -1) {
		p := strings.ReplaceAll(m[1], `\\`, `\`)
		p = filepath.Clean(strings.ReplaceAll(p, `/`, `\`))
		out = append(out, p)
	}
	return out
}

func parseInstalldir(acf string) string {
	b, err := os.ReadFile(acf)
	if err != nil {
		return ""
	}
	re := regexp.MustCompile(`(?i)"installdir"\s*"([^"]+)"`)
	if m := re.FindSubmatch(b); len(m) == 2 {
		return strings.ReplaceAll(string(m[1]), `\\`, `\`)
	}
	return ""
}

func existsDir(p string) bool  { fi, err := os.Stat(p); return err == nil && fi.IsDir() }
func existsFile(p string) bool { fi, err := os.Stat(p); return err == nil && !fi.IsDir() }

// ===============================
// 系统 & 计划任务
// ===============================

func hasPowerShell() bool { _, err := exec.LookPath("powershell"); return err == nil }

func isAdmin() bool {
	f, err := os.Open(`\\.\PHYSICALDRIVE0`)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

func registerTask() {
	if !isAdmin() {
		logf("错误: 注册计划任务需要管理员权限")
		return
	}
	exePath, err := os.Executable()
	if err != nil {
		logf("获取可执行文件路径失败: %v", err)
		return
	}
	workDir := filepath.Dir(exePath)
	script := fmt.Sprintf(`
if (Get-ScheduledTask -TaskName "%s" -ErrorAction SilentlyContinue) {
  Unregister-ScheduledTask -TaskName "%s" -Confirm:$false
  Start-Sleep -Seconds 1
}
$action = New-ScheduledTaskAction -Execute "%s" -WorkingDirectory "%s"
$logonTrigger = New-ScheduledTaskTrigger -AtLogOn
$dailyTrigger = New-ScheduledTaskTrigger -Daily -At 3am
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -RunOnlyIfNetworkAvailable
Register-ScheduledTask -TaskName "%s" -Action $action -Settings $settings -Trigger $logonTrigger, $dailyTrigger -Description "自动更新LimbusCompany汉化包"
`, taskName, taskName, exePath, workDir, taskName)
	if err := runPowerShell(script); err != nil {
		logf("注册任务失败: %v", err)
	} else {
		logf("计划任务注册成功")
	}
}

func unregisterTask() {
	script := fmt.Sprintf(`Unregister-ScheduledTask -TaskName "%s" -Confirm:$false -ErrorAction SilentlyContinue`, taskName)
	if err := runPowerShell(script); err != nil {
		logf("移除计划任务失败: %v", err)
	} else {
		logf("计划任务已移除")
	}
}

func runPowerShell(script string) error {
	logf("执行PowerShell脚本:\n%s", script)
	ps := exec.Command("powershell", "-Command", script)
	ps.Stdout, ps.Stderr = os.Stdout, os.Stderr
	return ps.Run()
}

// ===============================
// 更新流程
// ===============================

func validateGamePath() error {
	if p := strings.TrimSpace(globalConfig.GamePath); p != "" {
		if existsFile(filepath.Join(p, executable)) {
			logf("使用配置中的游戏路径: %s", p)
			return nil
		}
		logf("配置中的游戏路径无效: %s", p)
	}
	logf("尝试自动查找游戏路径...")
	path, err := FindLimbusCompanyPath()
	if err != nil {
		return err
	}
	globalConfig.GamePath = path
	if err := saveConfig(); err != nil {
		logf("保存配置失败（忽略）: %v", err)
	}
	logf("找到游戏路径: %s", path)
	return nil
}

func runUpdate() {
	lockPath := filepath.Join(os.TempDir(), lockFile)
	if isRunning(lockPath) {
		logf("已有实例在运行，退出")
		return
	}
	defer createLockFile(lockPath)()

	localVer, err := getLocalVersion()
	if err != nil {
		logf("获取本地版本失败: %v", err)
		return
	}
	remoteVer, err := getRemoteVersion()
	if err != nil {
		logf("获取远程版本失败: %v", err)
		return
	}
	if remoteVer.Version > localVer.Version {
		logf("发现新版本: %d（当前: %d）", remoteVer.Version, localVer.Version)
		if err := downloadAndApply(remoteVer); err != nil {
			logf("更新失败: %v", err)
			return
		}
		updated = true
		logf("汉化包更新成功")
	} else {
		logf("当前已是最新版本")
	}

	if err := checkAndInstallFont(); err != nil {
		logf("字体检查/安装失败: %v", err)
	} else {
		logf("字体检查完成")
	}
}

func createLockFile(path string) func() {
	_ = os.WriteFile(path, []byte(fmt.Sprintf("%d", os.Getpid())), 0644)
	return func() { _ = os.Remove(path); logf("移除进程锁: %s", path) }
}
func isRunning(path string) bool { _, err := os.Stat(path); return err == nil }

func getLocalVersion() (*VersionInfo, error) {
	path := filepath.Join(globalConfig.GamePath, "LimbusCompany_Data", "Lang", "LLC_zh-CN", "Info", "version.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		logf("未找到本地版本文件，视为 0")
		return &VersionInfo{Version: 0}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ver VersionInfo
	if err := json.Unmarshal(data, &ver); err != nil {
		return nil, err
	}
	return &ver, nil
}

func getRemoteVersion() (*VersionInfo, error) {
	logf("获取远程版本信息: %s", globalConfig.APIVersionURL)
	resp, err := http.Get(globalConfig.APIVersionURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("远程版本 API HTTP %d", resp.StatusCode)
	}
	data, _ := io.ReadAll(resp.Body)
	var v VersionInfo
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func getRemoteHash() (*HashInfo, error) {
	logf("获取远程哈希信息: %s", globalConfig.APIHashURL)
	resp, err := http.Get(globalConfig.APIHashURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("哈希 API HTTP %d", resp.StatusCode)
	}
	data, _ := io.ReadAll(resp.Body)
	var h HashInfo
	if err := json.Unmarshal(data, &h); err != nil {
		return nil, err
	}
	return &h, nil
}

func calculateSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func tryDownload(url string) (*http.Response, error) {
	logf("尝试下载: %s", url)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return resp, nil
}

func downloadAndApply(remoteVer *VersionInfo) error {
	hashInfo, err := getRemoteHash()
	if err != nil {
		return fmt.Errorf("获取哈希失败: %v", err)
	}
	logf("远程主哈希: %s", hashInfo.MainHash)

	tempFile, err := os.CreateTemp("", "LimbusLocalize_*.7z")
	if err != nil {
		return err
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath)
	defer tempFile.Close()
	logf("创建临时文件: %s", tempPath)

	var urls []string
	if globalConfig.DownloadURL != "" {
		// 模板可能是 primary 或 fallback
		if strings.Contains(globalConfig.DownloadURL, "github.com") {
			urls = append(urls, fmt.Sprintf(globalConfig.DownloadURL, remoteVer.Version, remoteVer.Version))
		} else {
			urls = append(urls, fmt.Sprintf(globalConfig.DownloadURL, remoteVer.Version))
		}
	}
	// 兜底
	urls = append(urls, fmt.Sprintf(mainURLPrimary, remoteVer.Version))
	urls = append(urls, fmt.Sprintf(mainURLFallback, remoteVer.Version, remoteVer.Version))

	var resp *http.Response
	for _, u := range dedup(urls) {
		var e error
		resp, e = tryDownload(u)
		if e == nil {
			logf("使用下载源: %s", u)
			if strings.Contains(u, "github.com") {
				globalConfig.DownloadURL = mainURLFallback
			} else {
				globalConfig.DownloadURL = mainURLPrimary
			}
			_ = saveConfig()
			break
		}
		logf("下载失败: %s: %v", u, e)
	}
	if resp == nil {
		return fmt.Errorf("所有下载源均失败")
	}
	defer resp.Body.Close()

	size, err := io.Copy(tempFile, resp.Body)
	if err != nil {
		return fmt.Errorf("保存文件失败: %v", err)
	}
	_ = tempFile.Close()
	logf("下载完成，大小 %.2f MB", float64(size)/(1024*1024))

	sum, err := calculateSHA256(tempPath)
	if err != nil {
		return fmt.Errorf("计算哈希失败: %v", err)
	}
	logf("本地哈希: %s", sum)
	if sum != hashInfo.MainHash {
		return fmt.Errorf("哈希不匹配：期望 %s，实际 %s", hashInfo.MainHash, sum)
	}
	logf("汉化包哈希验证通过")

	gameDir := globalConfig.GamePath
	listArchive(globalConfig.SevenZipPath, tempPath) // 写目录到日志，便于排查
	logf("解压汉化包到: %s", gameDir)

	// 极简解压（删除所有多余参数）
	if err := extractArchive(globalConfig.SevenZipPath, tempPath, gameDir, "解压汉化包"); err != nil {
		return err
	}

	// 哨兵校验（任选一个必然存在的文件）
	sentinel := filepath.Join(gameDir, "LimbusCompany_Data", "Lang", "LLC_zh-CN", "Info", "version.json")
	if !existsFile(sentinel) {
		return fmt.Errorf("解压后未找到关键文件：%s", sentinel)
	}

	logf("解压完成 -> %s", gameDir)
	return nil
}

func checkAndInstallFont() error {
	fontFile := filepath.Join(globalConfig.GamePath, filepath.FromSlash(fontPath))
	if existsFile(fontFile) {
		logf("字体文件已存在：%s", fontFile)
		return nil
	}

	hashInfo, err := getRemoteHash()
	if err != nil {
		return fmt.Errorf("获取哈希失败: %v", err)
	}
	logf("远程字体哈希: %s", hashInfo.FontHash)

	tmp, err := os.CreateTemp("", "LLCCN-Font_*.7z")
	if err != nil {
		return fmt.Errorf("创建字体临时文件失败: %v", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	defer tmp.Close()

	var resp *http.Response
	for _, u := range []string{fontURLPrimary, fontURLFallback} {
		var e error
		resp, e = tryDownload(u)
		if e == nil {
			logf("使用字体下载源: %s", u)
			break
		}
		logf("下载失败: %s: %v", u, e)
	}
	if resp == nil {
		return fmt.Errorf("所有字体下载源均失败")
	}
	defer resp.Body.Close()

	if _, err := io.Copy(tmp, resp.Body); err != nil {
		return fmt.Errorf("保存字体文件失败: %v", err)
	}
	_ = tmp.Close()

	sum, err := calculateSHA256(tmpPath)
	if err != nil {
		return fmt.Errorf("计算字体哈希失败: %v", err)
	}
	if sum != hashInfo.FontHash {
		return fmt.Errorf("字体哈希不匹配：期望 %s，实际 %s", hashInfo.FontHash, sum)
	}

	listArchive(globalConfig.SevenZipPath, tmpPath)
	logf("解压字体包到: %s", globalConfig.GamePath)

	if err := extractArchive(globalConfig.SevenZipPath, tmpPath, globalConfig.GamePath, "解压字体包"); err != nil {
		return err
	}
	if !existsFile(fontFile) {
		return fmt.Errorf("解压后仍未找到字体文件：%s", fontFile)
	}
	logf("字体安装完成：%s", fontFile)
	return nil
}

// ===============================
// 小工具
// ===============================

func dedup(ss []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func printHelp() {
	fmt.Printf(`LimbusCompany 汉化包自动更新工具
用法:
  --register    注册自动更新任务
  --unregister  注销自动更新任务
  (无参数)      执行更新检查

日志文件: %s
配置文件: %s
`, logFile, configFile)
}
