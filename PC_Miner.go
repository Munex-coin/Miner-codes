package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/sha3"
)

// ANSI colours (work on Windows 10+ terminals and most Unix terminals).
const (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cDim    = "\033[2m"
	cRed    = "\033[31m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cBlue   = "\033[34m"
	cMagenta = "\033[35m"
	cCyan   = "\033[36m"
	cWhite  = "\033[37m"
	cBgBlue = "\033[44m"
	cBgGreen = "\033[42m"
	cBgYellow = "\033[43m"
	cBgRed  = "\033[41m"
	cBgMagenta = "\033[45m"
)

const (
	chainID    = 6620
	moveDomain = "MCXPOGMOVEV1"
)

var excludedFields = map[string]struct{}{
	"hash":          {},
	"signature":     {},
	"pqc_signature": {},
	"finalized":     {},
}

var directionNames = []string{"east", "west", "north", "south", "up", "down"}
var directionOffsets = []point3{{1, 0, 0}, {-1, 0, 0}, {0, 1, 0}, {0, -1, 0}, {0, 0, 1}, {0, 0, -1}}

type config struct {
	nodeURL    string
	key        string
	keyFile    string
	walletFile string
	suffix     string
	navigate   bool
	duration   time.Duration
	generate   bool
	saveWallet bool
}

type minerKey struct {
	private *secp256k1.PrivateKey
	public  string
	wallet  string
	minerID string
}

type point3 [3]int

type mazeState struct {
	cells    [][][]int
	size     int
	current  point3
	goal     point3
	growth   int64
	nonce    int64
	sealed   map[point3]bool
	busy     bool
	pending  point3
	navigate bool

	// live stats (for coloured move / status logs)
	steps         int
	accepted      int
	attempts      int
	walls         int
	goals         int
	blocks        int
	rejectsInRow  int
	lastMoveAt    time.Time
	lastSyncAt    time.Time
	sessionAt     time.Time
	lastDir       string
	blockID       any
	difficulty    float64
	minerTag      string
}

const (
	movePaceMin     = 60 * time.Millisecond // avoid rate-limit spam
	rejectResyncAt  = 3                     // consecutive rejects → get_maze_state
	rejectBackoff   = 200 * time.Millisecond
)

type wsClient struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

type registerMessage struct {
	Type            string `json:"type"`
	MinerID         string `json:"miner_id"`
	Wallet          string `json:"wallet"`
	PublicKey       string `json:"public_key"`
	Signature       string `json:"signature"`
	Timestamp       int64  `json:"timestamp"`
	MinerType       string `json:"miner_type"`
	MazeID          string `json:"maze_id"`
	BlockSigningPub string `json:"block_signing_pub"`
}

type challengeResponse struct {
	Type       string `json:"type"`
	MinerID    string `json:"miner_id"`
	Seed       string `json:"seed"`
	Commitment string `json:"commitment"`
}

func main() {
	enableWindowsANSI()
	printBanner()

	cfg := parseConfig()

	// Interactive setup when no key was provided via flags/env/file.
	if err := interactiveSetup(&cfg); err != nil {
		fatalf("setup: %v", err)
	}

	if cfg.generate {
		if err := generateWallet(cfg.saveWallet); err != nil {
			fatalf("generate wallet: %v", err)
		}
		return
	}

	rawKey, err := loadPrivateKey(cfg)
	if err != nil {
		fatalf("load private key: %v", err)
	}
	key, err := keyFromHex(rawKey)
	if err != nil {
		fatalf("parse private key: %v", err)
	}
	if cfg.suffix != "" {
		key.minerID += cfg.suffix
	}

	info("miner  %s", key.minerID)
	info("wallet %s", key.wallet)
	info("node   %s", cfg.nodeURL)
	ok("mining started — navigating maze")

	if cfg.duration > 0 {
		time.AfterFunc(cfg.duration, func() {
			warn("duration reached — exiting")
			os.Exit(0)
		})
	}

	for {
		if err := runSession(cfg.nodeURL, key, cfg.navigate); err != nil {
			errf("session ended: %v", err)
			warn("reconnecting in 3s…")
		}
		time.Sleep(3 * time.Second)
	}
}

func parseConfig() config {
	var cfg config
	flag.StringVar(&cfg.nodeURL, "url", envOr("MCX_NODE_WS", ""), "node websocket URL")
	flag.StringVar(&cfg.key, "key", os.Getenv("MCX_MINER_PRIVATE_KEY"), "32-byte hex private key")
	flag.StringVar(&cfg.keyFile, "key-file", "", "file containing a 32-byte hex private key")
	flag.StringVar(&cfg.walletFile, "wallet-file", "", "wallet JSON containing privkey")
	flag.StringVar(&cfg.suffix, "suffix", "", "optional miner id suffix")
	flag.BoolVar(&cfg.navigate, "navigate", true, "move through the maze")
	flag.DurationVar(&cfg.duration, "duration", 0, "exit after this duration")
	flag.BoolVar(&cfg.generate, "generate", false, "generate a new wallet and exit")
	flag.BoolVar(&cfg.saveWallet, "save", true, "when using -generate, also write wallet.json")
	flag.Parse()
	return cfg
}

// ---------- coloured logging ----------

func ts() string {
	return time.Now().Format("15:04:05.000")
}

func logLine(bg, fg, tag, msg string) {
	fmt.Printf("%s%s%s %s%s %s%s%s%s%s\n",
		cDim, ts(), cReset,
		cBold, bg, tag, cReset,
		fg, msg, cReset,
	)
}

func info(format string, args ...any) {
	logLine(cBgBlue, cCyan, " info ", fmt.Sprintf(format, args...))
}

func ok(format string, args ...any) {
	logLine(cBgGreen, cGreen, "  ok  ", fmt.Sprintf(format, args...))
}

func warn(format string, args ...any) {
	logLine(cBgYellow, cYellow, " warn ", fmt.Sprintf(format, args...))
}

func errf(format string, args ...any) {
	logLine(cBgRed, cRed, " err  ", fmt.Sprintf(format, args...))
}

func mine(format string, args ...any) {
	logLine(cBgMagenta, cMagenta, " mine ", fmt.Sprintf(format, args...))
}

func fatalf(format string, args ...any) {
	errf(format, args...)
	os.Exit(1)
}

func printBanner() {
	fmt.Printf("%s%s", cMagenta, cBold)
	fmt.Println(`  ███╗   ███╗██╗   ██╗███╗   ██╗███████╗██╗  ██╗`)
	fmt.Println(`  ████╗ ████║██║   ██║████╗  ██║██╔════╝╚██╗██╔╝`)
	fmt.Println(`  ██╔████╔██║██║   ██║██╔██╗ ██║█████╗   ╚███╔╝ `)
	fmt.Println(`  ██║╚██╔╝██║██║   ██║██║╚██╗██║██╔══╝   ██╔██╗ `)
	fmt.Println(`  ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║███████╗██╔╝ ██╗`)
	fmt.Println(`  ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝`)
	fmt.Printf("%s", cReset)
	fmt.Printf("%s  ───  PC Miner (Go) · PoG MOVEV1  ───%s\n\n", cCyan, cReset)
}

func enableWindowsANSI() {
	// Best-effort: on modern Windows Terminal / ConPTY, ANSI already works.
	// No-op elsewhere.
}

func prompt(label, def string) string {
	r := bufio.NewReader(os.Stdin)
	if def != "" {
		fmt.Printf("%s%s%s [%s%s%s]: ", cCyan, label, cReset, cDim, def, cReset)
	} else {
		fmt.Printf("%s%s%s: ", cCyan, label, cReset)
	}
	line, _ := r.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func promptYesNo(label string, defYes bool) bool {
	def := "y"
	if !defYes {
		def = "n"
	}
	ans := strings.ToLower(prompt(label+" (y/n)", def))
	if ans == "" {
		return defYes
	}
	return ans == "y" || ans == "yes"
}

func interactiveSetup(cfg *config) error {
	// Default node if still empty.
	if cfg.nodeURL == "" {
		cfg.nodeURL = envOr("MCX_NODE_WS", "ws://munexseed1.duckdns.org:8080/ws")
	}

	hasKey := strings.TrimSpace(cfg.key) != "" || cfg.keyFile != "" || cfg.walletFile != ""
	if !hasKey {
		if _, err := os.Stat("wallet.json"); err == nil {
			hasKey = true
			if cfg.walletFile == "" {
				cfg.walletFile = "wallet.json"
			}
		}
	}

	if cfg.generate {
		return nil
	}

	if !hasKey {
		fmt.Printf("%sNo wallet found.%s\n\n", cYellow, cReset)
		fmt.Println("  1) Generate a new wallet")
		fmt.Println("  2) Paste an existing private key")
		fmt.Println("  3) Load from a key file")
		choice := prompt("Choose", "1")

		switch choice {
		case "2":
			raw := prompt("Private key (64 hex chars)", "")
			raw = strings.TrimPrefix(strings.TrimSpace(raw), "0x")
			if len(raw) != 64 {
				return errors.New("private key must be 64 hex characters")
			}
			cfg.key = raw
			if promptYesNo("Save to wallet.json", true) {
				if err := saveWalletFromHex(raw); err != nil {
					warn("could not save wallet.json: %v", err)
				} else {
					ok("saved wallet.json")
				}
			}
		case "3":
			path := prompt("Path to key file", "miner.key")
			cfg.keyFile = path
		default:
			cfg.generate = true
			cfg.saveWallet = promptYesNo("Save wallet.json after generating", true)
			if err := generateWallet(cfg.saveWallet); err != nil {
				return err
			}
			cfg.generate = false
			cfg.walletFile = "wallet.json"
			ok("wallet ready — continuing to mine")
		}
	}

	// Node URL prompt (always allow override unless passed via -url).
	if !flagWasPassed("url") {
		cfg.nodeURL = prompt("Node WebSocket URL", cfg.nodeURL)
	}
	if !flagWasPassed("suffix") {
		suf := prompt("Miner ID suffix (optional, Enter to skip)", cfg.suffix)
		cfg.suffix = suf
	}
	// Navigate is always on for a real miner — no prompt.
	cfg.navigate = true
	return nil
}

// flagWasPassed reports whether the user explicitly set a flag on the CLI.
func flagWasPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func saveWalletFromHex(privHex string) error {
	key, err := keyFromHex(privHex)
	if err != nil {
		return err
	}
	walletData := map[string]string{
		"privkey":    strings.TrimPrefix(privHex, "0x"),
		"public_key": key.public,
		"wallet":     key.wallet,
		"miner_id":   key.minerID,
	}
	payload, err := json.MarshalIndent(walletData, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile("wallet.json", payload, 0600)
}

func loadPrivateKey(cfg config) (string, error) {
	if strings.TrimSpace(cfg.key) != "" {
		return strings.TrimSpace(cfg.key), nil
	}
	if cfg.keyFile != "" {
		payload, err := os.ReadFile(cfg.keyFile)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(payload)), nil
	}
	walletFile := cfg.walletFile
	if walletFile == "" {
		if _, err := os.Stat("wallet.json"); err == nil {
			walletFile = "wallet.json"
		}
	}
	if walletFile == "" {
		return "", errors.New("provide -key, -key-file, -wallet-file, or wallet.json")
	}
	payload, err := os.ReadFile(walletFile)
	if err != nil {
		return "", err
	}
	var wallet map[string]any
	if err := json.Unmarshal(payload, &wallet); err != nil {
		return "", err
	}
	raw, _ := wallet["privkey"].(string)
	if strings.TrimSpace(raw) == "" {
		return "", errors.New("wallet JSON has no privkey")
	}
	return strings.TrimSpace(raw), nil
}

func envOr(name string, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func keyFromHex(raw string) (*minerKey, error) {
	raw = strings.TrimPrefix(strings.TrimSpace(raw), "0x")
	keyBytes, err := hex.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	if len(keyBytes) != 32 {
		return nil, errors.New("private key must be 32 bytes")
	}
	private := secp256k1.PrivKeyFromBytes(keyBytes)
	if private.Key.IsZero() {
		return nil, errors.New("private key is zero")
	}
	public := private.PubKey().SerializeUncompressed()
	publicHex := hex.EncodeToString(public)
	wallet := publicAddress(public)
	digest := sha256.Sum256([]byte(wallet + "_mcx_miner"))
	return &minerKey{
		private: private,
		public:  publicHex,
		wallet:  wallet,
		minerID: "PC_" + strings.ToUpper(hex.EncodeToString(digest[:16])),
	}, nil
}

func generateWallet(save bool) error {
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return fmt.Errorf("generate random key: %w", err)
	}
	privHex := hex.EncodeToString(keyBytes)
	key, err := keyFromHex(privHex)
	if err != nil {
		return err
	}

	fmt.Printf("\n%s%s=== New Munex / MCX Miner Wallet ===%s\n\n", cGreen, cBold, cReset)
	fmt.Printf("  %sPrivate Key%s : %s%s%s\n", cYellow, cReset, cRed, privHex, cReset)
	fmt.Printf("  %sPublic Key%s  : %s\n", cYellow, cReset, key.public)
	fmt.Printf("  %sWallet%s      : %s%s%s\n", cYellow, cReset, cCyan, key.wallet, cReset)
	fmt.Printf("  %sMiner ID%s     : %s%s%s\n", cYellow, cReset, cMagenta, key.minerID, cReset)
	fmt.Printf("\n  %sKeep the private key secret. Anyone with it controls the wallet.%s\n", cRed, cReset)

	if save {
		walletData := map[string]string{
			"privkey":    privHex,
			"public_key": key.public,
			"wallet":     key.wallet,
			"miner_id":   key.minerID,
		}
		payload, err := json.MarshalIndent(walletData, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile("wallet.json", payload, 0600); err != nil {
			return fmt.Errorf("write wallet.json: %w", err)
		}
		fmt.Printf("\n  %sSaved to wallet.json%s — next time just run the miner.\n", cGreen, cReset)
	}
	return nil
}

func publicAddress(public []byte) string {
	hash := sha3.NewLegacyKeccak256()
	hash.Write(public[1:])
	sum := hash.Sum(nil)
	return "0x" + hex.EncodeToString(sum[len(sum)-20:])
}

func (k *minerKey) signMessage(message []byte) string {
	digest := sha256.Sum256(message)
	return k.signDigest(digest[:])
}

var (
	secpN     = mustBig("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
	secpHalfN = new(big.Int).Rsh(new(big.Int).Set(secpN), 1)
)

func mustBig(hexStr string) *big.Int {
	n, ok := new(big.Int).SetString(hexStr, 16)
	if !ok {
		panic("bad curve constant")
	}
	return n
}

func (k *minerKey) signDigest(digest []byte) string {
	signature := ecdsa.Sign(k.private, digest)
	rScalar := signature.R()
	sScalar := signature.S()
	rArr := rScalar.Bytes()
	sArr := sScalar.Bytes()
	sInt := new(big.Int).SetBytes(sArr[:])
	// BIP-62 low-S: node rejects high-s (~50% of raw ECDSA without this).
	if sInt.Cmp(secpHalfN) > 0 {
		sInt.Sub(secpN, sInt)
		sb := sInt.FillBytes(make([]byte, 32))
		copy(sArr[:], sb)
	}
	raw := make([]byte, 64)
	copy(raw[:32], rArr[:])
	copy(raw[32:], sArr[:])
	return hex.EncodeToString(raw)
}

func canonicalJSON(value any) ([]byte, error) {
	var out bytes.Buffer
	if err := writeCanonical(&out, value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func writeCanonical(out *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if v {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case string:
		writeCanonicalString(out, v)
	case json.Number:
		out.WriteString(v.String())
	case int:
		out.WriteString(strconv.Itoa(v))
	case int64:
		out.WriteString(strconv.FormatInt(v, 10))
	case uint64:
		out.WriteString(strconv.FormatUint(v, 10))
	case []any:
		out.WriteByte('[')
		for index, item := range v {
			if index > 0 {
				out.WriteByte(',')
			}
			if err := writeCanonical(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				out.WriteByte(',')
			}
			writeCanonicalString(out, key)
			out.WriteByte(':')
			if err := writeCanonical(out, v[key]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	default:
		return errors.New("unsupported canonical JSON type")
	}
	return nil
}

func writeCanonicalString(out *bytes.Buffer, value string) {
	out.WriteByte('"')
	for index := 0; index < len(value); index++ {
		c := value[index]
		switch c {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if c < 0x20 {
				out.WriteString(`\u00`)
				out.WriteByte("0123456789abcdef"[c>>4])
				out.WriteByte("0123456789abcdef"[c&0x0f])
			} else {
				out.WriteByte(c)
			}
		}
	}
	out.WriteByte('"')
}

func newRegister(key *minerKey, timestamp int64) registerMessage {
	message := key.minerID + key.wallet + strconv.FormatInt(timestamp, 10)
	return registerMessage{
		Type:            "register",
		MinerID:         key.minerID,
		Wallet:          key.wallet,
		PublicKey:       key.public,
		Signature:       key.signMessage([]byte(message)),
		Timestamp:       timestamp,
		MinerType:       "pc",
		MazeID:          key.public,
		BlockSigningPub: key.public,
	}
}

func solveChallenge(minerID string, seedBase64 string, memorySize int64) (challengeResponse, error) {
	seed, err := base64.StdEncoding.DecodeString(seedBase64)
	if err != nil {
		return challengeResponse{}, err
	}
	if memorySize <= 0 {
		memorySize = 8 * 1024 * 1024
	}
	commitment := sha256.New()
	buffer := make([]byte, len(seed)+8)
	copy(buffer, seed)
	var produced int64
	for counter := uint64(0); produced < memorySize; counter++ {
		for index := 0; index < 8; index++ {
			buffer[len(seed)+index] = byte(counter >> (56 - 8*index))
		}
		block := sha256.Sum256(buffer)
		commitment.Write(block[:])
		produced += 32
	}
	return challengeResponse{
		Type:       "memory_challenge_response",
		MinerID:    minerID,
		Seed:       seedBase64,
		Commitment: base64.StdEncoding.EncodeToString(commitment.Sum(nil)),
	}, nil
}

func signBlock(block map[string]any, key *minerKey) (string, error) {
	block["producer_pub"] = key.public
	unsigned := make(map[string]any, len(block))
	for field, value := range block {
		if _, excluded := excludedFields[field]; !excluded {
			unsigned[field] = value
		}
	}
	payload, err := canonicalJSON(unsigned)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(payload)
	hashHex := hex.EncodeToString(hash[:])
	digest := sha256.Sum256(hash[:])
	delete(block, "hash")
	delete(block, "signature")
	delete(block, "pqc_signature")
	block["hash"] = hashHex
	block["signature"] = key.signDigest(digest[:])
	return hashHex, nil
}

func dial(url string) (*wsClient, error) {
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		return nil, err
	}
	conn.SetReadLimit(64 << 20)
	return &wsClient{conn: conn}, nil
}

func (c *wsClient) close() error {
	return c.conn.Close()
}

func (c *wsClient) write(value any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.WriteJSON(value)
}

func (c *wsClient) read() (map[string]any, error) {
	_, payload, err := c.conn.ReadMessage()
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var message map[string]any
	if err := decoder.Decode(&message); err != nil {
		return nil, err
	}
	return message, nil
}

func runSession(url string, key *minerKey, navigate bool) error {
	client, err := dial(url)
	if err != nil {
		return err
	}
	defer client.close()
	if err := client.write(newRegister(key, time.Now().Unix())); err != nil {
		return err
	}
	done := make(chan struct{})
	defer close(done)
	go pingLoop(client, done)
	var stateMu sync.Mutex
	var state *mazeState
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				stateMu.Lock()
				s := state
				stateMu.Unlock()
				if s != nil {
					printStatusBox(s, key.minerID)
				}
			}
		}
	}()
	for {
		message, err := client.read()
		if err != nil {
			return err
		}
		kind, _ := message["type"].(string)
		switch kind {
		case "memory_challenge_request":
			seed, _ := message["seed"].(string)
			size := challengeMemorySize(message["memory_size"])
			response, err := solveChallenge(key.minerID, seed, size)
			if err != nil {
				return err
			}
			if err := client.write(response); err != nil {
				return err
			}
		case "registered":
			ok("registered with node  miner=%s", key.minerID)
		case "maze_init":
			stateMu.Lock()
			prev := state
			state, err = newMazeState(message)
			stateMu.Unlock()
			if err != nil {
				return err
			}
			state.navigate = navigate
			state.minerTag = shortTag(key.minerID)
			if prev != nil {
				state.blocks = prev.blocks
				state.goals = prev.goals
				state.walls = prev.walls
				state.sessionAt = prev.sessionAt
			}
			mine("maze init  %d³  start=%s  goal=%s  gc=%d  block=#%v",
				state.size, posStr(state.current), posStr(state.goal), state.growth, state.blockID)
		case "maze_state":
			if state != nil {
				rawState, _ := message["state"].(map[string]any)
				state.applyState(rawState)
				state.applyMazeFields(message)
				if rawState != nil {
					state.applyMazeFields(rawState)
				}
				state.rejectsInRow = 0
				state.busy = false
				info("state synced  pos=%s  goal=%s  nonce=%d  %d³",
					posStr(state.current), posStr(state.goal), state.nonce, state.size)
			}
		case "maze_move_ack":
			if state != nil {
				handleMoveAck(client, key, state, message)
			}
		case "wall_hit":
			if state != nil {
				pace := time.Since(state.lastMoveAt).Seconds()
				state.attempts++
				moveLog(state, "wall", pace)
				if err := solveWallHit(client, key, state, message); err != nil {
					errf("solve wall hit: %v", err)
				}
			}
		case "wall_hit_solved":
			if state != nil {
				handleWallSolved(client, key, state, message)
			}
		case "produce_block":
			if err := signProducedBlock(client, key, state, message); err != nil {
				errf("sign block: %v", err)
			}
		case "ping":
			if err := client.write(map[string]any{"type": "pong", "timestamp": time.Now().Unix()}); err != nil {
				return err
			}
		case "registration_failed", "error":
			errf("node rejected miner: %v", message["error"])
		}
		if state != nil && !state.busy {
			sendNextMove(client, key, state)
		}
	}
}

func signProducedBlock(client *wsClient, key *minerKey, state *mazeState, message map[string]any) error {
	block, hasBlock := message["block"].(map[string]any)
	if !hasBlock {
		return errors.New("produce_block missing block")
	}
	blockHash, err := signBlock(block, key)
	if err != nil {
		return err
	}
	if err := client.write(map[string]any{
		"type":     "block_signed",
		"miner_id": key.minerID,
		"block":    block,
	}); err != nil {
		return err
	}
	if state != nil {
		state.blocks++
		state.blockID = block["id"]
	}
	fmt.Printf("\n%s%s  ★ BLOCK SIGNED ★%s\n", cGreen, cBold, cReset)
	fmt.Printf("  %sblock id%s   : %v\n", cYellow, cReset, block["id"])
	fmt.Printf("  %shash%s       : %s%s%s\n", cYellow, cReset, cCyan, blockHash, cReset)
	if sig, _ := block["signature"].(string); sig != "" {
		shown := sig
		if len(shown) > 32 {
			shown = shown[:32] + "…"
		}
		fmt.Printf("  %ssignature%s  : %s\n", cYellow, cReset, shown)
	}
	if reward := block["reward"]; reward != nil {
		subs := int64Value(reward)
		fmt.Printf("  %sreward%s     : %s%.6f MCX%s  (%d subs)\n", cYellow, cReset, cGreen, float64(subs)/1_000_000.0, cReset, subs)
	}
	fmt.Printf("  %sminer%s      : %s\n\n", cYellow, cReset, key.minerID)
	ok("block #%v submitted  hash=%s", block["id"], blockHash)
	return nil
}

func requestStateSync(client *wsClient, key *minerKey, state *mazeState) {
	if state != nil && time.Since(state.lastSyncAt) < 2*time.Second {
		return
	}
	if state != nil {
		state.lastSyncAt = time.Now()
	}
	_ = client.write(map[string]any{
		"type":     "get_maze_state",
		"miner_id": key.minerID,
		"maze_id":  key.public,
	})
	warn("state sync requested (map/nonce may be stale)")
}

func pingLoop(client *wsClient, done <-chan struct{}) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			if err := client.write(map[string]any{"type": "ping"}); err != nil {
				return
			}
		}
	}
}

func newMazeState(message map[string]any) (*mazeState, error) {
	state := &mazeState{
		sealed:    make(map[point3]bool),
		sessionAt: time.Now(),
		lastMoveAt: time.Now(),
	}
	state.size = intValue(message["size"])
	state.growth = int64Value(message["growthcount"])
	state.nonce = int64Value(message["movenonce"])
	state.current = pointValue(message["start"])
	state.goal = pointValue(message["goal"])
	state.blockID = message["block_id"]
	if state.blockID == nil {
		state.blockID = message["height"]
	}
	state.difficulty = floatValue(message["difficulty"])
	cells, err := cellsValue(message["maze"])
	if err != nil {
		return nil, err
	}
	state.cells = cells
	state.applySealed(message["sealed_walls"])
	return state, nil
}

func floatValue(value any) float64 {
	switch v := value.(type) {
	case json.Number:
		f, _ := v.Float64()
		return f
	case float64:
		return v
	case int:
		return float64(v)
	case int64:
		return float64(v)
	}
	return 0
}

func shortTag(minerID string) string {
	if len(minerID) <= 8 {
		return minerID
	}
	return minerID[len(minerID)-8:]
}

func posStr(p point3) string {
	return fmt.Sprintf("(%d,%d,%d)", p[0], p[1], p[2])
}

// moveLog mirrors the Python miner's per-move coloured line.
func moveLog(state *mazeState, share string, paceSec float64) {
	tag := state.minerTag
	if tag == "" {
		tag = "miner"
	}
	var bg, fg, sym string
	switch share {
	case "accept":
		bg, fg, sym = cBgGreen, cGreen, "accepted"
	case "wall":
		bg, fg, sym = cBgYellow, cYellow, "wall hit"
	case "goal":
		bg, fg, sym = cBgGreen, cCyan, " goal!  "
	case "reject":
		bg, fg, sym = cBgRed, cRed, "rejected"
	default:
		bg, fg, sym = cBgBlue, cWhite, share
	}
	sr := 100.0
	if state.attempts > 0 {
		sr = float64(state.accepted) / float64(state.attempts) * 100
	}
	dir := state.lastDir
	if dir == "" {
		dir = "?"
	}
	pace := fmt.Sprintf("%.2fs", paceSec)
	fmt.Printf("%s%s%s  %s%s %s %s  %s%s%-8s%s  %s%3d/%-3d%s %s(%5.1f%%)%s  %s%-11s%s  %s%-5s%s  %snonce:%-4d%s  %s%s%s  %s%d³ gc=%d steps=%d%s\n",
		cDim, ts(), cReset,
		cBold, bg, tag, cReset,
		cBold, fg, sym, cReset,
		cWhite, state.accepted, state.attempts, cReset,
		cYellow, sr, cReset,
		cBold+cWhite, posStr(state.current), cReset,
		cBlue, dir, cReset,
		cCyan, state.nonce, cReset,
		cDim, pace, cReset,
		cMagenta, state.size, state.growth, state.steps, cReset,
	)
}

func printStatusBox(state *mazeState, minerID string) {
	if state == nil {
		return
	}
	up := time.Since(state.sessionAt)
	hrs := int(up.Hours())
	mins := int(up.Minutes()) % 60
	secs := int(up.Seconds()) % 60
	sr := 100.0
	if state.attempts > 0 {
		sr = float64(state.accepted) / float64(state.attempts) * 100
	}
	fmt.Printf("\n%s%s  ╔═════════════════════════════════════════════════════════════════╗%s\n", cCyan, cBold, cReset)
	fmt.Printf("%s%s  ║%s            %s ★ MCX GO MINER STATUS ★ %s            %s%s║%s\n",
		cCyan, cBold, cReset, cBgMagenta+cBold+cWhite, cReset, cCyan, cBold, cReset)
	fmt.Printf("%s%s  ╠═════════════════════════════════════════════════════════════════╣%s\n", cCyan, cBold, cReset)
	fmt.Printf("%s%s  ║%s  ● Miner ID:        %-43s %s║%s\n", cCyan, cBold, cReset, minerID, cCyan+cBold, cReset)
	fmt.Printf("%s%s  ║%s  ● Uptime:          %-43s %s║%s\n", cCyan, cBold, cReset, fmt.Sprintf("%dh %02dm %02ds", hrs, mins, secs), cCyan+cBold, cReset)
	fmt.Printf("%s%s  ║%s  ● Blocks signed:   %-43d %s║%s\n", cCyan, cBold, cReset, state.blocks, cCyan+cBold, cReset)
	fmt.Printf("%s%s  ║%s  ● Goals reached:   %-43d %s║%s\n", cCyan, cBold, cReset, state.goals, cCyan+cBold, cReset)
	fmt.Printf("%s%s  ║%s  ● Moves:           %-43s %s║%s\n", cCyan, cBold, cReset, fmt.Sprintf("%d/%d (%.1f%%)", state.accepted, state.attempts, sr), cCyan+cBold, cReset)
	fmt.Printf("%s%s  ║%s  ● Wall solves:     %-43d %s║%s\n", cCyan, cBold, cReset, state.walls, cCyan+cBold, cReset)
	fmt.Printf("%s%s  ║%s  ● Maze:            %-43s %s║%s\n", cCyan, cBold, cReset, fmt.Sprintf("%d³  gc=%d  pos=%s  goal=%s", state.size, state.growth, posStr(state.current), posStr(state.goal)), cCyan+cBold, cReset)
	fmt.Printf("%s%s  ║%s  ● Diff / block:    %-43s %s║%s\n", cCyan, cBold, cReset, fmt.Sprintf("%.1f  #%v", state.difficulty, state.blockID), cCyan+cBold, cReset)
	fmt.Printf("%s%s  ╚═════════════════════════════════════════════════════════════════╝%s\n\n", cCyan, cBold, cReset)
}

func (m *mazeState) nextMove() (string, bool) {
	if m.busy || len(m.cells) == 0 {
		return "", false
	}
	next, ok := m.bfsNext(m.current, m.goal)
	if !ok {
		next, ok = m.openNeighbor(m.current)
	}
	if !ok {
		return "", false
	}
	delta := point3{next[0] - m.current[0], next[1] - m.current[1], next[2] - m.current[2]}
	for index, offset := range directionOffsets {
		if offset == delta {
			m.busy = true
			m.pending = next
			m.nonce++
			return directionNames[index], true
		}
	}
	return "", false
}

func (m *mazeState) bfsNext(start point3, goal point3) (point3, bool) {
	if start == goal {
		return point3{}, false
	}
	queue := []point3{start}
	previous := map[point3]point3{start: start}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, offset := range directionOffsets {
			next := point3{current[0] + offset[0], current[1] + offset[1], current[2] + offset[2]}
			if !m.open(next) {
				continue
			}
			if _, seen := previous[next]; seen {
				continue
			}
			previous[next] = current
			if next == goal {
				return firstStep(previous, start, goal), true
			}
			queue = append(queue, next)
		}
	}
	return point3{}, false
}

func firstStep(previous map[point3]point3, start point3, goal point3) point3 {
	step := goal
	for previous[step] != start {
		step = previous[step]
	}
	return step
}

func (m *mazeState) open(position point3) bool {
	if position[0] < 0 || position[1] < 0 || position[2] < 0 {
		return false
	}
	if position[2] >= len(m.cells) || position[1] >= len(m.cells[position[2]]) || position[0] >= len(m.cells[position[2]][position[1]]) {
		return false
	}
	return m.cells[position[2]][position[1]][position[0]] == 0 && !m.sealed[position]
}

func (m *mazeState) openNeighbor(position point3) (point3, bool) {
	for _, offset := range directionOffsets {
		next := point3{position[0] + offset[0], position[1] + offset[1], position[2] + offset[2]}
		if m.open(next) {
			return next, true
		}
	}
	return point3{}, false
}

func (m *mazeState) markWall(position point3) {
	if position[2] < 0 || position[2] >= len(m.cells) {
		return
	}
	if position[1] < 0 || position[1] >= len(m.cells[position[2]]) {
		return
	}
	if position[0] < 0 || position[0] >= len(m.cells[position[2]][position[1]]) {
		return
	}
	m.cells[position[2]][position[1]][position[0]] = 1
}

func (m *mazeState) applySealed(value any) {
	items, ok := value.([]any)
	if !ok {
		return
	}
	for _, item := range items {
		m.sealed[pointValue(item)] = true
	}
}

func (m *mazeState) applyOpened(value any) {
	items, ok := value.([]any)
	if !ok {
		return
	}
	for _, item := range items {
		delete(m.sealed, pointValue(item))
	}
}

func (m *mazeState) applyState(state map[string]any) {
	if state == nil {
		return
	}
	m.applyMazeFields(state)
	if caught, _ := state["caught"].(bool); caught {
		return
	}
	if shrink, _ := state["shrink"].(bool); shrink {
		return
	}
	if value, ok := state["current"]; ok {
		m.current = pointValue(value)
	}
	if value, ok := state["position"]; ok {
		m.current = pointValue(value)
	}
	if value, ok := state["goal"]; ok {
		m.goal = pointValue(value)
	}
	if value, ok := state["newgoal"]; ok {
		m.goal = pointValue(value)
	}
	if value, ok := state["newspawn"]; ok {
		m.current = pointValue(value)
	}
}

func (m *mazeState) applyMazeFields(message map[string]any) {
	if value, ok := message["maze"]; ok {
		if cells, err := cellsValue(value); err == nil {
			m.cells = cells
		}
	}
	if value, ok := message["size"]; ok {
		m.size = intValue(value)
	}
	if value, ok := message["start"]; ok {
		m.current = pointValue(value)
	}
	if value, ok := message["goal"]; ok {
		m.goal = pointValue(value)
	}
	if value, ok := message["movenonce"]; ok {
		m.nonce = int64Value(value)
	}
	if value, ok := message["growthcount"]; ok {
		m.growth = int64Value(value)
	}
	m.applySealed(message["sealed_walls"])
	m.applyOpened(message["opened_walls"])
}

func sendNextMove(client *wsClient, key *minerKey, state *mazeState) {
	if !state.navigate {
		return
	}
	// Pace moves so we don't burn the node's rate limit (and spam rejects).
	if elapsed := time.Since(state.lastMoveAt); elapsed < movePaceMin {
		time.Sleep(movePaceMin - elapsed)
	}
	direction, found := state.nextMove()
	if !found {
		if state.rejectsInRow >= 1 || state.attempts > 0 {
			requestStateSync(client, key, state)
			state.rejectsInRow = 0
		}
		state.busy = false
		return
	}
	state.lastDir = direction
	auth, err := canonicalJSON(map[string]any{
		"domain":      moveDomain,
		"chainid":     json.Number(strconv.Itoa(chainID)),
		"minerid":     key.minerID,
		"mazeid":      key.public,
		"mazeversion": json.Number(strconv.FormatInt(state.growth, 10)),
		"movenonce":   json.Number(strconv.FormatInt(state.nonce, 10)),
		"direction":   direction,
	})
	if err != nil {
		state.busy = false
		return
	}
	payload := map[string]any{
		"type":       "maze_move",
		"miner_id":   key.minerID,
		"maze_id":    key.public,
		"direction":  direction,
		"signature":  key.signMessage(auth),
		"move_nonce": state.nonce,
	}
	if err := client.write(payload); err != nil {
		state.busy = false
	}
}

func handleMoveAck(client *wsClient, key *minerKey, state *mazeState, message map[string]any) {
	state.applyMazeFields(message)
	pace := time.Since(state.lastMoveAt).Seconds()
	state.lastMoveAt = time.Now()
	state.attempts++
	state.steps++

	success, _ := message["success"].(bool)
	share := "reject"
	if success {
		share = "accept"
		state.accepted++
		state.rejectsInRow = 0
		rawState, _ := message["state"].(map[string]any)
		caught := false
		if rawState != nil {
			caught, _ = rawState["caught"].(bool)
			state.applyState(rawState)
		}
		if caught {
			share = "goal"
			state.goals++
			ok("goal reached!  goals=%d  maze growing…", state.goals)
		}
	} else {
		// Reject: treat attempted cell as a wall so we stop ramming it.
		state.rejectsInRow++
		state.markWall(state.pending)
		msg := strings.ToLower(fmt.Sprint(message["message"], " ", message["error"], " ", message["reason"]))
		if strings.Contains(msg, "rate limit") {
			warn("rate limited — backing off 1s")
			time.Sleep(time.Second)
			requestStateSync(client, key, state)
		} else if state.rejectsInRow >= rejectResyncAt {
			warn("%d rejects in a row at %s — resyncing", state.rejectsInRow, posStr(state.current))
			requestStateSync(client, key, state)
			state.rejectsInRow = 0
			time.Sleep(rejectBackoff)
		} else {
			time.Sleep(rejectBackoff)
		}
	}
	moveLog(state, share, pace)

	if state.accepted > 0 && state.accepted%50 == 0 {
		printStatusBox(state, key.minerID)
	}

	if value, ok := message["movenonce"]; ok {
		state.nonce = int64Value(value)
	}
	if value, ok := message["growthcount"]; ok {
		state.growth = int64Value(value)
	}
	state.busy = false
	sendNextMove(client, key, state)
}

func solveWallHit(client *wsClient, key *minerKey, state *mazeState, message map[string]any) error {
	state.markWall(state.pending)
	state.applyMazeFields(message)
	if value, ok := message["position"]; ok {
		state.current = pointValue(value)
	}
	if value, ok := message["movenonce"]; ok {
		state.nonce = int64Value(value)
	}
	if value, ok := message["growthcount"]; ok {
		state.growth = int64Value(value)
	}
	seed, _ := message["seed"].(string)
	difficulty := intValue(message["difficulty"])
	if difficulty <= 0 {
		difficulty = 16
	}
	nonce := solvePoW(seed, difficulty)
	return client.write(map[string]any{
		"type":     "wall_hit_solve",
		"miner_id": key.minerID,
		"maze_id":  key.public,
		"nonce":    nonce,
	})
}

func handleWallSolved(client *wsClient, key *minerKey, state *mazeState, message map[string]any) {
	state.applyMazeFields(message)
	pace := time.Since(state.lastMoveAt).Seconds()
	state.lastMoveAt = time.Now()
	if accepted, _ := message["accepted"].(bool); accepted {
		state.walls++
		if value, ok := message["position"]; ok {
			state.current = pointValue(value)
		}
		rawState, _ := message["state"].(map[string]any)
		state.applyState(rawState)
		ok("wall solved  walls=%d  pace=%.2fs  pos=%s", state.walls, pace, posStr(state.current))
	} else {
		errf("wall solve rejected: %v", message["error"])
	}
	state.busy = false
	sendNextMove(client, key, state)
}

func solvePoW(seed string, difficulty int) uint64 {
	if difficulty > 256 {
		difficulty = 256
	}
	for nonce := uint64(0); ; nonce++ {
		digest := sha256.Sum256([]byte(seed + strconv.FormatUint(nonce, 10)))
		if leadingZeroBits(digest[:], difficulty) {
			return nonce
		}
	}
}

func leadingZeroBits(digest []byte, bits int) bool {
	full := bits / 8
	remainder := bits % 8
	for index := 0; index < full; index++ {
		if digest[index] != 0 {
			return false
		}
	}
	if remainder == 0 {
		return true
	}
	mask := byte(0xff << (8 - remainder))
	return digest[full]&mask == 0
}

func cellsValue(value any) ([][][]int, error) {
	planes, ok := value.([]any)
	if !ok {
		return nil, errors.New("maze is not an array")
	}
	result := make([][][]int, len(planes))
	for z, planeValue := range planes {
		rows, ok := planeValue.([]any)
		if !ok {
			return nil, errors.New("maze plane is not an array")
		}
		result[z] = make([][]int, len(rows))
		for y, rowValue := range rows {
			cells, ok := rowValue.([]any)
			if !ok {
				return nil, errors.New("maze row is not an array")
			}
			result[z][y] = make([]int, len(cells))
			for x, cell := range cells {
				result[z][y][x] = intValue(cell)
			}
		}
	}
	return result, nil
}

func pointValue(value any) point3 {
	items, ok := value.([]any)
	if !ok || len(items) != 3 {
		return point3{}
	}
	return point3{intValue(items[0]), intValue(items[1]), intValue(items[2])}
}

func intValue(value any) int {
	return int(int64Value(value))
}

func int64Value(value any) int64 {
	switch v := value.(type) {
	case json.Number:
		n, _ := v.Int64()
		return n
	case float64:
		return int64(v)
	case bool:
		if v {
			return 1
		}
		return 0
	case int:
		return int64(v)
	case int64:
		return v
	}
	return 0
}

func challengeMemorySize(value any) int64 {
	switch v := value.(type) {
	case json.Number:
		n, err := v.Int64()
		if err == nil && n > 0 {
			return n
		}
	case float64:
		if v > 0 {
			return int64(v)
		}
	}
	return 8 * 1024 * 1024
}
