// Command webhook-receiver demonstrates verifying a RocketVault vault
// webhook delivery, per docs/superpowers/specs/2026-08-20-webhook-delivery-primitive-design.md.
//
// RocketVault does not send anything to a configured webhook yet — that
// design is proposed but unbuilt (see the README in this directory). This
// program can still be tested end-to-end today: run it in receiver mode,
// then run a second instance in -simulate mode to send it one correctly
// signed "webhook.test" event, exactly like the future real sender would.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

// Event is the envelope RocketVault will send, per the design spec's wire
// contract. Fields and shape are fixed — a receiver implementation must not
// assume anything beyond what's documented there.
type Event struct {
	Version string          `json:"version"`
	ID      string          `json:"id"`
	Type    string          `json:"type"`
	Time    string          `json:"time"`
	Vault   string          `json:"vault"`
	Data    json.RawMessage `json:"data"`
}

func main() {
	listen := flag.String("listen", ":8090", "address to listen on (receiver mode)")
	path := flag.String("path", "/hooks/rocketvault", "path the webhook is configured to POST to")
	secret := flag.String("secret", os.Getenv("ROCKETVAULT_WEBHOOK_SECRET"),
		"webhook signing secret, exactly as printed by `vault-webhook set` (or set ROCKETVAULT_WEBHOOK_SECRET)")
	tolerance := flag.Duration("tolerance", 5*time.Minute, "max allowed signature age")
	simulate := flag.String("simulate", "", "instead of serving, POST one signed webhook.test event to this URL and exit")
	vault := flag.String("vault", "demo", "vault name to put in the simulated event's \"vault\" field")
	flag.Parse()

	if *secret == "" {
		fmt.Fprintln(os.Stderr, "error: -secret or ROCKETVAULT_WEBHOOK_SECRET is required")
		os.Exit(1)
	}

	if *simulate != "" {
		if err := runSimulate(*simulate, *secret, *vault); err != nil {
			fmt.Fprintf(os.Stderr, "simulate: %v\n", err)
			os.Exit(1)
		}
		return
	}

	runServer(*listen, *path, *secret, *tolerance)
}

// runServer starts a receiver that verifies every delivery to path against
// secret before acting on it.
func runServer(listen, path, secret string, tolerance time.Duration) {
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Signature covers the exact raw bytes sent — read them once, unparsed.
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}

		if err := Verify(secret, r.Header.Get("X-RocketVault-Signature"), body, tolerance, time.Now()); err != nil {
			log.Printf("rejected delivery: %v", err)
			http.Error(w, "signature verification failed", http.StatusUnauthorized)
			return
		}

		var event Event
		if err := json.Unmarshal(body, &event); err != nil {
			http.Error(w, "malformed envelope", http.StatusBadRequest)
			return
		}

		log.Printf("verified event: type=%s id=%s vault=%s time=%s",
			event.Type, event.ID, event.Vault, event.Time)

		w.WriteHeader(http.StatusOK)
	})

	log.Printf("webhook-receiver listening on %s%s", listen, path)
	log.Printf("point a vault's webhook here with: rocketvault vault-webhook set --url https://<this-host>%s", path)
	if err := http.ListenAndServe(listen, mux); err != nil { //nolint:gosec
		log.Fatalf("server error: %v", err)
	}
}

// runSimulate builds and sends one webhook.test event to targetURL, signed
// exactly as the real sender is specified to sign it. This is how to
// exercise a receiver today, since nothing in RocketVault sends real
// deliveries yet.
func runSimulate(targetURL, secret, vault string) error {
	event := Event{
		Version: "1",
		ID:      newUUIDv4(),
		Type:    "webhook.test",
		Time:    time.Now().UTC().Format(time.RFC3339),
		Vault:   vault,
		Data:    json.RawMessage("{}"),
	}

	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	ts := time.Now().Unix()
	sig := Sign(secret, ts, body)

	req, err := http.NewRequest(http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-RocketVault-Signature", fmt.Sprintf("t=%d,v1=%s", ts, sig))
	req.Header.Set("X-RocketVault-Event-Id", event.ID)
	req.Header.Set("X-RocketVault-Event-Type", event.Type)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("send: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	fmt.Printf("sent %s (id=%s) to %s -> %s\n", event.Type, event.ID, targetURL, resp.Status)
	return nil
}

func newUUIDv4() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		log.Fatalf("generate event id: %v", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]), hex.EncodeToString(b[4:6]), hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]), hex.EncodeToString(b[10:16]))
}
