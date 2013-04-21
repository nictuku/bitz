package bitmessage

// This file implements a method to save and reConfig config files that contain
// node config and recent bitmessage content.

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strings"
	"sync"
)

// Config is used to persist the node state on disk.
type Config struct {
	sync.RWMutex
	Port int

	path  string // Empty if the store is disabled.
	Nodes []ipPort
}

// saveConfig tries to safe the provided config in a safe way.
func (s *Config) save(connectedNodes streamNodes) {
	s.Lock()
	defer s.Unlock()
	if s.path == "" {
		log.Println("skipping save, empty path")
		return
	}
	s.Nodes = make([]ipPort, 0, 10)
	for _, nodes := range connectedNodes {
		for addr, _ := range nodes {
			s.Nodes = append(s.Nodes, addr)
		}
	}

	tmp, err := ioutil.TempFile(s.path, id)
	if err != nil {
		log.Println("saveConfig tempfile:", err)
		return
	}
	err = json.NewEncoder(tmp).Encode(s)
	// The file has to be closed already otherwise it can't be renamed on
	// Windows.
	tmp.Close()
	if err != nil {
		log.Println("saveConfig json encoding:", err)
		return
	}

	// Write worked, so replace the existing file. That's atomic in Linux, but
	// not on Windows.
	p := fmt.Sprintf("%v-%v", path.Join(s.path, prefix), s.Port)
	if err := os.Rename(tmp.Name(), p); err != nil {
		// Doesn't work on Windows:
		// if os.IsExist(err) {
		// It's not possible to atomically rename files on Windows, so I
		// have to delete it and try again. If the program crashes between
		// the unlink and the rename operation, the config should be
		// available in the temp path.

		// TODO: Use a static temp path and always try to recover from it
		// during openConfig().
		if err := os.Remove(p); err != nil {
			log.Println("saveConfig failed to remove the existing config:", err)
			return
		}
		if err := os.Rename(tmp.Name(), p); err != nil {
			log.Println("saveConfig failed to rename file after deleting the original config:", err)
			return
		}
	}
	log.Printf("Saved bitz state to the filesystem at %v.", p)
}

// mkdirConfig() creates a directory to load and save the configuration from.
// Uses ~/.bitz if $HOME is set, otherwise falls back to
// /var/run/bitz.
func mkdirConfig() string {
	// XXX use a different default on Windows (although HOME does seem to work).
	dir := "/var/run/" + id
	env := os.Environ()
	for _, e := range env {
		if strings.HasPrefix(e, "HOME=") {
			dir = strings.SplitN(e, "=", 2)[1]
			dir = path.Join(dir, "."+id)
		}
	}
	// Ignore errors.
	os.MkdirAll(dir, 0750)

	if s, err := os.Stat(dir); err != nil {
		log.Fatal("stat config dir", err)
	} else if !s.IsDir() {
		log.Fatalf("Dir %v expected directory, got %v", dir, s)
	}
	return dir
}

func openConfig(port int) (cfg *Config) {
	// TODO: File locking.
	cfg = &Config{Port: port}
	cfg.path = mkdirConfig()

	// If id is bitz, prefix is bitmessage and the node is running in port
	// 30610, the config should be in ~/.bitz/bitmessage-36010.
	p := fmt.Sprintf("%v-%v", path.Join(cfg.path, prefix), port)
	f, err := os.Open(p)
	if err != nil {
		// log.Println(err)
		return cfg
	}
	defer f.Close()

	if err = json.NewDecoder(f).Decode(cfg); err != nil {
		log.Println(err)
	}
	return
}
