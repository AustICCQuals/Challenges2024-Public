package main

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/AustICCQuals/Challenges2024/re/you-cannot-reverse-under-pressure/zig"
	"github.com/google/uuid"
)

//go:embed templates/*.html
var templateFs embed.FS

var templates = template.Must(template.ParseFS(templateFs, "templates/*.html"))

var (
	doDownload = flag.Bool("download", false, "ensure that zig is downloaded.")
	doTest     = flag.String("test", "", "test a single c file and compile it check.wasm.")
	address    = flag.String("address", "127.0.0.1:8080", "the address to start the server on.")
)

type Stage struct {
	Name         string
	Description  string
	MaxTime      time.Duration
	GenerateFunc func(flag uint32, w io.Writer) error
}

type Session struct {
	Id           string
	currentStage int
	currentFlag  uint32
	endTime      time.Time
}

type Site struct {
	compiler *zig.NativeCompileDriver
	stages   []*Stage
	sessions map[string]*Session
}

func (site *Site) getSession(sessionId string) (*Session, error) {
	session, ok := site.sessions[sessionId]
	if !ok {
		return nil, fmt.Errorf("Session Not Found")
	}

	return session, nil
}

func (site *Site) compileCode(input string, output string) error {
	err := site.compiler.Compile(zig.CompileOptions{
		Language:   zig.LanguageC,
		Target:     zig.TargetFor(zig.OSFreestanding, zig.ArchWASM32, zig.ABIMusl),
		InputFiles: []string{input},
		OutputFile: output,
	})
	if err != nil {
		return err
	}

	return nil
}

func (site *Site) getStageModule(sessionId string, stage *Stage, flag uint32) ([]byte, error) {
	slog.Info("compiling", "stage", stage.Name, "session", sessionId)
	tmpDir := filepath.Join("sessions", sessionId)

	if err := os.MkdirAll(tmpDir, os.ModePerm); err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	f, err := os.Create(filepath.Join(tmpDir, "main.c"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if err := stage.GenerateFunc(flag, f); err != nil {
		return nil, err
	}

	f.Close()

	if err := site.compileCode(filepath.Join(tmpDir, "main.c"), filepath.Join(tmpDir, "out.wasm")); err != nil {
		return nil, err
	}

	mod, err := os.ReadFile(filepath.Join(tmpDir, "out.wasm"))
	if err != nil {
		return nil, err
	}

	return mod, nil
}

func (site *Site) handleIndex(w http.ResponseWriter, r *http.Request) {
	err := templates.ExecuteTemplate(w, "index.html", nil)
	if err != nil {
		slog.Warn("error", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (site *Site) startStage(stage *Stage, session *Session) (string, error) {
	session.currentFlag = rand.Uint32()

	mod, err := site.getStageModule(session.Id, stage, session.currentFlag)
	if err != nil {
		return "", err
	}

	modBase64 := base64.StdEncoding.EncodeToString(mod)

	// Time is calculated from after
	startTime := time.Now()
	session.endTime = startTime.Add(stage.MaxTime)

	return modBase64, nil
}

func (site *Site) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Bad Method", http.StatusMethodNotAllowed)
		return
	}

	sessionId := uuid.NewString()

	session := &Session{Id: sessionId, currentStage: 0}

	stage := site.stages[session.currentStage]

	modBase64, err := site.startStage(stage, session)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	site.sessions[sessionId] = session

	enc := json.NewEncoder(w)
	w.Header().Add("Content-Type", "application/json")

	err = enc.Encode(&struct {
		SessionId   string `json:"sessionId"`
		Message     string `json:"message"`
		Module      string `json:"module"`
		Name        string `json:"name"`
		Description string `json:"description"`
		EndTime     int64  `json:"endTime"`
	}{
		SessionId:   sessionId,
		Message:     "Can YOU Reverse Under Pressure?",
		Module:      modBase64,
		Name:        stage.Name,
		Description: stage.Description,
		EndTime:     session.endTime.Unix(),
	})
	if err != nil {
		slog.Warn("error", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (site *Site) handleSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Bad Method", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		SessionId string `json:"sessionId"`
		Guess     uint32 `json:"guess"`
	}

	dec := json.NewDecoder(r.Body)

	err := dec.Decode(&body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusMethodNotAllowed)
		return
	}

	session, err := site.getSession(body.SessionId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusMethodNotAllowed)
		return
	}

	var resp struct {
		Complete    bool   `json:"complete"`
		Message     string `json:"message"`
		Module      string `json:"module"`
		Name        string `json:"name"`
		Description string `json:"description"`
		EndTime     int64  `json:"endTime"`
	}

	var stage *Stage

	if body.Guess == session.currentFlag {
		if session.endTime.After(time.Now()) {
			session.currentStage += 1

			if session.currentStage == len(site.stages) {
				resp.Message = "You can reverse under pressure: " + os.Getenv("FLAG")
				stage = nil
				resp.Complete = true
			} else {
				stage = site.stages[session.currentStage]

				resp.Message = "Correct. Onto the next level."
			}
		} else {
			stage = site.stages[session.currentStage]

			resp.Message = "Correct but Too Slow. You need to reverse faster!"
		}
	} else {
		stage = site.stages[session.currentStage]

		resp.Message = "Incorrect!"
	}

	if stage != nil {
		modBase64, err := site.startStage(stage, session)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		resp.Module = modBase64
		resp.Name = stage.Name
		resp.Description = stage.Description
		resp.EndTime = session.endTime.Unix()
	}

	enc := json.NewEncoder(w)
	w.Header().Add("Content-Type", "application/json")

	err = enc.Encode(&resp)
	if err != nil {
		slog.Warn("error", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func main() {
	flag.Parse()

	if *doDownload {
		if err := zig.EnsureDownloaded(); err != nil {
			log.Fatal(err)
		}

		return
	}

	site := &Site{
		compiler: &zig.NativeCompileDriver{},
		sessions: make(map[string]*Session),
	}

	if *doTest != "" {
		if err := site.compileCode(*doTest, "check.wasm"); err != nil {
			log.Fatal(err)
		}

		return
	}

	// Getting Started
	site.stages = append(site.stages, &Stage{
		Name:        "Getting Started",
		Description: "Just a nice easy challenge to get you warmed up.",
		MaxTime:     5 * time.Minute,
		GenerateFunc: func(flag uint32, w io.Writer) error {
			_, err := fmt.Fprintf(w, "__attribute__((export_name(\"check\"))) int check(unsigned int flag) { return flag == %d; }", flag)
			if err != nil {
				return err
			}

			return nil
		},
	})

	// Final Challenge
	site.stages = append(site.stages, &Stage{
		Name:        "Final Challenge",
		Description: "If you solve this you can reverse under pressure.",
		MaxTime:     30 * time.Second,
		GenerateFunc: func(flag uint32, w io.Writer) error {
			_, err := fmt.Fprintf(w, `__attribute__((export_name("check"))) int check(unsigned int flag) {
	if ((flag & 0xff000000) != %d) {
	  return 0;
	}
	if ((flag & 0x00ff0000) != %d) {
	  return 0;
	}
	if ((flag & 0x0000ff00) != %d) {
	  return 0;
	}
	if ((flag & 0x000000ff) != %d) {
	  return 0;
	}
	return 1;
}`, flag&0xff000000, flag&0x00ff0000, flag&0x0000ff00, flag&0x000000ff)
			if err != nil {
				return err
			}

			return nil
		},
	})

	http.HandleFunc("/", site.handleIndex)
	http.HandleFunc("/start", site.handleStart)
	http.HandleFunc("/submit", site.handleSubmit)

	slog.Info("listening", "addr", *address)
	if err := http.ListenAndServe(*address, nil); err != nil {
		log.Fatal(err)
	}
}
