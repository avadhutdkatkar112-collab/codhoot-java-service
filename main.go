package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	maxOutputSize    = 512 * 1024
	maxSourceSize    = 100 * 1024
	maxCompileTime   = 15 * time.Second
	maxExecTime      = 10 * time.Second
	workspaceDir     = "/tmp/codhoot-workspace"
)

type CompileRequest struct {
	Source string `json:"source"`
}

type CompileResponse struct {
	Success         bool   `json:"success"`
	Output          string `json:"output,omitempty"`
	Error           string `json:"error,omitempty"`
	ExitCode        int    `json:"exit_code"`
	CompileTime     int64  `json:"compile_time_ms"`
	ExecuteTime     int64  `json:"execute_time_ms"`
	Timeout         bool   `json:"timeout,omitempty"`
	OutputTruncated bool   `json:"output_truncated,omitempty"`
}

type HealthResponse struct {
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	os.MkdirAll(workspaceDir, 0755)
	defer os.RemoveAll(workspaceDir)

	if _, err := exec.LookPath("javac"); err != nil {
		log.Fatalf("javac not found: %v", err)
	}
	if _, err := exec.LookPath("java"); err != nil {
		log.Fatalf("java not found: %v", err)
	}
	log.Println("Java 21 found, ready to compile")

	mux := http.NewServeMux()
	mux.HandleFunc("POST /compile", handleCompile)
	mux.HandleFunc("GET /health", handleHealth)
	mux.HandleFunc("GET /", handleIndex)

	handler := corsMiddleware(loggingMiddleware(mux))

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)
	}()

	log.Printf("Java Compiler Service listening on :%s", port)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"service": "codhoot-java-compiler",
		"version": "1.0.0",
		"usage":   "POST /compile with {\"source\": \"...\"}",
	})
}

func handleCompile(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	var req CompileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", 0, 0)
		return
	}

	if strings.TrimSpace(req.Source) == "" {
		writeError(w, http.StatusBadRequest, "Source code is required", 0, 0)
		return
	}

	if len(req.Source) > maxSourceSize {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Source code exceeds %d bytes", maxSourceSize), 0, 0)
		return
	}

	jobID := fmt.Sprintf("%d", time.Now().UnixNano())
	jobDir := filepath.Join(workspaceDir, jobID)
	os.MkdirAll(jobDir, 0755)
	defer os.RemoveAll(jobDir)

	output, exitCode, compileMs, execMs, timeout, truncated := compileAndRun(jobDir, req.Source)

	resp := CompileResponse{
		Success:         exitCode == 0,
		Output:          output,
		ExitCode:        exitCode,
		CompileTime:     compileMs,
		ExecuteTime:     execMs,
		Timeout:         timeout,
		OutputTruncated: truncated,
	}

	if exitCode != 0 && output == "" {
		resp.Error = "Compilation or execution failed"
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)

	totalMs := time.Since(start).Milliseconds()
	log.Printf("Compile: exit=%d compile=%dms exec=%dms total=%dms timeout=%v",
		exitCode, compileMs, execMs, totalMs, timeout)
}

func compileAndRun(jobDir, source string) (output string, exitCode int, compileMs, execMs int64, timeout, truncated bool) {
	srcFile := filepath.Join(jobDir, "Main.java")
	if err := os.WriteFile(srcFile, []byte(source), 0644); err != nil {
		return fmt.Sprintf("Failed to write source: %v", err), -1, 0, 0, false, false
	}

	// Compile
	compileStart := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), maxCompileTime)
	defer cancel()

	compileCmd := exec.CommandContext(ctx, "javac", srcFile)
	compileOutput, err := compileCmd.CombinedOutput()
	compileMs = time.Since(compileStart).Milliseconds()

	if err != nil {
		return string(compileOutput), 1, compileMs, 0, false, false
	}

	// Execute
	execStart := time.Now()
	execCtx, execCancel := context.WithTimeout(context.Background(), maxExecTime)
	defer execCancel()

	execCmd := exec.CommandContext(execCtx, "java", "-cp", jobDir, "Main")
	var stdout, stderr strings.Builder
	execCmd.Stdout = &stdout
	execCmd.Stderr = &stderr

	err = execCmd.Run()
	execMs = time.Since(execStart).Milliseconds()

	if execCtx.Err() == context.DeadlineExceeded {
		return "Execution timed out (limit: 10s)", -1, compileMs, execMs, true, false
	}

	combinedOutput := stdout.String() + stderr.String()
	if len(combinedOutput) > maxOutputSize {
		combinedOutput = combinedOutput[:maxOutputSize] + "\n... [output truncated]"
		truncated = true
	}

	output = combinedOutput
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	} else {
		exitCode = 0
	}

	return
}

func writeError(w http.ResponseWriter, status int, message string, compileMs, execMs int64) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(CompileResponse{
		Success:     false,
		Error:       message,
		ExitCode:    -1,
		CompileTime: compileMs,
		ExecuteTime: execMs,
	})
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
