package cmd

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"beryju.io/crtls/internal"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type FileInfo struct {
	Name    string
	Size    int64
	ModTime time.Time
	IsDir   bool
	Path    string
}

type PageData struct {
	CurrentPath string
	ParentPath  string
	Files       []FileInfo
	Title       string
}

const htmlTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>{{.Title}}</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            background: #2c3e50;
            color: white;
            padding: 20px;
        }
        .header h1 {
            margin: 0;
            font-size: 24px;
        }
        .breadcrumb {
            margin-top: 10px;
            font-size: 14px;
            opacity: 0.8;
        }
        .breadcrumb a {
            color: #3498db;
            text-decoration: none;
        }
        .breadcrumb a:hover {
            text-decoration: underline;
        }
        .file-list {
            padding: 0;
        }
        .file-item {
            display: flex;
            align-items: center;
            padding: 15px 20px;
            border-bottom: 1px solid #eee;
            transition: background-color 0.2s;
        }
        .file-item:hover {
            background-color: #f8f9fa;
        }
        .file-item:last-child {
            border-bottom: none;
        }
        .file-icon {
            width: 24px;
            height: 24px;
            margin-right: 15px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 16px;
        }
        .file-info {
            flex: 1;
        }
        .file-name {
            font-weight: 500;
            color: #2c3e50;
            text-decoration: none;
            font-size: 16px;
        }
        .file-name:hover {
            color: #3498db;
        }
        .file-meta {
            font-size: 12px;
            color: #7f8c8d;
            margin-top: 4px;
        }
        .file-size {
            color: #95a5a6;
            font-size: 14px;
            min-width: 80px;
            text-align: right;
        }
        .cert-file {
            background-color: #e8f5e8;
        }
        .key-file {
            background-color: #fff3cd;
        }
        .pfx-file {
            background-color: #e1ecf4;
        }
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: #7f8c8d;
        }
        .empty-state h3 {
            margin: 0 0 10px 0;
            color: #95a5a6;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Certificate File Browser</h1>
            <div class="breadcrumb">
                <a href="/">🏠 Root</a>
                {{if .CurrentPath}}
                    / {{.CurrentPath}}
                {{end}}
            </div>
        </div>

        <div class="file-list">
            {{if .ParentPath}}
            <div class="file-item">
                <div class="file-icon">📁</div>
                <div class="file-info">
                    <a href="{{.ParentPath}}" class="file-name">.. (Parent Directory)</a>
                </div>
            </div>
            {{end}}

            {{if .Files}}
                {{range .Files}}
                <div class="file-item {{if eq (fileExt .Name) ".pem"}}cert-file{{else if eq (fileExt .Name) ".key"}}key-file{{else if eq (fileExt .Name) ".pfx"}}pfx-file{{end}}">
                    <div class="file-icon">
                        {{if .IsDir}}📁{{else if eq (fileExt .Name) ".pem"}}📜{{else if eq (fileExt .Name) ".key"}}🔑{{else if eq (fileExt .Name) ".pfx"}}📦{{else}}📄{{end}}
                    </div>
                    <div class="file-info">
                        <a href="{{.Path}}" class="file-name">{{.Name}}</a>
                        <div class="file-meta">Modified: {{.ModTime.Format "2006-01-02 15:04:05"}}</div>
                    </div>
                    <div class="file-size">
                        {{if not .IsDir}}{{formatSize .Size}}{{end}}
                    </div>
                </div>
                {{end}}
            {{else}}
                <div class="empty-state">
                    <h3>No files found</h3>
                    <p>This directory is empty or no certificates have been generated yet.</p>
                </div>
            {{end}}
        </div>
    </div>
</body>
</html>
`

var (
	serverPort string
	serverHost string
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve generated files on the network.",
	RunE: func(cmd *cobra.Command, args []string) error {
		outputDir, err := cmd.Flags().GetString("output-dir")
		if err != nil {
			return err
		}

		// Ensure the directory exists
		if _, err := os.Stat(outputDir); os.IsNotExist(err) {
			return errors.Wrap(err, "Directory does not exist\n")
		}

		// Get absolute path
		absDir, err := filepath.Abs(outputDir)
		if err != nil {
			return errors.Wrap(err, "Failed to get absolute path")
		}

		fmt.Printf("Starting file browser on http://%s:%s\n", serverHost, serverPort)
		fmt.Printf("Serving directory: %s\n", absDir)

		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			serveFileBrowser(w, r, absDir)
		})

		return http.ListenAndServe(serverHost+":"+serverPort, nil)
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().StringVarP(&serverPort, "port", "p", "8000", "Port to serve on")
	serveCmd.Flags().StringVar(&serverHost, "host", "[::1]", "Host to serve on")
}

func serveFileBrowser(w http.ResponseWriter, r *http.Request, baseDir string) {
	// Clean the URL path
	urlPath := filepath.Clean(r.URL.Path)
	if urlPath == "." {
		urlPath = "/"
	}

	// Convert URL path to file system path
	var fsPath string
	if urlPath == "/" {
		fsPath = baseDir
	} else {
		fsPath = filepath.Join(baseDir, strings.TrimPrefix(urlPath, "/"))
	}

	// Security check: ensure we're not serving outside the base directory
	if !strings.HasPrefix(fsPath, baseDir) {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	// Check if path exists
	info, err := os.Stat(fsPath)
	if os.IsNotExist(err) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// If it's a file, serve it for download
	if !info.IsDir() {
		// Set appropriate headers for certificate files
		ext := strings.ToLower(filepath.Ext(fsPath))
		switch ext {
		case ".pem":
			w.Header().Set("Content-Type", "application/x-pem-file")
		case ".key":
			w.Header().Set("Content-Type", "application/x-pem-file")
		case ".pfx":
			w.Header().Set("Content-Type", "application/x-pkcs12")
		default:
			w.Header().Set("Content-Type", "application/octet-stream")
		}

		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filepath.Base(fsPath)))
		http.ServeFile(w, r, fsPath)
		return
	}

	// It's a directory, show file listing
	files, err := os.ReadDir(fsPath)
	if err != nil {
		http.Error(w, "Failed to read directory", http.StatusInternalServerError)
		return
	}

	// Convert to FileInfo slice and sort
	var fileInfos []FileInfo
	for _, file := range files {
		info, err := file.Info()
		if err != nil {
			continue
		}

		var filePath string
		if urlPath == "/" {
			filePath = "/" + file.Name()
		} else {
			filePath = urlPath + "/" + file.Name()
		}

		fileInfos = append(fileInfos, FileInfo{
			Name:    file.Name(),
			Size:    info.Size(),
			ModTime: info.ModTime(),
			IsDir:   file.IsDir(),
			Path:    filePath,
		})
	}

	// Sort: directories first, then by name
	sort.Slice(fileInfos, func(i, j int) bool {
		if fileInfos[i].IsDir != fileInfos[j].IsDir {
			return fileInfos[i].IsDir
		}
		return fileInfos[i].Name < fileInfos[j].Name
	})

	// Prepare template data
	var parentPath string
	if urlPath != "/" {
		parentPath = filepath.Dir(urlPath)
		if parentPath == "." {
			parentPath = "/"
		}
	}

	data := PageData{
		CurrentPath: strings.TrimPrefix(urlPath, "/"),
		ParentPath:  parentPath,
		Files:       fileInfos,
		Title:       "Certificate Browser - " + urlPath,
	}

	// Create template with helper functions
	tmpl := template.New("browser").Funcs(template.FuncMap{
		"formatSize": internal.FormatSize,
		"fileExt":    filepath.Ext,
	})

	tmpl, err = tmpl.Parse(htmlTemplate)
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Template execution error: %v", err)
	}
}
