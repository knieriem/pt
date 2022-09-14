package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"cuelang.org/go/cue"
	cueerrors "cuelang.org/go/cue/errors"
	"cuelang.org/go/cue/load"

	"github.com/knieriem/fsutil"
	"github.com/knieriem/tool"

	"github.com/knieriem/gointernal/cmd/cli"
	"github.com/knieriem/gointernal/cmd/go/base"
	"github.com/knieriem/gointernal/cmd/go/cfg"
	"github.com/knieriem/gointernal/cmd/go/envcmd"
	"github.com/knieriem/gointernal/cmd/go/modfetch/codehost"
	"github.com/knieriem/gointernal/cmd/go/work"

	"t9rsys.com/tools/pt/internal/diff"
)

type conf struct {
	Sources map[string]*Source
	Require map[string]string `json:"require"`
	Replace map[string]string `json:"replace"`
	Build   Build
}

type Build struct {
	DefaultVariant string                   `json:"default"`
	Variant        map[string]*BuildVariant `json:"variant"`
}

type BuildVariant struct {
	Script string `json:"script"`
}

var extraDefs = flag.String("extra-defs", "", "comma separated list of additional project CUE files")
var variant = flag.String("variant", "", "select build variant")

var prog = &cli.Command{
	UsageLine: "pt",
	Long:      "Pt is a tool to manage project dependencies",
	Commands: []*cli.Command{
		cmdVersion,
		cmdDep,
		envcmd.CmdEnv,
	},
}

var (
	projectFile string
	sourcesFile string
	tags        []string
)

func setupEnv() {
	cfg.EnvName = "PTENV"
	cfg.ConfigDirname = "github.com-knieriem-pt"

	cacheDir, err := os.UserCacheDir()
	if err != nil {
		errExit(err)
	}

	env := []cfg.EnvVar{
		{Name: "PTCACHE", Value: filepath.Join(cacheDir, cfg.ConfigDirname), Var: &cfg.GOMODCACHE},
		{Name: "PTPROJECT", Value: "p.cue", Var: &projectFile},
		{Name: "PTSOURCES", Value: "sources.cue", Var: &sourcesFile},
	}
	cfg.SetupEnv(env)

}

func main() {
	setupEnv()

	base.Prog = prog
	flag.Parse()

	cli.EvalArgs(flag.Args())
}

var cmdVersion = &cli.Command{
	UsageLine: "pt version",
	Short:     "print pt version",
	Run: func(_ context.Context, _ *cli.Command, _ []string) {
		fmt.Println("v0.1.0")
	},
}

func init() {
	addProjectFlags(cmdStatus)
	addProjectFlags(cmdDiff)
	addProjectFlags(cmdUpdate)
	addProjectFlags(cmdListLatest)
	addProjectFlags(cmdZip)
}

var cmdDep = &cli.Command{
	UsageLine: "pt dep",
	Short:     "dependency maintenance",
	Commands: []*cli.Command{
		cmdStatus,
		cmdDiff,
		cmdUpdate,
		cmdListLatest,
		cmdZip,
	},
}

var cmdStatus = &cli.Command{
	UsageLine: "pt dep status [project flags]",
	Short:     "show status of dependencies",
	Run:       newNamespaceAction(depsStatus).run,
}

var cmdDiff = &cli.Command{
	UsageLine: "pt dep diff [project flags]",
	Short:     "show difference between  workdir and dependencies",
	Run:       newNamespaceAction(depsDiff).run,
}

var cmdUpdate = &cli.Command{
	UsageLine: "pt dep update [project flags]",
	Short:     "update dependencies",
	Run:       newNamespaceAction(updateDeps).run,
}

var cmdZip = &cli.Command{
	UsageLine: "pt dep zip [project flags] -- file.zip",
	Short:     "create a zip of dependencies",
	Run:       newNamespaceAction(createZip).run,
}

func addProjectFlags(cmd *cli.Command) {
	cmd.Flag.StringVar(&projectFile, "p", "p.cue", "project definitions file")
	cmd.Flag.StringVar(&sourcesFile, "sources", sourcesFile, "module source definitions file")
	cmd.Flag.Var((*work.TagsFlag)(&tags), "tags", "a comma-separated list of tags to consider satisfied during dependency calculation")
}

var cmdListLatest = &cli.Command{
	UsageLine: "pt dep latest [project flags]",
	Short:     "list latest available dependencies",
	Run:       runListLatest,
}

func runListLatest(_ context.Context, cmd *cli.Command, args []string) {
	sources, err := setupProjectSources()
	if err != nil {
		errExit(err)
	}
	err = listLatest(sources)
	if err != nil {
		errExit(err)
	}
}

type namespaceActionFunc func(ns *fsutil.NameSpace, sources []*SourceMap, args []string) error

type namespaceAction struct {
	action namespaceActionFunc
}

func (a *namespaceAction) run(_ context.Context, cmd *cli.Command, args []string) {
	sources, err := setupProjectSources()
	if err != nil {
		errExit(err)
	}
	ns, err := setupNamespace(sources)
	if err != nil {
		errExit(err)
	}
	err = a.action(ns, sources, args)
	if err != nil {
		errExit(err)
	}
}

func newNamespaceAction(a namespaceActionFunc) *namespaceAction {
	return &namespaceAction{action: a}
}

func setupProjectSources() ([]*SourceMap, error) {
	c, err := loadProjectConf()
	if err != nil {
		return nil, err
	}

	return MapSources(c.Require, c.Replace, c.Sources)
}

func loadProjectConf() (*conf, error) {
	files := strings.Split(projectFile, ",")
	files = append(files, sourcesFile)
	extraFiles := strings.Split(*extraDefs, ",")
	if len(extraFiles) > 1 || extraFiles[0] != "" {
		files = append(files, extraFiles...)
	}
	cueConf := &load.Config{}
	inst := cue.Build(load.Instances(files, cueConf))
	if err := inst[0].Err; err != nil {
		return nil, err
	}
	c := new(conf)
	err := inst[0].Value().Decode(c)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func setupNamespace(sources []*SourceMap) (*fsutil.NameSpace, error) {
	ns := new(fsutil.NameSpace)
	for _, src := range sources {
		dir := ""
		if src.Replace != "" {
			dir = src.Replace
		} else if src.isVCS() {
			cacheDir, err := getCachedDir(src)
			if err != nil {
				return nil, err
			}
			dir = cacheDir
		} else {
			fsys, err := src.fs()
			if err != nil {
				return nil, err
			}
			if src.Subdir != "" {
				fsys, err = fs.Sub(fsys, src.Subdir)
				if err != nil {
					return nil, err
				}
			}
			err = ns.Bind(src.Path, fsys, fsutil.WithValue(srcFsKey, src))
			if err != nil {
				return nil, fmt.Errorf("bind %q: %w", src.Path, err)
			}
			continue
		}
		if src.Subdir != "" {
			dir = filepath.Join(dir, src.Subdir)
		}
		err := ns.Bind(src.Path, os.DirFS(dir), fsutil.WithNewOSDir(dir), fsutil.WithValue(srcFsKey, src))
		if err != nil {
			return nil, fmt.Errorf("bind %q: %w", src.Path, err)
		}
	}
	return ns, nil
}

type fsKey uint8

const (
	srcFsKey fsKey = iota
)

func listLatest(sources []*SourceMap) error {
	for _, src := range sources {
		if !src.isVCS() {
			continue
		}
		latest, err := latestRev(src)
		if err != nil {
			if errors.Is(err, codehost.ErrNoCommits) {
				fmt.Printf("%v\t%v: %v\n", src.Path, src.Module, err)
				continue
			}
			return fmt.Errorf("%v: %w", src.Module, err)
		}
		if latest == "" {
			//			fmt.Printf("%v\t%v@%v\n", src.Path, src.Module, src.Version)
		} else {
			fmt.Printf("%v\t%v@%v => %v\n", src.Path, src.Module, src.Version, latest)
		}
	}
	return nil
}

func createZip(ns *fsutil.NameSpace, _ []*SourceMap, args []string) error {
	if len(args) == 0 {
		log.Fatal("args") // FIXME
	}
	zf, err := os.Create(args[0])
	if err != nil {
		return err
	}
	defer zf.Close()

	zw := zip.NewWriter(zf)
	err = fs.WalkDir(ns, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path.Base(p) == ".git" {
			return fs.SkipDir
		}
		if d.IsDir() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		fh, err := zip.FileInfoHeader(fi)
		if err != nil {
			return err
		}
		fh.Name = p

		f, err := zw.CreateHeader(fh)
		if err != nil {
			return err
		}
		r, err := ns.Open(p)
		if err != nil {
			return err
		}
		_, err = io.Copy(f, r)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	return zw.Close()
}

type depFileStatus struct {
	filename string
	err      error
}

var errMissing = errors.New("file missing")
var errUnknown = errors.New("file unknown")
var errContent = errors.New("content")

type linkTargetsMismatch struct {
	src   string
	local string
}

func (*linkTargetsMismatch) Error() string {
	return "symlink targets mismatch"
}

type fileModeMismatch struct {
	src   fs.FileMode
	local fs.FileMode
}

func (*fileModeMismatch) Error() string {
	return "file mode mismatch"
}

type depsStatusMap map[string][]depFileStatus

func (m depsStatusMap) set(filename string, fs fs.FS, err error) {
	src, ok := fsutil.Value(fs, srcFsKey).(*SourceMap)
	if !ok {
		return
	}
	mod := src.Module + "@" + src.Version
	modStatus, ok := m[mod]
	modStatus = append(modStatus, depFileStatus{filename: filename, err: err})
	m[mod] = modStatus
}

func depsStatus(ns *fsutil.NameSpace, sources []*SourceMap, args []string) error {
	status := make(depsStatusMap, len(sources))

	err := calcStatus(status, ns)
	if err != nil {
		return err
	}

	var ltm linkTargetsMismatch
	var fmm fileModeMismatch
	for _, src := range sources {
		mod := src.Module + "@" + src.Version
		modStatus := status[mod]
		if len(modStatus) == 0 {
			continue
		}
		delete(status, mod)
		fmt.Println(mod)
		for _, st := range modStatus {
			err := st.err
			t := "E"
			switch {
			case errors.Is(err, errUnknown):
				t = "?"
			case errors.Is(err, errMissing):
				t = "!"
			case errors.Is(err, errContent):
				t = "M"
			case errors.As(err, &ltm):
				t = "L"
			case errors.As(err, &fmm):
				t = "M"
			default:
			}
			fmt.Printf("\t%s %s\n", t, st.filename)
		}
	}
	return nil
}

func depsDiff(ns *fsutil.NameSpace, sources []*SourceMap, args []string) error {
	status := make(depsStatusMap, len(sources))

	err := calcStatus(status, ns)
	if err != nil {
		return err
	}

	for _, src := range sources {
		mod := src.Module + "@" + src.Version
		modStatus := status[mod]
		if len(modStatus) == 0 {
			continue
		}
		delete(status, mod)
		for _, st := range modStatus {
			err := st.err
			switch {
			case errors.Is(err, errContent):
				err := printDiff(ns, st.filename)
				if err != nil {
					return err
				}
			default:
			}
		}
	}
	return nil
}

func calcStatus(status depsStatusMap, ns *fsutil.NameSpace) error {
	h := sha256.New()
	workdir := os.DirFS(".")
	err := fs.WalkDir(ns, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if pb := path.Base(p); pb == ".hg" || pb == ".git" {
			return fs.SkipDir
		}

		// extract fs
		item, ok := d.(fsutil.Item)
		if !ok {
			if d.IsDir() {
				return nil
			}
			return fmt.Errorf("cannot extract fsutil.Item for %q", p)
		}
		fsys := item.FS()

		if d.Type()&fs.ModeSymlink != 0 {
			osName, err := fsutil.OSName(p, fsys)
			if err != nil {
				status.set(p, fsys, fmt.Errorf("symlinks are not supported for source"))
				return nil
			}
			err = compareSymlinkTargets(osName, p)
			if err != nil {
				status.set(p, fsys, err)
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		err = hashFile(h, workdir, p)
		if err != nil {
			if os.IsNotExist(err) {
				err = errMissing
			}
			status.set(p, fsys, errMissing)
			return nil
		}
		h1 := hex.EncodeToString(h.Sum(nil))
		err = hashFile(h, ns, p)
		if err != nil {
			status.set(p, fsys, err)
			return nil
		}
		h2 := hex.EncodeToString(h.Sum(nil))
		if h1 != h2 {
			status.set(p, fsys, errContent)
		}
		return nil
	})
	return err
}

func compareSymlinkTargets(filename1, filename2 string) error {
	target1, err := os.Readlink(filename1)
	if err != nil {
		return err
	}
	target2, err := os.Readlink(filename2)
	if err != nil {
		return err
	}
	if target1 != target2 {
		return fmt.Errorf("symlink targets don't match: %q, %q", target1, target2)
	}
	return nil
}

func updateDeps(ns *fsutil.NameSpace, _ []*SourceMap, args []string) error {
	return fs.WalkDir(ns, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path.Base(p) == ".git" {
			return fs.SkipDir
		}
		if d.IsDir() {
			return os.MkdirAll(p, 0o755)
		}
		if d.Type()&fs.ModeSymlink != 0 {
			// extract fs
			item, ok := d.(fsutil.Item)
			if !ok {
				if d.IsDir() {
					return nil
				}
				return fmt.Errorf("cannot extract fsutil.Item for %q", p)
			}
			fsys := item.FS()
			if err != nil {
				return err
			}
			osName, err := fsutil.OSName(p, fsys)
			if err != nil {
				return fmt.Errorf("symlinks are not supported for source")
			}
			link, err := os.Readlink(osName)
			if err != nil {
				return err
			}
			return os.Symlink(link, p)
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		r, err := ns.Open(p)
		if err != nil {
			return err
		}
		defer r.Close()

		perm := fs.FileMode(0644)
		if fi.Mode().Perm()&0100 != 0 {
			perm = 0755
		}
		w, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
		if err != nil {
			return err
		}
		defer w.Close()
		_, err = io.Copy(w, r)
		if err != nil {
			return err
		}
		return nil
	})
}

func hashFile(h hash.Hash, fsys fs.FS, filename string) error {
	f, err := fsys.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	h.Reset()
	_, err = io.Copy(h, f)
	return err
}

func printDiff(ns fs.FS, filename string) error {
	input1, err := setupDiffInput(ns, "SRC/", filename)
	if err != nil {
		return err
	}
	input2, err := setupDiffInput(os.DirFS("."), "", filename)
	if err != nil {
		return err
	}
	r := diff.Compare(input1, input2)
	r.WriteUnified(os.Stdout)
	return nil
}

func setupDiffInput(ns fs.FS, prefix, filename string) (*diff.File, error) {
	f, err := ns.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	in := new(diff.File)
	in.Name = filename
	in.Text = string(b)
	in.Time = fi.ModTime()
	return in, nil
}

type Source struct {
	Type  string `json:"type"`
	Addr  string `json:"addr"`
	Match []MatchSpec
}

type MatchSpec struct {
	Version map[string]*Source
}

func (src *Source) match(version string) *Source {
	if len(src.Match) == 0 {
		return src
	}
	for _, m := range src.Match {
		if src, ok := m.Version[version]; ok {
			return src
		}
	}
	return src
}

type SourceMap struct {
	Path    string
	Replace string `json:"replace"`
	*Source
	Module  string `json:"module"`
	Version string
	Subdir  string
}

func MapSources(require, replace map[string]string, sources map[string]*Source) ([]*SourceMap, error) {
	n := len(require)
	paths := make([]string, 0, n)
	for path := range require {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	s := make([]*SourceMap, n)
	for i, path := range paths {
		moduleVersion := require[path]
		f := strings.SplitN(moduleVersion, "@", 2)
		module := f[0]
		version := f[1]
		f = strings.SplitN(version, ":", 2)
		subdir := ""
		if len(f) == 2 {
			version = f[0]
			subdir = f[1]
		}
		src := sources[module]
		if src == nil {
			return nil, fmt.Errorf("module %q not found in %s", module, sourcesFile)
		}
		src = src.match(version)
		if path == "/" {
			path = ""
		}
		rpl := ""
		if r := replace[module]; r != "" {
			if _, err := os.Stat(r); err != nil {
				return nil, fmt.Errorf("replacement path not found: %s", r)
			}
			r, err := filepath.Abs(r)
			if err != nil {
				return nil, err
			}
			rpl = r
		}
		s[i] = &SourceMap{
			Path:    path,
			Replace: rpl,
			Module:  module,
			Source:  src,
			Subdir:  subdir,
			Version: version,
		}
	}
	return s, nil
}

func (src *SourceMap) fs() (fs.FS, error) {
	switch src.Type {
	case "zip":
		f := strings.SplitN(src.Addr, ":", 2)
		filename := f[0]
		fsys, err := zip.OpenReader(filename)
		if err != nil {
			return nil, err
		}
		if len(f) == 2 {
			return fs.Sub(fsys, f[1])
		}
		return fsys, nil

	}
	return nil, fmt.Errorf("unknown type: %q", src.Type)
}

func (src *SourceMap) isVCS() bool {
	switch src.Type {
	case "git", "hg":
		return true
	}
	return false
}

func (src *SourceMap) repo() (codehost.Repo, error) {
	addr := src.Addr
	if len(addr) > 0 {
		switch addr[0] {
		case '.':
			a, err := filepath.Abs(addr)
			if err != nil {
				return nil, err
			}
			addr = a
			fallthrough
		case '/':
			addr = "file://" + addr
		}
	}

	return codehost.NewRepo(src.Type, addr)
}

func getCachedDir(src *SourceMap) (string, error) {
	cacheDir := filepath.Join(cfg.GOMODCACHE, src.Module+"@"+src.Version)
	fi, err := os.Stat(cacheDir)
	if err != nil {
		if os.IsNotExist(err) {
			err = getRevision(cacheDir, src)
			if err != nil {
				return "", err
			}
		}
	} else if !fi.IsDir() {
		return "", err
	}
	return cacheDir, nil
}

func latestRev(src *SourceMap) (string, error) {
	repo, err := src.repo()
	if err != nil {
		return "", err
	}

	latest, err := repo.Latest()
	if err != nil {
		return "", err
	}

	tags := latest.Tags
	if len(tags) == 0 {
		tip := latest.Short
		tag, err := repo.RecentTag(latest.Name, "", func(string) bool { return true })
		if err == nil {
			if tag != src.Version {
				return fmt.Sprintf("%v+ (%v)", tag, tip), nil
			}
		}
		return tip, nil
	}
	for _, tag := range latest.Tags {
		if tag == src.Version {
			return "", nil
		}
	}
	return strings.Join(latest.Tags, " "), nil
}

func getRevision(cacheDir string, src *SourceMap) error {
	fmt.Fprintln(os.Stderr, "pt: downloading", src.Module, src.Version)
	repo, err := src.repo()
	if err != nil {
		return err
	}
	r, err := repo.ReadZip(src.Version, "", codehost.MaxZipFile)
	if err != nil {
		return err
	}
	defer r.Close()
	tf, err := os.CreateTemp("", "pt-codehost-repo-*")
	if err != nil {
		return err
	}
	defer tf.Close()
	defer os.Remove(tf.Name())
	n, err := io.Copy(tf, r)
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(tf, n)
	if err != nil {
		return err
	}
	prefix := ""
	err = os.MkdirAll(cacheDir, 0o755)
	if err != nil {
		return err
	}
	err = fs.WalkDir(zr, ".", func(p string, d fs.DirEntry, err error) error {
		if p == "." {
			return nil
		}
		if prefix == "" {
			if !d.IsDir() {
				return fmt.Errorf("missing top-level prefix directory in vcs zip file")
			}
			prefix = p + "/"
			return nil
		}
		if !strings.HasPrefix(p, prefix) {
			return fmt.Errorf("")
		}
		filename := p[len(prefix):]
		filename = filepath.Join(cacheDir, filename)
		r, err := zr.Open(p)
		if err != nil {
			return err
		}
		defer r.Close()
		if d.Type()&fs.ModeSymlink != 0 {
			b, err := io.ReadAll(r)
			if err != nil {
				return err
			}
			symlinkTarget := string(b)
			return os.Symlink(string(symlinkTarget), filename)
		}
		if d.IsDir() {
			return os.MkdirAll(filename, 0o755)
		}

		fi, err := d.Info()
		if err != nil {
			return err
		}
		perm := fs.FileMode(0444)
		if fi.Mode().Perm()&0100 != 0 {
			perm = 0555
		}
		w, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, perm)
		if err != nil {
			return err
		}
		defer w.Close()
		_, err = io.Copy(w, r)
		return err
	})

	if err != nil {
		os.RemoveAll(cacheDir)
	}
	return err
}

func printCueError(err error) {
	format := func(w io.Writer, format string, args ...interface{}) {
		fmt.Fprintf(w, format, args...)
	}

	cwd, _ := os.Getwd()

	w := &bytes.Buffer{}
	cueerrors.Print(w, err, &cueerrors.Config{
		Format: format,
		Cwd:    cwd,
	})

	b := w.Bytes()
	os.Stderr.Write(b)
}

func errExit(err error) {
	var cueerr cueerrors.Error
	if errors.As(err, &cueerr) {
		printCueError(err)
	} else {
		tool.PrintErrExit(err)
	}
	os.Exit(1)
}
