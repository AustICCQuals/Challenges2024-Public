package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"

	"github.com/go-git/go-billy/v5/memfs"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/storage/filesystem"
	"github.com/schollz/progressbar/v3"
)

const FLAG = "oiccflag{and_thus_the_flag_was_given_though_commitment}"

type Bible []struct {
	Abbreviation string     `json:"abbrev"`
	Chapters     [][]string `json:"chapters"`
	Name         string     `json:"name"`
}

type simpleWorktree struct {
	wt *git.Worktree
}

func (wt *simpleWorktree) WriteFile(filename string, content []byte) error {
	if err := wt.MkdirAll(path.Dir(filename)); err != nil {
		return err
	}

	f, err := wt.wt.Filesystem.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(content)
	if err != nil {
		return err
	}

	return nil
}

func (wt *simpleWorktree) MkdirAll(dirname string) error {
	return wt.wt.Filesystem.MkdirAll(dirname, os.ModePerm)
}

func (wt *simpleWorktree) Commit(message string) error {
	if err := wt.wt.AddGlob("*"); err != nil {
		return err
	}

	_, err := wt.wt.Commit(message, &git.CommitOptions{})
	if err != nil {
		return err
	}

	return nil
}

func readBible(filename string) (*Bible, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var ret Bible

	err = json.Unmarshal(content, &ret)
	if err != nil {
		return nil, err
	}

	return &ret, nil
}

func main() {
	bible, err := readBible("data/en_kjv_fixed.json")
	if err != nil {
		log.Fatal("failed to load bible", err)
	}

	log.Printf("loaded bible")

	fs := memfs.New()
	wtFs := memfs.New()

	store := filesystem.NewStorage(fs, cache.NewObjectLRU(cache.DefaultMaxSize))

	// Create the new repository.
	repo, err := git.Init(store, wtFs)
	if err != nil {
		log.Fatal(err)
	}

	// Get the repo worktree.
	wt, err := repo.Worktree()
	if err != nil {
		log.Fatal(err)
	}

	swt := &simpleWorktree{wt: wt}

	log.Printf("created repo")

	i := 0

	pb := progressbar.Default(1533)

	// Add the bible.
	for x, chapter := range (*bible)[0].Chapters {
		for y, verse := range chapter {
			if i == 1337 {
				if err := swt.WriteFile(fmt.Sprintf("bible/gen/%d/%d.txt", x, y), []byte(FLAG)); err != nil {
					log.Fatal(err)
				}
			} else {
				if err := swt.WriteFile(fmt.Sprintf("bible/gen/%d/%d.txt", x, y), []byte(verse)); err != nil {
					log.Fatal(err)
				}
			}

			if err := swt.Commit(fmt.Sprintf("add gen %d:%d", x, y)); err != nil {
				log.Fatal(err)
			}

			pb.Add(1)

			i += 1
		}
	}

	pb.Close()

	log.Printf("created commits")

	// Pack the data into a pack file.
	err = repo.RepackObjects(&git.RepackConfig{})
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("repacked objects")

	packEnts, err := fs.ReadDir("objects/pack")
	if err != nil {
		log.Fatal(err)
	}

	for _, ent := range packEnts {
		if ent.IsDir() {
			continue
		}

		filename := path.Join("objects/pack", ent.Name())

		f, err := fs.Open(filename)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		out, err := os.Create(filepath.Join("out", ent.Name()))
		if err != nil {
			log.Fatal(err)
		}
		defer out.Close()

		_, err = io.Copy(out, f)
		if err != nil {
			log.Fatal(err)
		}
	}

	log.Printf("finished")
}
