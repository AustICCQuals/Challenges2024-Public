package main

import (
	"log"
	"math/rand"
	"os"
	"os/exec"
)

func randN(max int) int {
	return rand.Intn(max)
}

func getChar(index int) Node {
	return RawStringf("os.Args[1][%d]", index)
}

func funcExpr(returnType Node, body Block) Node {
	return CallExpression{
		Target: FunctionDeclaration{
			ReturnType: returnType,
			Body:       body,
		},
	}
}

func generate(flag string, depth int, truePath bool) (Node, error) {
	if depth > len(flag) {
		return nil, nil
	}

	if !truePath && randN(100) < 60 {
		return nil, nil
	}

	if depth == 0 {
		val, err := generate(flag, depth+1, true)
		if err != nil {
			return nil, err
		}

		ret := FunctionDeclaration{
			Name: Identifier("main"),
			Body: Block{
				IfStatement{
					Expr: RawString("len(os.Args) < 2"),
					Body: Block{
						ReturnExpression{},
					},
				},

				CallExpression{
					Target: MemberExpression{
						Target: Identifier("fmt"),
						Name:   Identifier("Println"),
					},
					Arguments: []Node{
						val,
					},
				},
			},
		}

		return ret, nil
	}

	var cases Block

	trueCase, err := generate(flag, depth+1, truePath)
	if err != nil {
		return nil, err
	}

	paths := make(map[byte]bool)

	flagChar := flag[depth-1]

	paths[flagChar] = true

	if trueCase == nil {
		if truePath {
			cases = append(cases, SwitchCase{
				Expr: CharLiteral(flagChar),
				Body: Block{
					ReturnExpression{Value: StringLiteral("Correct")},
				},
			})
		} else {
			cases = append(cases, SwitchCase{
				Expr: CharLiteral(flagChar),
				Body: Block{
					ReturnExpression{Value: StringLiteral("Incorrect")},
				},
			})
		}
	} else {
		cases = append(cases, SwitchCase{
			Expr: CharLiteral(flag[depth-1]),
			Body: Block{
				ReturnExpression{Value: trueCase},
			},
		})
	}

	for i := 0; i < randN(5); i++ {
		c := "abcdefghijklmnopqrstuvwxyz"[randN(26)]
		if _, ok := paths[c]; ok {
			continue
		}

		casePath, err := generate(flag, depth+1, false)
		if err != nil {
			return nil, err
		}

		if casePath != nil {
			cases = append(cases, SwitchCase{
				Expr: CharLiteral(c),
				Body: Block{
					ReturnExpression{Value: casePath},
				},
			})
		}

		paths[c] = true
	}

	rand.Shuffle(len(cases), func(i, j int) { cases[i], cases[j] = cases[j], cases[i] })

	cases = append(cases, SwitchDefaultCase{
		Body: Block{
			ReturnExpression{Value: StringLiteral("Incorrect")},
		},
	})

	return funcExpr(TypeString, Block{
		SwitchStatement{Expr: getChar(depth - 1), Cases: cases},
	}), nil
}

func formatFile(filename string) error {
	cmd := exec.Command("go", "fmt", filename)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

func compileFile(filename string, out string) error {
	cmd := exec.Command("go", "build", "-o", out, filename)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = cmd.Environ()
	cmd.Env = append(cmd.Env, "GOOS=linux")
	cmd.Env = append(cmd.Env, "GOARCH=amd64")

	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

func main() {
	log.Printf("generating")
	f, err := generate("oiccflag{hope_you_enjoyed_reading_my_nicely_nested_code}", 0, true)
	if err != nil {
		log.Fatal(err)
	}

	out, err := os.Create("out/out.go")
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()

	log.Printf("outputting")
	if err := (File{
		PackageDeclaration("main"),
		ImportDeclaration("fmt"),
		ImportDeclaration("os"),
		f,
	}).EmitGo(out); err != nil {
		log.Fatal(err)
	}

	log.Printf("formatting")
	if err := formatFile("out/out.go"); err != nil {
		log.Fatal(err)
	}

	log.Printf("compiling")
	if err := compileFile("out/out.go", "out/out"); err != nil {
		log.Fatal(err)
	}
}
