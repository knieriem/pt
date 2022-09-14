package diff

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/knieriem/dmp"
)

type Hunk struct {
	IsEqual bool
	Lines   []Line
}

type Line struct {
	Num struct {
		Left, Right int
	}
	Context string
	Mod     dmp.Diffs
}

type Result struct {
	input1 *File
	input2 *File
	Lines  []Line
}

type File struct {
	Name string
	Text string
	Time time.Time
}

func Compare(file1, file2 *File) *Result {
	diffs := dmp.DiffMain(file1.Text, file2.Text, false, -1)
	//	diffs.CleanupSemantic()
	//	diffs.CleanupEfficiency(0)

	//	fmt.Println(diffs.PrettyHTML())
	//	return nil
	lines := convertToLines(diffs)
	r := new(Result)
	r.input1 = file1
	r.input2 = file2
	r.Lines = lines
	return r
}

func (r *Result) Hunks() []Hunk {
	var hunks []Hunk
	ictx := -1
	neq := 0

	lines := r.Lines
	i := 0
	for i != len(lines) {
		if ictx == -1 {
			if lines[i].Mod != nil {
				ictx = i - 3
				if ictx < 0 {
					ictx = 0
				}
				if ictx > 0 {
					// create a hunk containing equal lines
					hunks = append(hunks, Hunk{IsEqual: true, Lines: lines[:ictx]})
				}
				neq = 0
			}
		} else {
			if lines[i].Mod == nil {
				neq++
				if neq == 7 {
					hunks = append(hunks, Hunk{Lines: lines[ictx : i-3]})
					lines = lines[i-3:]
					ictx = -1
					i = 3
				}
			} else {
				neq = 0
			}
		}
		i++
	}
	if len(lines) == 0 {
		return hunks
	}
	if ictx != -1 {
		hunks = append(hunks, Hunk{Lines: lines[ictx:]})
	} else {
		hunks = append(hunks, Hunk{IsEqual: true, Lines: lines})
	}
	return hunks
}

func convertToLines(diffs dmp.Diffs) []Line {
	var cur []dmp.Diff
	var lines []Line
	isMod := false
	numLeft := 1
	numRight := 1

loopDiffs:
	for _, d := range diffs {
		for {
			eol := strings.IndexByte(d.Text, '\n')
			if eol == -1 {
				cur = append(cur, d)
				continue loopDiffs
			}
			s := d.Text[:eol]
			cur = append(cur, dmp.Diff{Op: d.Op, Text: s})
			if d.Op != dmp.Equal {
				isMod = true
			}
			var line Line
			if len(cur) == 1 {
				if !isMod {
					line.Num.Left = numLeft
					line.Num.Right = numRight
					line.Context = cur[0].Text
					numRight++
					numLeft++
				} else if cur[0].Op == dmp.Insert {
					line.Mod = cur
					line.Num.Right = numRight
					numRight++
				} else {
					line.Mod = cur
					line.Num.Left = numLeft
					numLeft++
				}
			} else {
				line.Num.Right = numRight
				line.Num.Left = numLeft
				lastOp := cur[len(cur)-1].Op
				if lastOp != '-' {
					numRight++
				}
				if lastOp != '+' {
					numLeft++
				}
				line.Mod = cur
			}
			lines = append(lines, line)

			cur = nil
			isMod = false
			d.Text = d.Text[eol+1:]
			if len(d.Text) == 0 {
				break
			}
		}
	}
	return lines
}

func (h *Hunk) RangeLeft() (int, int) {
	i0 := 0
	n0 := 0
	numPrev := 0
	for _, line := range h.Lines {
		if num := line.Num.Left; num != 0 {
			if i0 == 0 {
				i0 = num
			}
			if num != numPrev {
				n0++
				numPrev = num
			}
		}
	}
	return i0, n0
}

func (h *Hunk) RangeRight() (int, int) {
	i0 := 0
	n0 := 0
	numPrev := 0
	for _, line := range h.Lines {
		if num := line.Num.Right; num != 0 {
			if i0 == 0 {
				i0 = num
			}
			if num != numPrev {
				n0++
				numPrev = num
			}
		}
	}
	return i0, n0
}

const timeLayout = "2006-01-02 15:04:05.999999999 -07:00"

func (r *Result) WriteUnified(w io.Writer) error {
	hunks := r.Hunks()
	headerWritten := false

	var leftQueue []Line
	var rightQueue []Line
	for _, h := range hunks {
		if h.IsEqual {
			continue
		}
		if !headerWritten {
			fmt.Fprintf(w, "--- %s\t%s\n", r.input1.Name, r.input1.Time.Format(timeLayout))
			fmt.Fprintf(w, "+++ %s\t%s\n", r.input2.Name, r.input2.Time.Format(timeLayout))
			headerWritten = true
		}
		l1, s1 := h.RangeLeft()
		l2, s2 := h.RangeRight()
		fmt.Fprintf(w, "@@ -%d,%d +%d,%d @@\n", l1, s1, l2, s2)

		for _, line := range h.Lines {
			if line.Mod == nil {
				lOpen, rOpen := printQueue(w, '-', leftQueue)
				if lOpen {
					fmt.Fprintf(w, "!%s\n", line.Context)
				} else if rOpen {
					fmt.Fprintf(w, "-!%s\n", line.Context)
				}
				rOpen, lOpen = printQueue(w, '+', rightQueue)
				sep := " "
				if rOpen {
					sep = "?"
				} else if lOpen {
					sep = "+?"
				}
				fmt.Fprintf(w, "%s%s\n", sep, line.Context)

				leftQueue = leftQueue[:0]
				rightQueue = rightQueue[:0]
				continue
			}
			if line.Num.Left != 0 {
				leftQueue = append(leftQueue, line)
			}
			if line.Num.Right != 0 {
				rightQueue = append(rightQueue, line)
			}
		}
		printQueue(w, '-', leftQueue)
		printQueue(w, '+', rightQueue)
		leftQueue = leftQueue[:0]
		rightQueue = rightQueue[:0]
	}
	return nil
}

func printQueue(w io.Writer, op int, lines []Line) (opOpen, otherOpen bool) {
	isOpen := false
	otherOpen = false
	for _, line := range lines {
		if !isOpen {
			fmt.Fprintf(w, "%c", op)
		}
		isOpen = false
		otherOpen = false
		diffs := line.Mod
		if len(diffs) > 1 {
			lastOp := diffs[len(diffs)-1].Op
			if lastOp != '=' {
				if lastOp != op {
					isOpen = true
				} else {
					otherOpen = true
				}
			}
		}
		for _, d := range diffs {
			if d.Op == '=' || d.Op == op {
				fmt.Fprint(w, d.Text)
			}
		}
		if !isOpen {
			fmt.Fprintln(w)
		}
	}
	return isOpen, otherOpen
}
