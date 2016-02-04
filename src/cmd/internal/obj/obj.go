// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package obj

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// A LineHist records the history of the file input stack, which maps the virtual line number,
// an incrementing count of lines processed in any input file and typically named lineno,
// to a stack of file:line pairs showing the path of inclusions that led to that position.
// The first line directive (//line in Go, #line in assembly) is treated as pushing
// a new entry on the stack, so that errors can report both the actual and translated
// line number.
//
// In typical use, the virtual lineno begins at 1, and file line numbers also begin at 1,
// but the only requirements placed upon the numbers by this code are:
//	- calls to Push, Update, and Pop must be monotonically increasing in lineno
//	- except as specified by those methods, virtual and file line number increase
//	  together, so that given (only) calls Push(10, "x.go", 1) and Pop(15),
//	  virtual line 12 corresponds to x.go line 3.
type LineHist struct {
	Top            *LineStack  // current top of stack
	Ranges         []LineRange // ranges for lookup
	Dir            string      // directory to qualify relative paths
	TrimPathPrefix string      // remove leading TrimPath from recorded file names
	GOROOT         string      // current GOROOT
	GOROOT_FINAL   string      // target GOROOT
}

// A LineStack is an entry in the recorded line history.
// Although the history at any given line number is a stack,
// the record for all line processed forms a tree, with common
// stack prefixes acting as parents.
type LineStack struct {
	Parent    *LineStack // parent in inclusion stack
	Lineno    int        // virtual line number where this entry takes effect
	File      string     // file name used to open source file, for error messages
	AbsFile   string     // absolute file name, for pcln tables
	FileLine  int        // line number in file at Lineno
	Directive bool
	Sym       *LSym // for linkgetline - TODO(rsc): remove
}

func (stk *LineStack) fileLineAt(lineno int) int {
	return stk.FileLine + lineno - stk.Lineno
}

// The span of valid linenos in the recorded line history can be broken
// into a set of ranges, each with a particular stack.
// A LineRange records one such range.
type LineRange struct {
	Start int        // starting lineno
	Stack *LineStack // top of stack for this range
}

// startRange starts a new range with the given top of stack.
func (h *LineHist) startRange(lineno int, top *LineStack) {
	h.Top = top
	h.Ranges = append(h.Ranges, LineRange{top.Lineno, top})
}

// setFile sets stk.File = file and also derives stk.AbsFile.
func (h *LineHist) setFile(stk *LineStack, file string) {
	// Note: The exclusion of stk.Directive may be wrong but matches what we've done before.
	// The check for < avoids putting a path prefix on "<autogenerated>".
	abs := file
	if h.Dir != "" && !filepath.IsAbs(file) && !strings.HasPrefix(file, "<") && !stk.Directive {
		abs = filepath.Join(h.Dir, file)
	}

	// Remove leading TrimPathPrefix, or else rewrite $GOROOT to literal $GOROOT.
	if h.TrimPathPrefix != "" && hasPathPrefix(abs, h.TrimPathPrefix) {
		if abs == h.TrimPathPrefix {
			abs = ""
		} else {
			abs = abs[len(h.TrimPathPrefix)+1:]
		}
	} else if hasPathPrefix(abs, h.GOROOT) {
		abs = "$GOROOT" + abs[len(h.GOROOT):]
	}
	if abs == "" {
		abs = "??"
	}
	abs = filepath.Clean(abs)
	stk.AbsFile = abs

	if file == "" {
		file = "??"
	}
	stk.File = file
}

// Does s have t as a path prefix?
// That is, does s == t or does s begin with t followed by a slash?
// For portability, we allow ASCII case folding, so that hasPathPrefix("a/b/c", "A/B") is true.
// Similarly, we allow slash folding, so that hasPathPrefix("a/b/c", "a\\b") is true.
// We do not allow full Unicode case folding, for fear of causing more confusion
// or harm than good. (For an example of the kinds of things that can go wrong,
// see http://article.gmane.org/gmane.linux.kernel/1853266.)
func hasPathPrefix(s string, t string) bool {
	if len(t) > len(s) {
		return false
	}
	var i int
	for i = 0; i < len(t); i++ {
		cs := int(s[i])
		ct := int(t[i])
		if 'A' <= cs && cs <= 'Z' {
			cs += 'a' - 'A'
		}
		if 'A' <= ct && ct <= 'Z' {
			ct += 'a' - 'A'
		}
		if cs == '\\' {
			cs = '/'
		}
		if ct == '\\' {
			ct = '/'
		}
		if cs != ct {
			return false
		}
	}
	return i >= len(s) || s[i] == '/' || s[i] == '\\'
}

// Push records that at that lineno a new file with the given name was pushed onto the input stack.
func (h *LineHist) Push(lineno int, file string) {
	stk := &LineStack{
		Parent:   h.Top,
		Lineno:   lineno,
		FileLine: 1,
	}
	h.setFile(stk, file)
	h.startRange(lineno, stk)
}

// Pop records that at lineno the current file was popped from the input stack.
func (h *LineHist) Pop(lineno int) {
	top := h.Top
	if top == nil {
		return
	}
	if top.Directive && top.Parent != nil { // pop #line level too
		top = top.Parent
	}
	next := top.Parent
	if next == nil {
		h.Top = nil
		h.Ranges = append(h.Ranges, LineRange{lineno, nil})
		return
	}

	// Popping included file. Update parent offset to account for
	// the virtual line number range taken by the included file.
	// Cannot modify the LineStack directly, or else lookups
	// for the earlier line numbers will get the wrong answers,
	// so make a new one.
	stk := new(LineStack)
	*stk = *next
	stk.Lineno = lineno
	stk.FileLine = next.fileLineAt(top.Lineno)
	h.startRange(lineno, stk)
}

// Update records that at lineno the file name and line number were changed using
// a line directive (//line in Go, #line in assembly).
func (h *LineHist) Update(lineno int, file string, line int) {
	top := h.Top
	if top == nil {
		return // shouldn't happen
	}
	var stk *LineStack
	if top.Directive {
		// Update existing entry, except make copy to avoid changing earlier history.
		stk = new(LineStack)
		*stk = *top
	} else {
		// Push new entry.
		stk = &LineStack{
			Parent:    top,
			Directive: true,
		}
	}
	stk.Lineno = lineno
	if stk.File != file {
		h.setFile(stk, file) // only retain string if needed
	}
	stk.FileLine = line
	h.startRange(lineno, stk)
}

// AddImport adds a package to the list of imported packages.
func (ctxt *Link) AddImport(pkg string) {
	ctxt.Imports = append(ctxt.Imports, pkg)
}

// At returns the input stack in effect at lineno.
func (h *LineHist) At(lineno int) *LineStack {
	i := sort.Search(len(h.Ranges), func(i int) bool {
		return h.Ranges[i].Start > lineno
	})
	// Found first entry beyond lineno.
	if i == 0 {
		return nil
	}
	return h.Ranges[i-1].Stack
}

// LineString returns a string giving the file and line number
// corresponding to lineno, for use in error messages.
func (h *LineHist) LineString(lineno int) string {
	stk := h.At(lineno)
	if stk == nil {
		return "<unknown line number>"
	}

	text := fmt.Sprintf("%s:%d", stk.File, stk.fileLineAt(lineno))
	if stk.Directive && stk.Parent != nil {
		stk = stk.Parent
		text += fmt.Sprintf("[%s:%d]", stk.File, stk.fileLineAt(lineno))
	}
	const showFullStack = false // was used by old C compilers
	if showFullStack {
		for stk.Parent != nil {
			lineno = stk.Lineno - 1
			stk = stk.Parent
			text += fmt.Sprintf(" %s:%d", stk.File, stk.fileLineAt(lineno))
			if stk.Directive && stk.Parent != nil {
				stk = stk.Parent
				text += fmt.Sprintf("[%s:%d]", stk.File, stk.fileLineAt(lineno))
			}
		}
	}
	return text
}

// FileLine returns the file name and line number
// at the top of the stack for the given lineno.
func (h *LineHist) FileLine(lineno int) (file string, line int) {
	stk := h.At(lineno)
	if stk == nil {
		return "??", 0
	}
	return stk.File, stk.fileLineAt(lineno)
}

// AbsFileLine returns the absolute file name and line number
// at the top of the stack for the given lineno.
func (h *LineHist) AbsFileLine(lineno int) (file string, line int) {
	stk := h.At(lineno)
	if stk == nil {
		return "??", 0
	}
	return stk.AbsFile, stk.fileLineAt(lineno)
}

// This is a simplified copy of linklinefmt above.
// It doesn't allow printing the full stack, and it returns the file name and line number separately.
// TODO: Unify with linklinefmt somehow.
func linkgetline(ctxt *Link, lineno int32, f **LSym, l *int32) {
	stk := ctxt.LineHist.At(int(lineno))
	if stk == nil || stk.AbsFile == "" {
		*f = Linklookup(ctxt, "??", HistVersion)
		*l = 0
		return
	}
	if stk.Sym == nil {
		stk.Sym = Linklookup(ctxt, stk.AbsFile, HistVersion)
	}
	*f = stk.Sym
	*l = int32(stk.fileLineAt(int(lineno)))
}

func Linkprfile(ctxt *Link, line int) {
	fmt.Printf("%s ", ctxt.LineHist.LineString(line))
}

func fieldtrack(ctxt *Link, cursym *LSym) {
	p := cursym.Text
	if p == nil || p.Link == nil { // handle external functions and ELF section symbols
		return
	}
	ctxt.Cursym = cursym

	for ; p != nil; p = p.Link {
		if p.As == AUSEFIELD {
			r := Addrel(ctxt.Cursym)
			r.Off = 0
			r.Siz = 0
			r.Sym = p.From.Sym
			r.Type = R_USEFIELD
		}
	}
}
