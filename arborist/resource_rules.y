%{
package arborist

import (
	"bufio"
	"strings"
	"errors"
	"unicode/utf8"
)

type Expression interface{}

type ParenExpr struct {
	SubExpr Expression
}

type Token struct {
	token   int
	literal string
}

type Variable struct {
	literal string
}

type AssocExpr struct {
	left     Expression
	operator string
	right    Expression
}

type UnaryExpr struct {
	operator string
	right    Expression
}
%}

%union{
	token Token
	expr  Expression
}
%type<expr> program
%type<expr> expr
%token<token> NOT AND OR RESOURCE LPAREN RPAREN
%left AND
%left OR
%right NOT
%%
program
	: expr
	{
		$$ = $1
		yylex.(*Lexer).result = $$
	}
expr
	: RESOURCE
	{
		$$ = Variable{literal: $1.literal}
	}
	| NOT expr
	{
		$$ = UnaryExpr{operator: "!", right: $2}
	}
	| expr AND expr
	{
		$$ = AssocExpr{left: $1, operator: "&&", right: $3}
	}
	| LPAREN expr RPAREN
	{
		$$ = ParenExpr{SubExpr: $2}
	}
	| expr OR expr
	{
		$$ = AssocExpr{left: $1, operator: "||", right: $3}
	}
%%
func isSpace(r rune) bool {
	if r <= '\u00FF' {
		// Obvious ASCII ones: \t through \r plus space. Plus two Latin-1 oddballs.
		switch r {
		case ' ', '\t', '\n', '\v', '\f', '\r':
			return true
		case '\u0085', '\u00A0':
			return true
		}
		return false
	}
	// High-valued ones.
	if '\u2000' <= r && r <= '\u200a' {
		return true
	}
	switch r {
	case '\u1680', '\u2028', '\u2029', '\u202f', '\u205f', '\u3000':
		return true
	}
	return false
}

func isParenthesis(r rune) bool {
	switch r {
	case '(', ')':
		return true
	}
	return false
}

func isQuote(r rune) bool {
	switch r {
	case '"', '\'':
		return true
	}
	return false
}

func scanToken(data []byte, atEOF bool) (advance int, token []byte, err error) {
	// Skip leading spaces.
	start := 0
	for width := 0; start < len(data); start += width {
		var r rune
		r, width = utf8.DecodeRune(data[start:])
		if !isSpace(r) {
			break
		}
	}
	if start < len(data) {
		sr, width := utf8.DecodeRune(data[start:])
		if isParenthesis(sr) {
			return start + width, data[start:start + width], nil
		}
		if isQuote(sr) {
			start += width
			// Scan until closing quote, marking end of word.
			for width, i := 0, start; i < len(data); i += width {
				var r rune
				r, width = utf8.DecodeRune(data[i:])
				if r == sr {
					return i + width, data[start:i], nil
				}
			}
			return 0, nil, errors.New("mismatching quotes")
		}
	}

	// Scan until space, marking end of word.
	for width, i := 0, start; i < len(data); i += width {
		var r rune
		r, width = utf8.DecodeRune(data[i:])
		if isSpace(r) || isParenthesis(r) || isQuote(r) {
			return i, data[start:i], nil
		}
	}
	// If we're at EOF, we have a final, non-empty, non-terminated word. Return it.
	if atEOF && len(data) > start {
		return len(data), data[start:], nil
	}
	// Request more data.
	return start, nil, nil
}

type Lexer struct {
	scanner *bufio.Scanner
	args map[string]interface{}
	result Expression
	error string
}

func (l *Lexer) Lex(lval *yySymType) int {
	if !l.scanner.Scan() {
		err := l.scanner.Err()
		if err != nil {
			l.error = err.Error()
		}
		return -1
	}
	lit := l.scanner.Text()
	tok := RESOURCE
	switch lit {
	case "not":
		tok = NOT
	case "and":
		tok = AND
	case "or":
		tok = OR
	case "(":
		tok = LPAREN
	case ")":
		tok = RPAREN
	default:
		l.args[lit] = nil
	}
	lval.token = Token{token: tok, literal: lit}
	return tok
}

func (l *Lexer) Error(e string) {
	l.error = e
}

func Eval(e Expression, vars map[string]bool) (bool, error) {
	switch t := e.(type) {
	case Variable:
		if v, ok := vars[t.literal]; ok {
			return v, nil
		}
		return false, errors.New("Undefined symbol: " + t.literal)
	case ParenExpr:
		return Eval(t.SubExpr, vars)
	case UnaryExpr:
		right, err := Eval(t.right, vars)
		if err != nil {
			return false, err
		}
		switch t.operator {
		case "!":
			return ! right, nil
		}
	case AssocExpr:
		switch t.operator {
		case "||":
			left, err := Eval(t.left, vars)
			if err != nil {
				return false, err
			}
			if left {
				return true, nil
			}
			return Eval(t.right, vars)
		case "&&":
			left, err := Eval(t.left, vars)
			if err != nil {
				return false, err
			}
			if !left {
				return false, nil
			}
			return Eval(t.right, vars)
		}
	}
	return false, errors.New("Unexpected error")
}

func Parse(exp string) (Expression, []string, error) {
	scanner := bufio.NewScanner(strings.NewReader(exp))
	scanner.Split(scanToken)
	l := new(Lexer)
	l.args = make(map[string]interface{})
	l.scanner = scanner
	if yyParse(l) != 0 || l.error != "" {
		return nil, nil, errors.New(l.error)
	}
	args := make([]string, 0)
	for arg := range l.args {
		args = append(args, arg)
	}
	return l.result, args, nil
}

func Run(exp string, vars map[string]bool) (bool, error) {
	e, _, err := Parse(exp)
	if err != nil {
		return false, err
	}
	return Eval(e, vars)
}

func init() {
	yyErrorVerbose = true // set the global that enables showing full errors
}
