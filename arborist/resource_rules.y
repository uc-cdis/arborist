%{
package arborist

import (
	"text/scanner"
	"strings"
	"errors"
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
%token<token> NOT AND OR VARIABLE
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
	: VARIABLE
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
	| '(' expr ')'
	{
		$$ = ParenExpr{SubExpr: $2}
	}
	| expr OR expr
	{
		$$ = AssocExpr{left: $1, operator: "||", right: $3}
	}
%%
type Lexer struct {
	scanner.Scanner
	args map[string]interface{}
	result Expression
	error string
}

func (l *Lexer) Lex(lval *yySymType) int {
	token := l.Scan()
	lit := l.TokenText()
	tok := int(token)
	switch lit {
	case "not":
		tok = NOT
	case "and":
		tok = AND
	case "or":
		tok = OR
	default:
		if lit != "" && lit != "(" && lit != ")" {
			tok = VARIABLE
			l.args[lit] = nil
		}
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
		left, err := Eval(t.left, vars)
		if err != nil {
			return false, err
		}
		right, err := Eval(t.right, vars)
		if err != nil {
			return false, err
		}
		switch t.operator {
		case "||":
			return left || right, nil
		case "&&":
			return left && right, nil
		}
	}
	return false, errors.New("Unexpected error")
}

func Parse(exp string) (Expression, []string, error) {
	l := new(Lexer)
	l.args = make(map[string]interface{})
	l.Init(strings.NewReader(exp))
	if yyParse(l) != 0 {
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
