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
	Vars map[string]interface{}
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
		}
	}
	lval.token = Token{token: tok, literal: lit}
	return tok
}

func (l *Lexer) Error(e string) {
	l.error = e
}

func (l *Lexer) Eval(e Expression) (bool, error) {
	switch t := e.(type) {
	case Variable:
		if v, ok := l.Vars[t.literal]; ok {
			switch v.(type) {
			case bool:
				if v.(bool) {
					return true, nil
				} else {
					return false, nil
				}
			default:
				return false, errors.New("Parameter type must be boolean")
			}
		}
		return false, errors.New("Undefined symbol: " + t.literal)
	case ParenExpr:
		return l.Eval(t.SubExpr)
	case UnaryExpr:
		right, err := l.Eval(t.right)
		if err != nil {
			return false, err
		}
		switch t.operator {
		case "!":
			return ! right, nil
		}
	case AssocExpr:
		left, err := l.Eval(t.left)
		if err != nil {
			return false, err
		}
		right, err := l.Eval(t.right)
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

func Parse(exp string, vars map[string]interface{}) (bool, error) {
	l := new(Lexer)
	l.Vars = vars
	l.Init(strings.NewReader(exp))
	if yyParse(l) != 0 {
		return false, errors.New(l.error)
	}
	return l.Eval(l.result)
}

func init() {
	yyErrorVerbose = true // set the global that enables showing full errors
}
