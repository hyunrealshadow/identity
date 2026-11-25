// Reference Langium grammar corresponding to `src/lib/syntax-tree.ts`,
// `src/domain/audit/query.rs`, and `src/lib/grammar-cases.json`.
grammar LuceneQuery

entry Query:
  DefaultExpression?
;

DefaultExpression:
  OrExpression ({infer BinaryExpression.left=current} right=OrExpression)*
;

OrExpression:
  AndExpression ({infer BinaryExpression.left=current} operator=OR right=AndExpression)*
;

AndExpression:
  PrimaryExpression ({infer BinaryExpression.left=current} operator=AND right=PrimaryExpression)*
;

PrimaryExpression:
  Node |
  NotExpression |
  DateMathTerm |
  DateTimeTerm |
  DateTerm |
  TimeTerm |
  WildcardTerm |
  SearchTerm |
  RegexTerm |
  GroupExpression
;

NotExpression:
  operator=(NOT | NOT_SYMBOL) expression=PrimaryExpression
;

GroupExpression:
  open=LPAREN expression=DefaultExpression close=RPAREN boost=BOOST?
;

FieldTermDefaultExpression:
  FieldTermOrExpression ({infer FieldTermBinaryExpression.left=current} right=FieldTermOrExpression)*
;

FieldTermOrExpression:
  FieldTermAndExpression ({infer FieldTermBinaryExpression.left=current} operator=OR right=FieldTermAndExpression)*
;

FieldTermAndExpression:
  FieldTermPrimaryExpression ({infer FieldTermBinaryExpression.left=current} operator=AND right=FieldTermPrimaryExpression)*
;

FieldTermPrimaryExpression:
  FieldTermNotExpression |
  FieldRangeTerm |
  ComparisonTerm |
  DateMathTerm |
  DateTimeTerm |
  DateTerm |
  TimeTerm |
  WildcardTerm |
  SearchTerm |
  RegexTerm |
  FieldTermGroupExpression
;

FieldTermNotExpression:
  operator=(NOT | NOT_SYMBOL) expression=FieldTermPrimaryExpression
;

FieldTermGroupExpression:
  open=LPAREN expression=FieldTermDefaultExpression close=RPAREN boost=BOOST?
;

Node:
  field=Field COLON term=Term
;

Field:
  value=FieldName
;

FieldName returns string:
  NORMAL_TERM | TO | DATE_MATH_TERM
;

Term:
  FieldTermPrimaryExpression
;

FieldRangeTerm:
  open=(LBRACKET | LBRACE) start=RangeEndpoint operator=TO end=RangeEndpoint close=(RBRACKET | RBRACE)
;

RangeEndpoint:
  DateMathTerm |
  DateTimeTerm |
  DateTerm |
  TimeTerm |
  WildcardTerm |
  SearchTerm
;

ComparisonTerm:
  operator=COMPARISON value=(DateMathTerm | DateTimeTerm | DateTerm | TimeTerm | SearchTerm)
;

DateMathTerm:
  value=DATE_MATH_TERM
;

DateTimeTerm:
  value=DATETIME_TERM
;

DateTerm:
  value=DATE_TERM
;

TimeTerm:
  value=TIME_TERM
;

SearchTerm:
  value=(Word | QUOTED_TERM) fuzzy=FUZZY? boost=BOOST?
;

Word returns string:
  NORMAL_TERM | TO
;

RegexTerm:
  value=REGEX_TERM
;

WildcardTerm:
  value=(WILDCARD | WILDCARD_TERM) boost=BOOST?
;

hidden terminal WS: /\s+/;

terminal COLON: ':';

terminal LPAREN: '(';
terminal RPAREN: ')';
terminal LBRACKET: '[';
terminal RBRACKET: ']';
terminal LBRACE: '{';
terminal RBRACE: '}';

terminal NOT: /[nN][oO][tT](?![^\s:()[\]{}^~"'!&|<>\/])/;
terminal NOT_SYMBOL: '!';

terminal TO: /[tT][oO](?![^\s:()[\]{}^~"'!&|<>\/])/;

terminal COMPARISON: '>=' | '<=' | '>' | '<';

terminal AND: /(?:[aA][nN][dD](?![^\s:()[\]{}^~"'!&|<>\/]))|&&/;
terminal OR: /(?:[oO][rR](?![^\s:()[\]{}^~"'!&|<>\/]))|\|\|/;

terminal FUZZY returns string: /~(?:\d+(?:\.\d+)?)?/;
terminal BOOST returns string: /\^\d+(?:\.\d+)?/;

terminal DATETIME_TERM returns string:
  /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:?\d{2})(?![^\s:()[\]{}^~"'!&|<>\/])/
;

terminal DATE_MATH_TERM returns string:
  /now(?:[+-]\d+(?:ms|s|m|h|d|w|M|y))*(?:\/(?:s|m|h|d|w|M|y))?(?![^\s:()[\]{}^~"'!&|<>])/
;

terminal DATE_TERM returns string:
  /\d{4}-\d{2}-\d{2}(?![^\s:()[\]{}^~"'!&|<>\/])/
;

terminal TIME_TERM returns string:
  /\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?![^\s:()[\]{}^~"'!&|<>\/])/
;

terminal QUOTED_TERM returns string:
  /(?:'(?:\\.|[^'\\])*')|(?:"(?:\\.|[^"\\])*")/
;

terminal REGEX_TERM returns string:
  /\/(?:\\.|[^\/\\\r\n])+\//
;

terminal fragment ESCAPED_CHAR: /\\[^\r\n]/;
terminal fragment NORMAL_CHAR: /[^\s:()[\]{}^~*?"'!&|<>\\/]/;
terminal fragment TERM_ATOM: NORMAL_CHAR | ESCAPED_CHAR;

terminal WILDCARD_TERM returns string:
  (TERM_ATOM+ ('*' | '?') | ('*' | '?') (TERM_ATOM | '*' | '?')) (TERM_ATOM | '*' | '?')* | '?'
;

terminal WILDCARD returns string: '*';

terminal NORMAL_TERM returns string:
  TERM_ATOM+
;
