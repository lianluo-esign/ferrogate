#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Token {
    pub(crate) kind: TokenKind,
    pub(crate) line: usize,
    pub(crate) column: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TokenKind {
    Word(String),
    LBrace,
    RBrace,
    Newline,
}

pub(crate) fn lex(raw: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = raw.chars().peekable();
    let mut line = 1;
    let mut column = 1;

    while let Some(ch) = chars.next() {
        let start_column = column;
        match ch {
            '\n' => {
                tokens.push(Token {
                    kind: TokenKind::Newline,
                    line,
                    column,
                });
                line += 1;
                column = 1;
            }
            ' ' | '\t' | '\r' => column += 1,
            '#' => {
                for next in chars.by_ref() {
                    if next == '\n' {
                        tokens.push(Token {
                            kind: TokenKind::Newline,
                            line,
                            column,
                        });
                        line += 1;
                        column = 1;
                        break;
                    }
                    column += 1;
                }
            }
            '{' => {
                tokens.push(Token {
                    kind: TokenKind::LBrace,
                    line,
                    column: start_column,
                });
                column += 1;
            }
            '}' => {
                tokens.push(Token {
                    kind: TokenKind::RBrace,
                    line,
                    column: start_column,
                });
                column += 1;
            }
            '"' => {
                let mut word = String::new();
                column += 1;
                for next in chars.by_ref() {
                    column += 1;
                    if next == '"' {
                        break;
                    }
                    word.push(next);
                }
                tokens.push(Token {
                    kind: TokenKind::Word(word),
                    line,
                    column: start_column,
                });
            }
            _ => {
                let mut word = String::from(ch);
                column += 1;
                while let Some(next) = chars.peek().copied() {
                    if next.is_whitespace() || next == '{' || next == '}' || next == '#' {
                        break;
                    }
                    word.push(next);
                    chars.next();
                    column += 1;
                }
                tokens.push(Token {
                    kind: TokenKind::Word(word),
                    line,
                    column: start_column,
                });
            }
        }
    }

    tokens
}
