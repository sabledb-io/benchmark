use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ParserError {
    #[error("Need more to data to complete operation")]
    NeedMoreData,
    #[error("Protocol error. `{0}`")]
    ProtocolError(String),
    #[error("Input too big")]
    BufferTooBig,
    #[error("Overflow occurred")]
    Overflow,
    #[error("Invalid input. {0}")]
    InvalidInput(String),
}

#[derive(Error, Debug)]
pub enum CommonError {
    #[error("Invalid argument error. {0}")]
    InvalidArgument(String),
    #[error("Error. {0}")]
    OtherError(String),
    #[error("Parse error. {0}")]
    Parser(#[from] ParserError),
    /// From system IO error
    #[error("I/O error. {0}")]
    StdIoError(#[from] std::io::Error),
}

#[allow(dead_code)]
impl CommonError {
    /// Is this parser error, equals `other` ?
    pub fn eq_parser_error(&self, other: &ParserError) -> bool {
        match self {
            CommonError::Parser(e) => e == other,
            _ => false,
        }
    }
}
