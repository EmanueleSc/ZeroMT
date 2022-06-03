use std::io::{Error, ErrorKind};

#[derive(Debug)]
pub enum ProofError {
    ProofValidationError,
}

pub fn throw(event: ProofError) -> Error {
    match event {
        ProofError::ProofValidationError => {
            Error::new(ErrorKind::Other, "Failure: proof validation error")
        }
    }
}
