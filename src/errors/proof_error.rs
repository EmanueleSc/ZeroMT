use std::io::{Error, ErrorKind};

#[derive(Debug)]
pub enum ProofError {
    ProofValidationError,
}

pub fn throw(event: ProofError) -> Result<(), Error> {
    match event {
        ProofError::ProofValidationError => Err(Error::new(
            ErrorKind::Other,
            "Failure: proof validation error",
        )),
    }
}
