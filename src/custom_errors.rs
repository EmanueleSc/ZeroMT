use std::io::{Error, ErrorKind};

#[derive(Debug)]
pub enum TranscriptError {
    PointValidationError,
}

pub fn throw (event: TranscriptError) -> Result<(), Error> {
    match event {
        TranscriptError::PointValidationError => Err(Error::new(
            ErrorKind::Other, 
            "Failure: G1 point is the identity")
        )
    }
}
