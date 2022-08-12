use std::io::{Error, ErrorKind};

#[derive(Debug)]
pub enum TranscriptError {
    PointValidationError,
    PointSerializationError,
}

pub fn throw(event: TranscriptError) -> Error {
    match event {
        TranscriptError::PointValidationError => {
            Error::new(ErrorKind::Other, "Failure: G1 point is the identity")
        }
        TranscriptError::PointSerializationError => {
            Error::new(ErrorKind::Other, "Failure: G1 point serialization error")
        }
    }
}
