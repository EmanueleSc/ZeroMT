use std::io::{Error, ErrorKind};

#[derive(Debug)]
pub enum UtilsError {
    MathError,
}

pub fn throw(event: UtilsError) -> Error {
    match event {
        UtilsError::MathError => Error::new(ErrorKind::Other, "Failure: math error"),
    }
}
