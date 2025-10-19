use rand::rand_core::OsError;

#[derive(Debug)]
pub enum SecurityError {
    ProcessAuthError(OsError),
    TpmError(tss_esapi::Error)
}


impl From<OsError> for SecurityError {
    fn from(err: OsError) -> Self {
        SecurityError::ProcessAuthError(err)
    }
}
impl From<tss_esapi::Error> for SecurityError {
    fn from(err: tss_esapi::Error) -> Self {
        SecurityError::TpmError(err)
    }
}