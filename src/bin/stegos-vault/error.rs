use super::api::VaultRequest;
use super::vault::AccountId;
use failure::{Error as FError, Fail};
#[derive(Fail, Debug)]
pub enum Error {
    #[fail(display = "Default error={}", _0)]
    Basic(FError),
    #[fail(display = "Unexpected request, {}={:?}", _1, _0)]
    UnexpectedRequest(VaultRequest, String),
    #[fail(display = "Unexpected request, {}", _0)]
    UnexpectedResponse(String),
    #[fail(display = "Account already exist: {}", _0)]
    AlreadyExist(AccountId),
    #[fail(display = "Account Not found: {}", _0)]
    AccountNotFound(AccountId),
    #[fail(display = "Withdraw request was canceled by account")]
    WithdrawRequestCanceled,
    #[fail(display = "Only single notification to vault allowed")]
    OnlySingleNotificationAllowed,
}

impl Error {
    pub fn code(&self) -> u64 {
        match self {
            Error::Basic(..) => 0,
            Error::UnexpectedRequest(..) => 2,
            Error::AlreadyExist(..) => 3,
            Error::AccountNotFound(..) => 4,
            Error::WithdrawRequestCanceled => 5,
            Error::UnexpectedResponse(..) => 6,
            Error::OnlySingleNotificationAllowed => 7,
        }
    }
}

impl From<FError> for Error {
    fn from(error: FError) -> Error {
        Error::Basic(error)
    }
}
