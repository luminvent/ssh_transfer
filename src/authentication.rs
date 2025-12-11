use crate::error::{Error::AuthenticationError, Result};
use ssh2::Session;
use std::path::PathBuf;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthenticationType {
  Interactive,
  KeyFile(PathBuf),
  Password(String),
}

impl AuthenticationType {
  pub(crate) fn authenticate(&self, session: &Session, username: &str) -> Result<()> {
    if session.authenticated() {
      return Ok(());
    }

    match &self {
      AuthenticationType::Interactive => {
        unimplemented!()
      }
      AuthenticationType::KeyFile(_key_file_path) => {
        unimplemented!()
      }
      AuthenticationType::Password(password) => {
        if session
          .auth_methods(username)?
          .split(',')
          .map(String::from)
          .any(|method| method == *"password")
        {
          session.userauth_password(username, password)?;
        }
      }
    }

    if !session.authenticated() {
      return Err(AuthenticationError(format!(
        "Could not authenticate user: {}.",
        username
      )));
    }

    Ok(())
  }
}
