use crate::error::{Error::AuthenticationError, Result};
use ssh2::Session;
use std::path::PathBuf;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthenticationType {
  Interactive,
  Agent,
  KeyFile(PathBuf),
  KeyMemory(String),
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
      AuthenticationType::Agent => {
        session.userauth_agent(username)?;
      }
      AuthenticationType::KeyFile(private_key_file_path) => {
        session.userauth_pubkey_file(username, None, private_key_file_path, None)?;
      }
      AuthenticationType::KeyMemory(private_key) => {
        session.userauth_pubkey_memory(username, None, private_key, None)?;
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
