//! Comment and rename handlers.

use crate::error::ToolError;
use crate::ida::handlers::resolve_address;
use idalib::IDB;
use serde_json::{json, Value};

pub fn handle_set_comments(
    idb: &Option<IDB>,
    addr: Option<u64>,
    name: Option<&str>,
    offset: i64,
    comment: &str,
    repeatable: bool,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let addr = resolve_address(idb, addr, name, offset)?;
    if repeatable {
        db.set_cmt_with(addr, comment, true)?;
    } else {
        db.set_cmt(addr, comment)?;
    }
    Ok(json!({
        "address": format!("{:#x}", addr),
        "repeatable": repeatable,
        "comment": comment,
    }))
}

pub fn handle_rename(
    idb: &Option<IDB>,
    addr: Option<u64>,
    current_name: Option<&str>,
    name: &str,
    flags: i32,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let addr = resolve_address(idb, addr, current_name, 0)?;
    if flags == 0 {
        db.set_name(addr, name)?;
    } else {
        db.set_name_with_flags(addr, name, flags)?;
    }
    Ok(json!({
        "address": format!("{:#x}", addr),
        "name": name,
        "flags": flags,
    }))
}
