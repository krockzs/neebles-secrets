//! F04: Private, single-purpose FD transfer between the host identity broker
//! and the isolated KeePass worker. No filesystem-visible control socket.
//! The broker authenticates the UnixStream, but never reads its RPC payload.
//! Linux x86_64 ABI for sendmsg/recvmsg; no new Cargo dependencies.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::c_void;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixDatagram, UnixStream};

const SOL_SOCKET: i32 = 1;
const SCM_RIGHTS: i32 = 1;
const MSG_CTRUNC: i32 = 0x08;
const MSG_TRUNC: i32 = 0x20;
const MSG_CMSG_CLOEXEC: i32 = 0x4000_0000;
const PREFIX: &str = "neebles-fd-v1:";
const MAX_MODULE: usize = 64;

#[repr(C)]
struct Iovec {
    iov_base: *mut c_void,
    iov_len: usize,
}
#[repr(C)]
struct Msghdr {
    msg_name: *mut c_void,
    msg_namelen: u32,
    msg_iov: *mut Iovec,
    msg_iovlen: usize,
    msg_control: *mut c_void,
    msg_controllen: usize,
    msg_flags: i32,
}
#[repr(C)]
struct Cmsghdr {
    cmsg_len: usize,
    cmsg_level: i32,
    cmsg_type: i32,
}
unsafe extern "C" {
    fn sendmsg(fd: i32, msg: *const Msghdr, flags: i32) -> isize;
    fn recvmsg(fd: i32, msg: *mut Msghdr, flags: i32) -> isize;
}

const fn align(n: usize) -> usize {
    (n + size_of::<usize>() - 1) & !(size_of::<usize>() - 1)
}
const CTRL_CAP: usize = align(size_of::<Cmsghdr>()) + align(size_of::<i32>());

fn validate_module(module: &str) -> bool {
    let b = module.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_MODULE
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|x| x.is_ascii_lowercase() || x.is_ascii_digit() || *x == b'-')
        && !module.ends_with('-')
        && !module.contains("--")
        && module != "general"
}

pub(crate) fn send_connection(
    control: &UnixDatagram,
    client: &UnixStream,
    peer: Option<&str>,
) -> Result<(), String> {
    if let Some(name) = peer {
        if !validate_module(name) {
            return Err("invalid_forwarded_peer".into());
        }
    }
    let mut payload = format!("{PREFIX}{}", peer.unwrap_or("")).into_bytes();
    let fd = client.as_raw_fd();
    let mut ancillary = [0usize; CTRL_CAP / size_of::<usize>()];
    let hdr = ancillary.as_mut_ptr().cast::<Cmsghdr>();
    unsafe {
        (*hdr).cmsg_len = align(size_of::<Cmsghdr>()) + size_of::<i32>();
        (*hdr).cmsg_level = SOL_SOCKET;
        (*hdr).cmsg_type = SCM_RIGHTS;
        ancillary
            .as_mut_ptr()
            .cast::<u8>()
            .add(align(size_of::<Cmsghdr>()))
            .cast::<i32>()
            .write_unaligned(fd);
    }
    let mut iov = Iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let hdr = Msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: ancillary.as_mut_ptr().cast(),
        msg_controllen: CTRL_CAP,
        msg_flags: 0,
    };
    let sent = unsafe { sendmsg(control.as_raw_fd(), &hdr, 0) };
    if sent < 0 {
        return Err(format!("private_fd_send: {}", io::Error::last_os_error()));
    }
    if sent as usize != payload.len() {
        return Err("private_fd_short_send".into());
    }
    // Only the kernel-passed descriptor reaches the isolated worker.
    // Neither this function nor the broker reads the RPC content.
    Ok(())
}

pub(crate) fn recv_connection(
    control: &UnixDatagram,
) -> Result<(UnixStream, Option<String>), String> {
    let mut bytes = [0u8; PREFIX.len() + MAX_MODULE];
    let mut ancillary = [0usize; CTRL_CAP / size_of::<usize>()];
    let mut iov = Iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut hdr: Msghdr = unsafe { zeroed() };
    hdr.msg_iov = &mut iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = ancillary.as_mut_ptr().cast();
    hdr.msg_controllen = CTRL_CAP;
    let received = unsafe { recvmsg(control.as_raw_fd(), &mut hdr, MSG_CMSG_CLOEXEC) };
    if received < 0 {
        return Err(format!("private_fd_recv: {}", io::Error::last_os_error()));
    }
    // Own the received FD immediately. An invalid packet must never leak it.
    let mut owned_fd: Option<OwnedFd> = None;
    if hdr.msg_controllen >= align(size_of::<Cmsghdr>()) + size_of::<i32>() {
        let control_hdr = ancillary.as_ptr().cast::<Cmsghdr>();
        let valid = unsafe {
            (*control_hdr).cmsg_level == SOL_SOCKET
                && (*control_hdr).cmsg_type == SCM_RIGHTS
                && (*control_hdr).cmsg_len == align(size_of::<Cmsghdr>()) + size_of::<i32>()
        };
        if valid {
            let raw = unsafe {
                ancillary
                    .as_ptr()
                    .cast::<u8>()
                    .add(align(size_of::<Cmsghdr>()))
                    .cast::<i32>()
                    .read_unaligned()
            };
            if raw >= 0 {
                owned_fd = Some(unsafe { OwnedFd::from_raw_fd(raw) });
            }
        }
    }
    if (hdr.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0
        || received == 0
        || received as usize > bytes.len()
        || hdr.msg_controllen != CTRL_CAP
    {
        return Err("invalid_private_fd_packet".into());
    }
    let fd = owned_fd.ok_or("missing_private_fd")?;
    let data = std::str::from_utf8(&bytes[..received as usize])
        .map_err(|_| "invalid_forwarded_identity_encoding")?;
    let name = data
        .strip_prefix(PREFIX)
        .ok_or("invalid_forwarded_identity_version")?;
    if !name.is_empty() && !validate_module(name) {
        return Err("invalid_forwarded_identity".into());
    }
    let peer = if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    };
    Ok((UnixStream::from(fd), peer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    #[test]
    fn passes_authenticated_fd_and_preserves_client_payload() {
        let (broker, isolated) = UnixDatagram::pair().unwrap();
        let (mut app, socket) = UnixStream::pair().unwrap();
        send_connection(&broker, &socket, Some("neebles-connect")).unwrap();
        drop(socket);
        let (mut handed, peer) = recv_connection(&isolated).unwrap();
        assert_eq!(peer.as_deref(), Some("neebles-connect"));
        app.write_all(b"private-rpc-data").unwrap();
        let mut buf = [0; 16];
        handed.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"private-rpc-data");
    }
    // F18: the host broker alone verifies that the installed, root-owned
    // neebles-secrets/bin/neebles-secrets-desktop is the peer. The private,
    // inherited SOCK_DGRAM must preserve that verified identity; otherwise
    // every personal-vault RPC is accidentally denied at transport level.
    #[test]
    fn f18_desktop_identity_can_cross_private_fd_channel() {
        let (broker, isolated) = UnixDatagram::pair().unwrap();
        let (mut client, socket) = UnixStream::pair().unwrap();
        send_connection(&broker, &socket, Some("neebles-secrets")).unwrap();
        drop(socket);
        let (mut handed, peer) = recv_connection(&isolated).unwrap();
        assert_eq!(peer.as_deref(), Some("neebles-secrets"));
        client.write_all(b"not-a-master-key").unwrap();
        let mut payload = [0u8; 16];
        handed.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"not-a-master-key");
    }

    #[test]
    fn unattributed_client_remains_unprivileged() {
        let (broker, isolated) = UnixDatagram::pair().unwrap();
        let (_, socket) = UnixStream::pair().unwrap();
        send_connection(&broker, &socket, None).unwrap();
        let (_, peer) = recv_connection(&isolated).unwrap();
        assert!(peer.is_none());
    }
    #[test]
    fn disallows_general_and_invalid_module_names() {
        for name in ["general", "A-B", "a--b", "invalid/peer", "a-"] {
            assert!(!validate_module(name));
        }
        assert!(validate_module("neebles-secrets"));
        assert!(validate_module("neebles-connect"));
    }
}
