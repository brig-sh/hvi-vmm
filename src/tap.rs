//! The tap side of virtio-net: attaching to an existing tap device, and the
//! `virtio_net_hdr_v1` framing every tap read and write carries.
//!
//! urunc creates the tap inside the container network namespace and redirects
//! the veth to it with tc mirred, so the monitor does not create, address or
//! bridge anything -- it only has to open it. Until something attaches, the
//! device stays NO-CARRIER and the guest's frames are dropped on the floor.
//!
//! The attach needs `/dev/net/tun` and is Linux-only. The framing helpers and
//! `parse_mac` are pure and portable, so the backends share one copy and the
//! portable test suite covers it everywhere.

use crate::virtio_net::NET_HDR_LEN;

/// Prepends the all-zero `virtio_net_hdr_v1` a tap write must carry.
///
/// The tap is attached with `IFF_VNET_HDR`, so each write is prefixed with a
/// `virtio_net_hdr_v1`. We negotiate no offloads, so an all-zero header -- no
/// GSO, no checksum offload -- is the correct description of the frame.
#[must_use]
pub fn prepend_vnet_hdr(frame: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(NET_HDR_LEN + frame.len());
    buf.extend_from_slice(&[0u8; NET_HDR_LEN]);
    buf.extend_from_slice(frame);
    buf
}

/// Returns the Ethernet payload of one `n`-byte tap read, or `None` when the
/// read is too short to carry anything beyond the `virtio_net_hdr_v1` (which
/// every read begins with -- the tap is attached with `IFF_VNET_HDR`).
#[must_use]
pub fn strip_vnet_hdr(buf: &[u8], n: usize) -> Option<&[u8]> {
    buf.get(NET_HDR_LEN..n)
        .filter(|payload| !payload.is_empty())
}

/// Parses `52:54:00:12:34:57` into six octets.
#[must_use]
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut n = 0;
    for part in s.split(':') {
        if n == 6 || part.len() != 2 {
            return None;
        }
        out[n] = u8::from_str_radix(part, 16).ok()?;
        n += 1;
    }
    (n == 6).then_some(out)
}

/// Checks the interface name fits an `ifreq`: 1..=15 bytes (`IFNAMSIZ` minus
/// the terminating NUL). Pure, so the check is testable without
/// `/dev/net/tun` -- which is also why it is only *called* on Linux.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn validate_name(name: &str) -> std::io::Result<()> {
    if name.is_empty() || name.len() >= 16 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "tap name must be 1..15 bytes",
        ));
    }
    Ok(())
}

/// The attach itself: everything that touches `/dev/net/tun`.
#[cfg(target_os = "linux")]
mod attach {
    use std::fs::File;
    use std::io;
    use std::os::unix::io::FromRawFd;

    use super::NET_HDR_LEN;

    const IFF_TAP: i16 = 0x0002;
    const IFF_NO_PI: i16 = 0x1000;
    const IFF_VNET_HDR: i16 = 0x4000;
    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
    const TUNSETVNETHDRSZ: libc::c_ulong = 0x4004_54d8;

    /// `virtio_net_hdr_v1`, the header hvi speaks (VIRTIO_F_VERSION_1). tun
    /// would otherwise assume the 10-byte legacy `virtio_net_hdr`.
    const VNET_HDR_SZ: libc::c_int = NET_HDR_LEN as libc::c_int;

    /// `struct ifreq`: a 16-byte name followed by a 24-byte union.
    #[repr(C)]
    struct IfReq {
        name: [u8; 16],
        flags: i16,
        _pad: [u8; 22],
    }

    /// Opens `/dev/net/tun` and attaches it to the existing tap named `name`.
    ///
    /// The flags have to match how urunc created the device (it passes
    /// `TUNTAP_VNET_HDR`), otherwise `TUNSETIFF` fails with `EINVAL`. Carrier
    /// comes up as soon as this succeeds, which is what lets the guest ARP its
    /// gateway.
    pub fn open(name: &str) -> io::Result<File> {
        super::validate_name(name)?;
        // SAFETY: a plain open(2) of a character device with a NUL-terminated
        // path.
        let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is valid and becomes owned here, so it is closed on every
        // path out of this function, including the ioctl error below.
        let file = unsafe { File::from_raw_fd(fd) };
        let mut req = IfReq {
            name: [0; 16],
            flags: IFF_TAP | IFF_NO_PI | IFF_VNET_HDR,
            _pad: [0; 22],
        };
        req.name[..name.len()].copy_from_slice(name.as_bytes());
        // SAFETY: fd is a tun character device and req is a correctly shaped
        // ifreq.
        if unsafe { libc::ioctl(fd, TUNSETIFF, std::ptr::addr_of_mut!(req)) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut sz: libc::c_int = VNET_HDR_SZ;
        // SAFETY: fd is an attached tap and sz is a live c_int for the call.
        if unsafe { libc::ioctl(fd, TUNSETVNETHDRSZ, std::ptr::addr_of_mut!(sz)) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(file)
    }
}

#[cfg(target_os = "linux")]
pub use attach::open;

#[cfg(test)]
mod tests {
    use super::{parse_mac, prepend_vnet_hdr, strip_vnet_hdr, validate_name, NET_HDR_LEN};

    #[test]
    fn parses_a_mac() {
        assert_eq!(
            parse_mac("52:54:00:12:34:57"),
            Some([0x52, 0x54, 0x00, 0x12, 0x34, 0x57])
        );
    }

    #[test]
    fn rejects_malformed_macs() {
        // Too few groups, too many, non-hex, and unpadded octets: urunc builds
        // this string from the veth, so a silent misparse would put the guest on
        // the wrong address and drop every redirected reply.
        for bad in [
            "",
            "52:54:00:12:34",
            "52:54:00:12:34:57:99",
            "zz:54:00:12:34:57",
            "5:54:00:12:34:57",
        ] {
            assert_eq!(parse_mac(bad), None, "{bad} should not parse");
        }
    }

    #[test]
    fn tx_frames_get_a_zero_vnet_header() {
        let frame = [0xaa, 0xbb, 0xcc];
        let buf = prepend_vnet_hdr(&frame);
        assert_eq!(buf.len(), NET_HDR_LEN + frame.len());
        assert_eq!(&buf[..NET_HDR_LEN], &[0u8; NET_HDR_LEN]);
        assert_eq!(&buf[NET_HDR_LEN..], &frame);
    }

    #[test]
    fn short_rx_reads_are_dropped() {
        // A read of the bare header (or less) carries no frame. n = 0 cannot
        // reach the strip in practice (a zero read means EOF and stops the
        // reader), but it must not slip through as an empty frame either.
        let buf = [0x55u8; 64];
        for n in [0, 11, NET_HDR_LEN] {
            assert_eq!(strip_vnet_hdr(&buf, n), None, "n = {n} should be dropped");
        }
    }

    #[test]
    fn tap_names_are_length_checked() {
        // The name lands in a fixed 16-byte ifreq field, NUL included: empty
        // names and names past IFNAMSIZ-1 must be refused before any ioctl,
        // and a bad name is a boot error (not a fallback), so the message is
        // what an operator sees.
        assert!(validate_name("").is_err(), "empty");
        assert!(
            validate_name("0123456789abcdef").is_err(),
            "16 bytes leaves no room for the NUL"
        );
        assert!(validate_name(&"x".repeat(64)).is_err());
        assert!(validate_name("0123456789abcde").is_ok(), "15 bytes fits");
        assert!(validate_name("tap0_urunc").is_ok());
    }

    #[test]
    fn rx_payload_survives_the_strip() {
        let mut buf = vec![0xffu8; NET_HDR_LEN]; // header bytes are junk to us
        buf.extend_from_slice(&[1, 2, 3, 4, 5]);
        buf.extend_from_slice(&[0xee; 32]); // stale bytes past the read length
        let n = NET_HDR_LEN + 5;
        assert_eq!(strip_vnet_hdr(&buf, n), Some(&[1u8, 2, 3, 4, 5][..]));
    }
}
