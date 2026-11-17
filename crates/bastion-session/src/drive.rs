//! Drive redirection policy.
//!
//! [`ReadOnlyDrive`] wraps any RDPDR backend and refuses every operation that could modify the
//! shared folder (write/append/delete access on open, creating/overwriting files, writes,
//! renames, deletes, truncation, attribute and security changes). The refusal happens at the
//! protocol layer, before the request reaches the filesystem, and is reported to Windows as
//! "media is write protected" so Explorer shows a sensible message.

use ironrdp_pdu::PduResult;
use ironrdp_rdpdr::Rdpdr;
use ironrdp_rdpdr::backend::RdpdrBackend;
use ironrdp_rdpdr::pdu::RdpdrPdu;
use ironrdp_rdpdr::pdu::efs::{
    AnyIoCtlCode, ClientDriveSetInformationResponse, ClientDriveSetSecurityResponse, CreateDisposition, CreateOptions,
    DecodedDeviceControlRequest, DesiredAccess, DeviceControlRequest, DeviceCreateRequest, DeviceCreateResponse,
    DeviceIoResponse, DeviceWriteResponse, Information, NtStatus, PrinterIoRequest, ServerDeviceAnnounceResponse,
    ServerDriveIoRequest,
};
use ironrdp_rdpdr::pdu::esc::{ScardCall, ScardIoCtlCode};
use ironrdp_rdpdr::pdu::esp::PortIoRequest;
use ironrdp_svc::SvcMessage;
use tracing::debug;

const DENIED: NtStatus = NtStatus::MEDIA_WRITE_PROTECTED;

/// Access rights that imply modification.
fn write_access() -> DesiredAccess {
    DesiredAccess::FILE_WRITE_DATA_OR_FILE_ADD_FILE
        | DesiredAccess::FILE_APPEND_DATA_OR_FILE_ADD_SUBDIRECTORY
        | DesiredAccess::FILE_WRITE_EA
        | DesiredAccess::FILE_WRITE_ATTRIBUTES
        | DesiredAccess::FILE_DELETE_CHILD
        | DesiredAccess::DELETE
        | DesiredAccess::WRITE_DAC
        | DesiredAccess::WRITE_OWNER
        | DesiredAccess::GENERIC_WRITE
        | DesiredAccess::GENERIC_ALL
        | DesiredAccess::MAXIMUM_ALLOWED
}

/// Whether an open request could modify anything.
pub fn create_is_mutating(req: &DeviceCreateRequest) -> bool {
    req.desired_access.intersects(write_access())
        || req.create_disposition != CreateDisposition::FILE_OPEN
        || req.create_options.contains(CreateOptions::FILE_DELETE_ON_CLOSE)
}

#[derive(Debug)]
pub struct ReadOnlyDrive {
    inner: Box<dyn RdpdrBackend>,
}

impl ReadOnlyDrive {
    pub fn new(inner: Box<dyn RdpdrBackend>) -> Self {
        Self { inner }
    }
}

ironrdp_core::impl_as_any!(ReadOnlyDrive);

fn deny(req: ServerDriveIoRequest) -> PduResult<Vec<SvcMessage>> {
    let pdu = match req {
        ServerDriveIoRequest::ServerCreateDriveRequest(r) => RdpdrPdu::DeviceCreateResponse(DeviceCreateResponse {
            device_io_reply: DeviceIoResponse::new(r.device_io_request, DENIED),
            file_id: 0,
            information: Information::empty(),
        }),
        ServerDriveIoRequest::DeviceWriteRequest(r) => RdpdrPdu::DeviceWriteResponse(DeviceWriteResponse {
            device_io_reply: DeviceIoResponse::new(r.device_io_request, DENIED),
            length: 0,
        }),
        ServerDriveIoRequest::ServerDriveSetInformationRequest(r) => RdpdrPdu::ClientDriveSetInformationResponse(
            ClientDriveSetInformationResponse::new(&r, DENIED).map_err(|e| ironrdp_pdu::encode_err!(e))?,
        ),
        ServerDriveIoRequest::ServerDriveSetSecurityRequest(r) => RdpdrPdu::ClientDriveSetSecurityResponse(
            ClientDriveSetSecurityResponse::new(&r, DENIED).map_err(|e| ironrdp_pdu::encode_err!(e))?,
        ),
        // Not reachable through `ReadOnlyDrive` (it only denies what `is_mutating` flags), but a
        // request we cannot answer must end in an error, never a panic: release builds abort.
        _ => return Err(ironrdp_pdu::pdu_other_err!("read-only drive", "request has no write-protected reply")),
    };
    Ok(vec![SvcMessage::from(pdu)])
}

/// Decides whether a drive request must be refused in read-only mode.
pub fn is_mutating(req: &ServerDriveIoRequest) -> bool {
    match req {
        ServerDriveIoRequest::ServerCreateDriveRequest(r) => create_is_mutating(r),
        ServerDriveIoRequest::DeviceWriteRequest(_)
        | ServerDriveIoRequest::ServerDriveSetInformationRequest(_)
        | ServerDriveIoRequest::ServerDriveSetSecurityRequest(_) => true,
        _ => false,
    }
}

impl RdpdrBackend for ReadOnlyDrive {
    fn supports_drive_security(&self) -> bool {
        self.inner.supports_drive_security()
    }
    fn reset(&mut self) -> PduResult<()> {
        self.inner.reset()
    }
    fn restore_drive(&mut self, device_id: u32) -> PduResult<()> {
        self.inner.restore_drive(device_id)
    }
    fn add_drive(&mut self, device_id: u32) -> PduResult<()> {
        self.inner.add_drive(device_id)
    }
    fn remove_drive(&mut self, device_id: u32) -> PduResult<Vec<SvcMessage>> {
        self.inner.remove_drive(device_id)
    }
    fn handle_server_device_announce_response(&mut self, pdu: ServerDeviceAnnounceResponse) -> PduResult<()> {
        self.inner.handle_server_device_announce_response(pdu)
    }
    fn handle_scard_call(
        &mut self,
        req: DeviceControlRequest<ScardIoCtlCode>,
        call: ScardCall,
    ) -> PduResult<Vec<SvcMessage>> {
        self.inner.handle_scard_call(req, call)
    }
    fn handle_drive_io_request(&mut self, req: ServerDriveIoRequest) -> PduResult<Vec<SvcMessage>> {
        if is_mutating(&req) {
            debug!("Read-only share: refused a modifying request");
            return deny(req);
        }
        self.inner.handle_drive_io_request(req)
    }
    fn handle_drive_device_control(
        &mut self,
        req: DecodedDeviceControlRequest<AnyIoCtlCode>,
    ) -> PduResult<Vec<SvcMessage>> {
        self.inner.handle_drive_device_control(req)
    }
    fn poll_deferred_messages(&mut self) -> PduResult<Vec<SvcMessage>> {
        self.inner.poll_deferred_messages()
    }
    fn handle_user_logged_on(&mut self, rdpdr: &mut Rdpdr) -> PduResult<Vec<SvcMessage>> {
        self.inner.handle_user_logged_on(rdpdr)
    }
    fn handle_printer_io_request(&mut self, req: PrinterIoRequest) -> PduResult<Vec<SvcMessage>> {
        self.inner.handle_printer_io_request(req)
    }
    fn handle_port_io_request(&mut self, req: PortIoRequest) -> PduResult<Vec<SvcMessage>> {
        self.inner.handle_port_io_request(req)
    }
    fn reject_printer_write(&mut self, req: ironrdp_rdpdr::pdu::efs::DeviceIoRequest) -> PduResult<Vec<SvcMessage>> {
        self.inner.reject_printer_write(req)
    }
}

#[cfg(test)]
mod tests {
    use ironrdp_rdpdr::pdu::efs::{
        DeviceCloseRequest, DeviceIoRequest, DeviceWriteRequest, FileAttributes, MajorFunction, MinorFunction,
        SharedAccess,
    };

    use super::*;

    fn create(access: DesiredAccess, disposition: CreateDisposition, options: CreateOptions) -> DeviceCreateRequest {
        DeviceCreateRequest {
            device_io_request: DeviceIoRequest {
                device_id: 1,
                file_id: 0,
                completion_id: 7,
                major_function: MajorFunction::Create,
                minor_function: MinorFunction::from(0u32),
            },
            desired_access: access,
            allocation_size: 0,
            file_attributes: FileAttributes::empty(),
            shared_access: SharedAccess::empty(),
            create_disposition: disposition,
            create_options: options,
            path: "\\docs\\a.txt".into(),
        }
    }

    #[test]
    fn read_opens_are_allowed() {
        let r = create(
            DesiredAccess::GENERIC_READ | DesiredAccess::FILE_READ_ATTRIBUTES | DesiredAccess::SYNCHRONIZE,
            CreateDisposition::FILE_OPEN,
            CreateOptions::empty(),
        );
        assert!(!create_is_mutating(&r));
    }

    #[test]
    fn modifying_opens_are_refused() {
        for access in [
            DesiredAccess::GENERIC_WRITE,
            DesiredAccess::FILE_WRITE_DATA_OR_FILE_ADD_FILE,
            DesiredAccess::FILE_APPEND_DATA_OR_FILE_ADD_SUBDIRECTORY,
            DesiredAccess::DELETE,
            DesiredAccess::GENERIC_ALL,
            DesiredAccess::WRITE_DAC,
        ] {
            let label = format!("{access:?}");
            assert!(
                create_is_mutating(&create(access, CreateDisposition::FILE_OPEN, CreateOptions::empty())),
                "{label}"
            );
        }
        for disp in [
            CreateDisposition::FILE_CREATE,
            CreateDisposition::FILE_OPEN_IF,
            CreateDisposition::FILE_OVERWRITE,
            CreateDisposition::FILE_OVERWRITE_IF,
            CreateDisposition::FILE_SUPERSEDE,
        ] {
            assert!(create_is_mutating(&create(DesiredAccess::GENERIC_READ, disp, CreateOptions::empty())));
        }
        assert!(create_is_mutating(&create(
            DesiredAccess::GENERIC_READ,
            CreateDisposition::FILE_OPEN,
            CreateOptions::FILE_DELETE_ON_CLOSE
        )));
    }

    #[test]
    fn writes_are_refused_and_unexpected_requests_do_not_panic() {
        let header = |major_function| DeviceIoRequest {
            device_id: 1,
            file_id: 3,
            completion_id: 9,
            major_function,
            minor_function: MinorFunction::from(0u32),
        };
        let write = ServerDriveIoRequest::DeviceWriteRequest(DeviceWriteRequest {
            device_io_request: header(MajorFunction::Write),
            offset: 0,
            write_data: b"x".to_vec(),
        });
        assert!(is_mutating(&write));
        assert_eq!(deny(write).unwrap().len(), 1);

        let close = ServerDriveIoRequest::DeviceCloseRequest(DeviceCloseRequest {
            device_io_request: header(MajorFunction::Close),
        });
        assert!(!is_mutating(&close), "closing a handle is not a modification");
        assert!(deny(close).is_err(), "an unexpected request is an error, not a panic");
    }

    #[test]
    fn denied_create_is_write_protected() {
        let req = ServerDriveIoRequest::ServerCreateDriveRequest(create(
            DesiredAccess::GENERIC_WRITE,
            CreateDisposition::FILE_CREATE,
            CreateOptions::empty(),
        ));
        assert!(is_mutating(&req));
        let msgs = deny(req).unwrap();
        assert_eq!(msgs.len(), 1);
    }
}
