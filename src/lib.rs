extern crate netsnmp_sys;

use netsnmp_sys::*;

use std::fmt;
use std::ffi;
use std::marker::PhantomData;
use std::mem;
use std::os::raw;
use std::ptr;
use std::slice;
use std::str;

#[derive(Debug)]
pub enum SnmpError {
    // SNMP_ERR_*
    NoError,
    TooBig,
    NoSuchName,
    BadValue,
    ReadOnly,
    GenErr,
    NoAccess,
    WrongType,
    WrongLength,
    WrongEncoding,
    WrongValue,
    NoCreation,
    InconsistentValue,
    ResourceUnavailable,
    CommitFailed,
    UndoFailed,
    AuthorizationError,
    NotWritable,
    InconsistentName,


    // SNMPERR_*
    Success,
    //GenErr, // duplicate
    BadLocalPort,
    BadAddress,
    BadSession,
    TooLong,
    NoSocket,
    V2InV1,
    V1InV2,
    BadRepeaters,
    BadRepetitions,
    BadAsn1Build,
    BadSendTo,
    BadParse,
    BadVersion,
    BadSrcParty,
    BadDstParty,
    BadContext,
    BadCommunity,
    NoAuthDesPriv,
    BadAcl,
    BadParty,
    Abort,
    UnknownPdu,
    Timeout,
    BadRecvFrom,
    BadEngId,
    BadSecName,
    BadSecLevel,
    AsnParseErr,
    UnknownSecModel,
    InvalidMsg,
    UnknownEngId,
    UnknownUserName,
    UnsupportedSecLevel,
    AuthenticationFailure,
    NotInTimeWindow,
    DecryptionErr,
    ScGeneralFailure,
    ScNotConfigured,
    KtNotAvailable,
    UnknownReport,
    UsmGenericError,
    UsmUnknownSecurityName,
    UsmUnsupportedSecurityLevel,
    UsmEncryptionError,
    UsmAuthenticationFailure,
    UsmParseError,
    UsmUnknownEngineId,
    UsmNotInTimeWindow,
    UsmDecryptionError,
    NoMib,
    Range,
    MaxSubId,
    BadSubId,
    LongOid,
    BadName,
    Value,
    UnknownObjId,
    NullPdu,
    NoVars,
    VarType,
    Malloc,
    Krb5,
    Protocol,
    OidNonIncreasing,
    JustAContextProbe,
    TransportNoConfig,
    TransportConfigError,
    TlsNoCertificate,

    // Custom
    OidParseError,
    InvalidParameters,
    Unknown,
}

impl SnmpError {
    pub fn from_snmp_err(code: raw::c_long) -> SnmpError {
        use SnmpError::*;
        match code {
            SNMP_ERR_NOERROR             => NoError,
            SNMP_ERR_TOOBIG              => TooBig,
            SNMP_ERR_NOSUCHNAME          => NoSuchName,
            SNMP_ERR_BADVALUE            => BadValue,
            SNMP_ERR_READONLY            => ReadOnly,
            SNMP_ERR_GENERR              => GenErr,
            SNMP_ERR_NOACCESS            => NoAccess,
            SNMP_ERR_WRONGTYPE           => WrongType,
            SNMP_ERR_WRONGLENGTH         => WrongLength,
            SNMP_ERR_WRONGENCODING       => WrongEncoding,
            SNMP_ERR_WRONGVALUE          => WrongValue,
            SNMP_ERR_NOCREATION          => NoCreation,
            SNMP_ERR_INCONSISTENTVALUE   => InconsistentValue,
            SNMP_ERR_RESOURCEUNAVAILABLE => ResourceUnavailable,
            SNMP_ERR_COMMITFAILED        => CommitFailed,
            SNMP_ERR_UNDOFAILED          => UndoFailed,
            SNMP_ERR_AUTHORIZATIONERROR  => AuthorizationError,
            SNMP_ERR_NOTWRITABLE         => NotWritable,
            SNMP_ERR_INCONSISTENTNAME    => InconsistentName,
            _                            => Unknown,
        }
    }

    pub fn from_snmperr(code: raw::c_int) -> SnmpError {
        use SnmpError::*;
        match code {
            SNMPERR_SUCCESS                      => Success,
            SNMPERR_GENERR                       => GenErr,
            SNMPERR_BAD_LOCPORT                  => BadLocalPort,
            SNMPERR_BAD_ADDRESS                  => BadAddress,
            SNMPERR_BAD_SESSION                  => BadSession,
            SNMPERR_TOO_LONG                     => TooLong,
            SNMPERR_NO_SOCKET                    => NoSocket,
            SNMPERR_V2_IN_V1                     => V2InV1,
            SNMPERR_V1_IN_V2                     => V1InV2,
            SNMPERR_BAD_REPEATERS                => BadRepeaters,
            SNMPERR_BAD_REPETITIONS              => BadRepetitions,
            SNMPERR_BAD_ASN1_BUILD               => BadAsn1Build,
            SNMPERR_BAD_SENDTO                   => BadSendTo,
            SNMPERR_BAD_PARSE                    => BadParse,
            SNMPERR_BAD_VERSION                  => BadVersion,
            SNMPERR_BAD_SRC_PARTY                => BadSrcParty,
            SNMPERR_BAD_DST_PARTY                => BadDstParty,
            SNMPERR_BAD_CONTEXT                  => BadContext,
            SNMPERR_BAD_COMMUNITY                => BadCommunity,
            SNMPERR_NOAUTH_DESPRIV               => NoAuthDesPriv,
            SNMPERR_BAD_ACL                      => BadAcl,
            SNMPERR_BAD_PARTY                    => BadParty,
            SNMPERR_ABORT                        => Abort,
            SNMPERR_UNKNOWN_PDU                  => UnknownPdu,
            SNMPERR_TIMEOUT                      => Timeout,
            SNMPERR_BAD_RECVFROM                 => BadRecvFrom,
            SNMPERR_BAD_ENG_ID                   => BadEngId,
            SNMPERR_BAD_SEC_NAME                 => BadSecName,
            SNMPERR_BAD_SEC_LEVEL                => BadSecLevel,
            SNMPERR_ASN_PARSE_ERR                => AsnParseErr,
            SNMPERR_UNKNOWN_SEC_MODEL            => UnknownSecModel,
            SNMPERR_INVALID_MSG                  => InvalidMsg,
            SNMPERR_UNKNOWN_ENG_ID               => UnknownEngId,
            SNMPERR_UNKNOWN_USER_NAME            => UnknownUserName,
            SNMPERR_UNSUPPORTED_SEC_LEVEL        => UnsupportedSecLevel,
            SNMPERR_AUTHENTICATION_FAILURE       => AuthenticationFailure,
            SNMPERR_NOT_IN_TIME_WINDOW           => NotInTimeWindow,
            SNMPERR_DECRYPTION_ERR               => DecryptionErr,
            SNMPERR_SC_GENERAL_FAILURE           => ScGeneralFailure,
            SNMPERR_SC_NOT_CONFIGURED            => ScNotConfigured,
            SNMPERR_KT_NOT_AVAILABLE             => KtNotAvailable,
            SNMPERR_UNKNOWN_REPORT               => UnknownReport,
            SNMPERR_USM_GENERICERROR             => UsmGenericError,
            SNMPERR_USM_UNKNOWNSECURITYNAME      => UsmUnknownSecurityName,
            SNMPERR_USM_UNSUPPORTEDSECURITYLEVEL => UsmUnsupportedSecurityLevel,
            SNMPERR_USM_ENCRYPTIONERROR          => UsmEncryptionError,
            SNMPERR_USM_AUTHENTICATIONFAILURE    => UsmAuthenticationFailure,
            SNMPERR_USM_PARSEERROR               => UsmParseError,
            SNMPERR_USM_UNKNOWNENGINEID          => UsmUnknownEngineId,
            SNMPERR_USM_NOTINTIMEWINDOW          => UsmNotInTimeWindow,
            SNMPERR_USM_DECRYPTIONERROR          => UsmDecryptionError,
            SNMPERR_NOMIB                        => NoMib,
            SNMPERR_RANGE                        => Range,
            SNMPERR_MAX_SUBID                    => MaxSubId,
            SNMPERR_BAD_SUBID                    => BadSubId,
            SNMPERR_LONG_OID                     => LongOid,
            SNMPERR_BAD_NAME                     => BadName,
            SNMPERR_VALUE                        => Value,
            SNMPERR_UNKNOWN_OBJID                => UnknownObjId,
            SNMPERR_NULL_PDU                     => NullPdu,
            SNMPERR_NO_VARS                      => NoVars,
            SNMPERR_VAR_TYPE                     => VarType,
            SNMPERR_MALLOC                       => Malloc,
            SNMPERR_KRB5                         => Krb5,
            SNMPERR_PROTOCOL                     => Protocol,
            SNMPERR_OID_NONINCREASING            => OidNonIncreasing,
            SNMPERR_JUST_A_CONTEXT_PROBE         => JustAContextProbe,
            SNMPERR_TRANSPORT_NO_CONFIG          => TransportNoConfig,
            SNMPERR_TRANSPORT_CONFIG_ERROR       => TransportConfigError,
            SNMPERR_TLS_NO_CERTIFICATE           => TlsNoCertificate,
            _                                    => Unknown
        }
    }
}

pub trait ToOids {
    fn to_oids(&self) -> Result<Box<[oid]>, SnmpError>;
}

impl<'a> ToOids for &'a [oid] {
    fn to_oids(&self) -> Result<Box<[oid]>, SnmpError> {
        init(b"snmp");
        Ok(self.to_vec().into_boxed_slice())
    }
}

impl<'a> ToOids for &'a str {
    fn to_oids(&self) -> Result<Box<[oid]>, SnmpError> {
        init(b"snmp");
        let buf: &mut [oid] = &mut [0; MAX_OID_LEN];
        let cstring = ffi::CString::new(*self).unwrap();

        unsafe {
            let mut new_len = buf.len();
            if 1 == read_objid(cstring.as_ptr(), buf.as_mut_ptr(), &mut new_len) {
                Ok(buf[..new_len].to_vec().into_boxed_slice())
            } else {
                Err(SnmpError::OidParseError)
            }
        }
    }
}

impl<'a> Drop for Session {
    fn drop(&mut self) {
        unsafe {
            snmp_sess_close(self.inner);
        }
    }
}

#[derive(Debug)]
pub enum AuthProtocol {
    MD5,
    SHA,
}

impl AuthProtocol {
    pub fn as_mut_ptr(&self) -> *mut oid {
        use AuthProtocol::*;
        unsafe {
            match *self {
                MD5 => usmHMACMD5AuthProtocol.as_mut_ptr(),
                SHA => usmHMACSHA1AuthProtocol.as_mut_ptr(),
            }
        }
    }

    pub fn len(&self) -> usize {
        use AuthProtocol::*;
        unsafe{
            match *self {
                MD5 => usmHMACMD5AuthProtocol.len(),
                SHA => usmHMACSHA1AuthProtocol.len(),
            }
        }
    }
}

#[derive(Debug)]
pub enum PrivProtocol {
    DES,
    AES,
}

impl PrivProtocol {
    pub fn as_mut_ptr(&self) -> *mut oid {
        use PrivProtocol::*;
        unsafe{
            match *self {
                DES => usmDESPrivProtocol.as_mut_ptr(),
                AES => usmAESPrivProtocol.as_mut_ptr(),
            }
        }
    }

    pub fn len(&self) -> usize {
        use PrivProtocol::*;
        unsafe {
            match *self {
                DES => usmDESPrivProtocol.len(),
                AES => usmAESPrivProtocol.len(),
            }
        }
    }
}

pub type AuthPassword<'a> = &'a [u8];
pub type PrivPassword<'a> = &'a [u8];

pub enum Security<'a> {
    NoAuthNoPriv,
    AuthNoPriv(AuthProtocol, AuthPassword<'a>),
    AuthPriv(AuthProtocol, PrivProtocol,
             AuthPassword<'a>, PrivPassword<'a>),
}

impl<'a> Security<'a> {
    pub fn level_as_int(&self) -> raw::c_int {
        use Security::*;
        match *self {
            NoAuthNoPriv      => SNMP_SEC_LEVEL_NOAUTH,
            AuthNoPriv(_,_)   => SNMP_SEC_LEVEL_AUTHNOPRIV,
            AuthPriv(_,_,_,_) => SNMP_SEC_LEVEL_AUTHPRIV,
        }
    }
}

pub type Community<'a>    = &'a [u8];
pub type SecurityName<'a> = &'a [u8];

pub enum SessOpts<'a> {
    V1(Community<'a>),
    V2c(Community<'a>),
    V3(Security<'a>, SecurityName<'a>),
}

pub struct Session {
    inner: *mut raw::c_void,
}

impl Session {

    pub fn new(host: &str, opts: SessOpts) -> Result<Session, SnmpError> {
        init(b"snmp");
        unsafe {
            let mut ss: netsnmp_session = mem::zeroed(); // session spec
            snmp_sess_init(&mut ss);

            let hostname = match ffi::CString::new(host) {
                Ok(s) => s,
                Err(_) => return Err(SnmpError::InvalidParameters),
            };
            ss.peername = hostname.as_ptr() as *mut raw::c_char;

            use SessOpts::*;
            match opts {
                V1(community) => {
                    ss.version = SNMP_VERSION_1;

                    ss.community_len = community.len();
                    ss.community = community.as_ptr() as *mut u8;
                },
                V2c(community) => {
                    ss.version = SNMP_VERSION_2c;

                    ss.community_len = community.len();
                    ss.community = community.as_ptr() as *mut u8;
                },
                V3(security, security_name) => {
                    ss.version = SNMP_VERSION_3;

                    let security_name_dup = security_name.to_vec();

                    ss.securityName = security_name_dup.as_ptr() as *mut raw::c_char;
                    ss.securityNameLen = security_name.len();

                    mem::forget(security_name_dup); // snmp_sess_close() handles freeing.

                    use Security::*;
                    match security {
                        NoAuthNoPriv => {
                            ss.securityLevel = SNMP_SEC_LEVEL_NOAUTH;
                        },
                        AuthNoPriv(auth_prot, auth_pass) => {
                            ss.securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;

                            // auth
                            ss.securityAuthProto     = snmp_duplicate_objid(auth_prot.as_mut_ptr(),
                                                                              auth_prot.len());
                            ss.securityAuthProtoLen  = auth_prot.len();
                            ss.securityAuthKeyLen    = USM_AUTH_KU_LEN;

                            let gen_result = generate_Ku(ss.securityAuthProto,
                                                         ss.securityAuthProtoLen as raw::c_uint,
                                                         auth_pass.as_ptr(),
                                                         auth_pass.len(),
                                                         ss.securityAuthKey[..].as_mut_ptr(),
                                                         &mut ss.securityAuthKeyLen);

                            if gen_result != SNMPERR_SUCCESS {
                                return Err(SnmpError::from_snmperr(gen_result));
                            }
                        },
                        AuthPriv(auth_prot, priv_prot, auth_pass, priv_pass) => {
                            ss.securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;

                            // auth
                            ss.securityAuthProto     = snmp_duplicate_objid(auth_prot.as_mut_ptr(),
                                                                              auth_prot.len());
                            ss.securityAuthProtoLen  = auth_prot.len();
                            ss.securityAuthKeyLen    = USM_AUTH_KU_LEN;

                            let gen_result = generate_Ku(ss.securityAuthProto,
                                                         ss.securityAuthProtoLen as raw::c_uint,
                                                         auth_pass.as_ptr(),
                                                         auth_pass.len(),
                                                         ss.securityAuthKey[..].as_mut_ptr(),
                                                         &mut ss.securityAuthKeyLen);

                            if gen_result != SNMPERR_SUCCESS {
                                return Err(SnmpError::from_snmperr(gen_result));
                            }

                            // priv
                            ss.securityPrivProto    = snmp_duplicate_objid(priv_prot.as_mut_ptr(),
                                                                             priv_prot.len());
                            ss.securityPrivProtoLen = priv_prot.len();
                            ss.securityPrivKeyLen   = USM_PRIV_KU_LEN;

                            let gen_result = generate_Ku(ss.securityAuthProto,
                                                         ss.securityAuthProtoLen as raw::c_uint,
                                                         priv_pass.as_ptr(),
                                                         priv_pass.len(),
                                                         ss.securityPrivKey[..].as_mut_ptr(),
                                                         &mut ss.securityPrivKeyLen);

                            if gen_result != SNMPERR_SUCCESS {
                                println!("priv generate_Ku failed");
                                return Err(SnmpError::from_snmperr(gen_result));
                            }
                        }
                    }
                }
            } // match opts {...}

            let sess_ptr = snmp_sess_open(&mut ss);
            if sess_ptr.is_null() {
                let mut pcliberr: raw::c_int = 0;
                let mut psnmperr: raw::c_int = 0;
                snmp_error(&mut ss, &mut pcliberr, &mut psnmperr, ptr::null_mut());
                Err(SnmpError::from_snmperr(psnmperr))
            } else {
                Ok(Session {inner: sess_ptr})
            }
        }
    }

    pub fn sync_response(&mut self, name: &[oid], pdu_type: i32,
                         non_repeaters: isize, max_repetitions: isize)
                         -> Result<Pdu, SnmpError>
    {
        unsafe {
            let pdu = snmp_pdu_create(pdu_type);
            snmp_add_null_var(pdu, name.as_ptr(), name.len());
            if pdu_type == SNMP_MSG_GETBULK {
                (*pdu).errstat  = non_repeaters as raw::c_long;   // aka non-repeaters
                (*pdu).errindex = max_repetitions as raw::c_long; // aka max-repetitions
            }

            let mut response_ptr: *mut netsnmp_pdu = ptr::null_mut();

            let sync_response = snmp_sess_synch_response(self.inner, pdu, &mut response_ptr);
            let ret = match sync_response {
                STAT_SUCCESS => {
                    assert!(!response_ptr.is_null());
                    let response = *response_ptr;
                    match response.errstat {
                        SNMP_ERR_NOERROR => {
                            Ok(Pdu{
                                inner: &mut *response_ptr,
                            })
                        }
                        n => Err(SnmpError::from_snmp_err(n))
                    }
                }
                STAT_TIMEOUT => Err(SnmpError::Timeout),
                STAT_ERROR => {
                    let (mut cliberr, mut snmperr) = (0,0);
                    snmp_sess_error(self.inner, &mut cliberr, &mut snmperr, ptr::null_mut());
                    println!("sync_response return error: libc: {}, snmp: {}", cliberr, snmperr);
                    Err(SnmpError::from_snmperr(snmperr))
                },
                _ => panic!("bad return value from snmp_sess_synch_response") // TODO
            };
            ret
        }
    }

    pub fn get<T: ToOids>(&mut self, name: T) -> Result<Pdu, SnmpError> {
        let oids = try!(name.to_oids());
        self.sync_response(&oids[..], SNMP_MSG_GET, 0, 10)
    }

    pub fn get_next<T: ToOids>(&mut self, name: T) -> Result<Pdu, SnmpError> {
        let oids = try!(name.to_oids());
        self.sync_response(&oids[..], SNMP_MSG_GETNEXT, 0, 10)
    }

    pub fn get_bulk<T: ToOids>(&mut self, name: T) -> Result<Pdu, SnmpError> {
        let oids = try!(name.to_oids());
        self.sync_response(&oids[..], SNMP_MSG_GETBULK, 0, 10)
    }

    pub fn bulk_walk<T: ToOids>(&mut self, name: T) -> Result<Walk, SnmpError> {

        let oids = try!(name.to_oids());

        let non_repeaters = 0;
        let max_repetitions = 10;
        let pdu_type = SNMP_MSG_GETBULK;

        let pdu = try!(self.sync_response(&oids[..], pdu_type, non_repeaters, max_repetitions));
        let var_ptr = unsafe {(*pdu.inner).variables};
        let mut w = Walk {
            session: self,
            pdu: pdu,

            root_buf: [0;128],
            root_len: oids.len(),
            pdu_type: pdu_type,
            non_repeaters: 0,
            max_repetitions: 10,

            name_buf: [0; 128],
            name_len: oids.len(),

            cur_var_ptr: ptr::null(),
            next_var_ptr: var_ptr,
        };

        w.root_buf[..oids.len()].clone_from_slice(&oids[..]);
        w.name_buf[..oids.len()].clone_from_slice(&oids[..]);
        Ok(w)
    }

    pub fn walk<T: ToOids>(&mut self, name: T) -> Result<Walk, SnmpError> {

        let oids = try!(name.to_oids());
        let non_repeaters = 0;
        let max_repetitions = 10;
        let pdu_type = SNMP_MSG_GETNEXT;

        let pdu = try!(self.sync_response(&oids[..], pdu_type, non_repeaters, max_repetitions));
        let var_ptr = unsafe {(*pdu.inner).variables};
        let mut w = Walk {
            session: self,
            pdu: pdu,

            root_buf: [0;128],
            root_len: oids.len(),
            pdu_type: pdu_type,
            non_repeaters: 0,
            max_repetitions: 10,

            name_buf: [0; 128],
            name_len: oids.len(),

            cur_var_ptr: ptr::null(),
            next_var_ptr: var_ptr,
        };

        w.root_buf[..oids.len()].clone_from_slice(&oids[..]);
        w.name_buf[..oids.len()].clone_from_slice(&oids[..]);
        Ok(w)
    }
}

pub struct Pdu {
    inner: *mut netsnmp_pdu,
}

impl Pdu {

    pub fn variables<'a >(&'a self) -> VariableIter<'a> {
        unsafe {
            VariableIter{head_ptr: ptr::null_mut(), cur_ptr: ptr::null(),
                         next_ptr: (*self.inner).variables, marker: PhantomData}
        }
    }

    pub fn cloned_variables(&self) -> VariableIter {
        let clone_ptr = unsafe { snmp_clone_varbind((*self.inner).variables) };
        VariableIter{head_ptr: clone_ptr, cur_ptr: ptr::null(),
                     next_ptr: clone_ptr, marker: PhantomData}
    }
}

impl Drop for Pdu {
    fn drop(&mut self) {
        unsafe {
            snmp_free_pdu(self.inner as *mut netsnmp_pdu);
        }
    }
}

//#[derive(Debug)]
pub struct Variable<'a> {
    inner: &'a netsnmp_variable_list,
}

use std::net::Ipv4Addr;

impl<'a> Variable<'a> {

    pub fn objid(&'a self) -> &'a [oid] { // aka name()
        unsafe{
            let name_ptr    = (*self.inner).name;
            let name_length = (*self.inner).name_length;
            assert!(!name_ptr.is_null());
            slice::from_raw_parts(name_ptr, name_length)
        }
    }

    pub fn value(&'a self) -> Value<'a> {
        let ty = (*self.inner)._type;
        let val = (*self.inner).val;
        let val_len = (*self.inner).val_len;
        Value::from_vardata(ty, val, val_len)
    }
}

impl<'a> fmt::Display for Variable<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let mut buf = [0 as raw::c_char; 255];
        let buf_len = buf.len();
        let strlen = unsafe {
            snprint_variable(&mut buf[0], buf_len,
                             (*self.inner).name, (*self.inner).name_length,
                             self.inner) as usize
        };
        assert!(strlen > 0);
        assert!(strlen < buf_len);

        let buf: [u8; 255] = unsafe {mem::transmute(buf)};
        match str::from_utf8(&buf[..strlen]) {
            Ok(s) => f.write_str(s),
            Err(_) => Err(fmt::Error)
        }
    }
}

pub struct VariableIter<'a> {
    head_ptr: *mut netsnmp_variable_list, // we own this varlist, unless this is null
    cur_ptr: *const netsnmp_variable_list, // pointer on loan
    next_ptr: *mut netsnmp_variable_list,
    marker: PhantomData<&'a netsnmp_variable_list>,
}

impl<'a> Drop for VariableIter<'a> {
    fn drop(&mut self) {
        if !self.head_ptr.is_null() {
            unsafe {
                snmp_free_varbind(self.head_ptr);
            }
        }
    }
}

impl<'a> Iterator for VariableIter<'a> {
    type Item = &'a Variable<'a>;
    fn next(&mut self) -> Option<&'a Variable<'a>> {
        unsafe {
            if self.next_ptr.is_null() {
                None
            } else {
                self.cur_ptr = self.next_ptr;
                self.next_ptr = (*self.cur_ptr).next_variable;
                let ret_ptr: *const *const netsnmp_variable_list = &self.cur_ptr;
                mem::transmute(ret_ptr)
            }
        }
    }
}

pub struct Walk<'a> {
    session: &'a mut Session,
    pdu: Pdu,

    root_buf: [oid; MAX_OID_LEN],
    root_len: usize,
    pdu_type: i32,

    non_repeaters: isize,
    max_repetitions: isize,

    name_buf: [oid; 128],
    name_len: usize,

    cur_var_ptr: *const netsnmp_variable_list,
    next_var_ptr: *mut netsnmp_variable_list,
}

impl<'a> Iterator for Walk<'a> {
    type Item = Result<&'a Variable<'a>, SnmpError>;

    fn next(&mut self) -> Option<Result<&'a Variable<'a>, SnmpError>> {

        if self.next_var_ptr.is_null() {
            // vars exhausted, request more
            let sync_response = self.session.sync_response(
                &self.name_buf[..self.name_len],
                self.pdu_type,
                self.non_repeaters, self.max_repetitions);
            match sync_response {
                Ok(response_pdu) => {
                    self.next_var_ptr = unsafe {(*response_pdu.inner).variables};
                    self.pdu = response_pdu;
                },
                Err(err) => return Some(Err(err)),
            }
        }

        unsafe {
            let is_subtree = snmp_oidtree_compare(&self.root_buf[0], self.root_len,
                                                  (*self.next_var_ptr).name,
                                                  (*self.next_var_ptr).name_length) == STAT_SUCCESS;
            if is_subtree {
                ptr::copy_nonoverlapping((*self.next_var_ptr).name,
                                         self.name_buf[..].as_mut_ptr(),
                                         (*self.next_var_ptr).name_length);
                self.name_len = (*self.next_var_ptr).name_length;

                self.cur_var_ptr = self.next_var_ptr;
                self.next_var_ptr = (*self.cur_var_ptr).next_variable;
                let ret_ptr: *const *const netsnmp_variable_list = &self.cur_var_ptr;
                Some(Ok(mem::transmute(ret_ptr)))
            } else {
                None
            }
        }
    }
}

impl<'a> fmt::Debug for Walk<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("Walk")
            .field("root_len", &self.root_len)
            .field("pdu_type", &self.pdu_type)
            .field("non_repeaters", &self.non_repeaters)
            .field("max_repetitions", &self.max_repetitions)
            .field("name_len", &self.name_len)
            .finish()
    }
}

#[derive(Debug)]
pub enum Value<'a> {
    Integer(i32),
    Counter32(u32),
    Gauge32(u32),
    TimeTicks(u32),
    Counter64(u64),
    IpAddress(Ipv4Addr),
    //OctetString(Box<[u8]>),
    OctetString(&'a [u8]),
    // String(&'a str),

    NoSuchObject,
    NoSuchInstance,
    EndOfMibView,

    UnsupportedType(u8),
}

impl<'a> Value<'a> {
    fn from_vardata(ty: raw::c_uchar, mut val: netsnmp_vardata, val_len: usize) -> Value<'a> {
        unsafe {
            match ty {
                ASN_INTEGER => Value::Integer(**val.integer() as i32),
                ASN_IPADDRESS => Value::IpAddress(Ipv4Addr::from((**val.integer() as u32).to_be())),
                ASN_COUNTER => Value::Counter32(**val.integer() as u32),
                ASN_COUNTER64 => {
                    let c64 = **val.counter64();
                    Value::Counter64(mem::transmute([c64.low as u32, c64.high as u32]))
                }
                ASN_GAUGE => Value::Gauge32(**val.integer() as u32),
                ASN_OCTET_STR => Value::OctetString(slice::from_raw_parts(*val.string(), val_len)),
                ASN_TIMETICKS => Value::TimeTicks(**val.integer() as u32),

                SNMP_NOSUCHOBJECT => Value::NoSuchObject,
                SNMP_NOSUCHINSTANCE => Value::NoSuchInstance,
                SNMP_ENDOFMIBVIEW => Value::EndOfMibView,

                n => Value::UnsupportedType(n),
            }
        }
    }

    pub fn get_integer(&self) -> Option<i32> {
        match *self { Value::Integer(n) => Some(n), _ => None }
    }

    pub fn get_counter32(&self) -> Option<u32> {
        match *self { Value::Counter32(n) => Some(n), _ => None }
    }

    pub fn get_gauge32(&self) -> Option<u32> {
        match *self { Value::Gauge32(n) => Some(n), _ => None }
    }

    pub fn get_timeticks(&self) -> Option<u32> {
        match *self { Value::TimeTicks(n) => Some(n), _ => None }
    }

    pub fn get_counter64(&self) -> Option<u64> {
        match *self { Value::Counter64(n) => Some(n), _ => None }
    }

    pub fn get_ipaddress(&self) -> Option<Ipv4Addr> {
        match *self { Value::IpAddress(n) => Some(n), _ => None }
    }

    pub fn get_octetstring(&self) -> Option<&'a [u8]> {
        match *self { Value::OctetString(s) => Some(s), _ => None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use AuthProtocol::*;
    use PrivProtocol::*;
    use Security::*;
    use SessOpts::*;

    const SNMP_PEERNAME: &'static str = "edgy.asdf.dk";

    // const SNMP_COMMUNITY: &'static [u8] = b"st0vsuger";
    // const SNMP_SESS_OPTS_V2C: SessOpts<'static> = V2c(SNMP_COMMUNITY);

    const SNMP_SECURITY: Security<'static> = AuthPriv(SHA, AES, b"rustyauth", b"rustypriv");
    const SNMP_USER: &'static [u8] = b"rustyuser";
    const SNMP_SESS_OPTS_V3: SessOpts<'static> = V3(SNMP_SECURITY, SNMP_USER);

    #[test]
    fn session_get_single() {

        let mut sess = Session::new(SNMP_PEERNAME, SNMP_SESS_OPTS_V3)
            .expect("Session::new() failed");

        sess.get("SNMPv2-MIB::sysDescr.0").map(|resp| {
            resp.variables().next().map(|variable|{
                variable.value().get_octetstring().map(|oct_str| {
                    use std::str;
                    println!("{:?} = {:?}",
                             variable.objid(),
                             str::from_utf8(&oct_str[..]).unwrap());
                });
            });
        }).expect("get failed");
    }

    #[test]
    fn session_get_bulk() {
        let mut sess = Session::new(SNMP_PEERNAME, SNMP_SESS_OPTS_V3)
            .expect("Session::new() failed");
        let resp = sess.get_bulk("IF-MIB::interfaces").unwrap();
        for var in resp.variables() {
            println!("get_bulk: {:?} -> {:?}", var.objid(), var.value());
        }
    }

    #[test]
    fn session_walk() {
        let mut sess = Session::new(SNMP_PEERNAME, SNMP_SESS_OPTS_V3)
            .expect("Session::new() failed");

        let variables = sess.walk("IF-MIB::ifAlias").expect("walk failed");

        for variable in variables {
            variable.map(|variable| {
                println!("walk: {}", variable);
            }).expect("walk failed");
        }
    }

    #[test]
    fn session_bulk_walk() {

        let mut sess = Session::new(SNMP_PEERNAME, SNMP_SESS_OPTS_V3)
            .expect("Session::new() failed");

        for variable in sess.bulk_walk("IF-MIB::ifAlias").expect("walk() failed") {
            variable.map(|variable| {
                println!("bulk walk: {:?}   - {}", variable.value(), variable);
            }).expect("walk failed");
        }
    }

    // #[test]
    // fn session_timeout() {

    //     let mut sess = Session::new("127.0.0.1", SessOpts::V1(b"foobar")).unwrap();

    //     let walk_result = sess.walk("IF-MIB::ifDescr");
    //     println!("{:?}", walk_result);
    //     match walk_result {
    //         Err(SnmpError::Timeout) => (), // expected
    //         _ => panic!()
    //     }
    // }

    #[test]
    fn str_to_oids() {
        let oids = "IF-MIB::ifIndex".to_oids().unwrap();
        let expected: &[u64] = &[1, 3, 6, 1, 2, 1, 2, 2, 1, 1];
        assert_eq!(&oids[..], expected);
    }

    #[test]
    fn oids_to_oids() {
        let expected: &[u64] = &[1, 3, 6, 1, 2, 1, 2, 2, 1, 1];
        assert_eq!(&expected.to_oids().unwrap()[..], expected);
    }
}
